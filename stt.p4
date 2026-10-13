#ifndef P4_PROTOCOL_HEADERS_STT_P4
#define P4_PROTOCOL_HEADERS_STT_P4

/**
 * Stateless Transport Tunneling definitions
 * 无状态传输隧道报头，区分传输段与重组后的完整帧
 * Frame and segment layouts follow draft-davie-stt-08, an expired
 * Internet-Draft. STT has no published RFC. The frame flags follow Figure 4
 * literally, with C/P/V/T in the high nibble. Open vSwitch and Wireshark use
 * different flag masks. Configure peers to use these masks.
 * Wire order: [outer Ethernet][IPv4 or IPv6][TCP-like segment header]
 *             [part of an STT frame]. Only the first part starts at the frame
 * header. The reassembled frame is [STT frame header][inner Ethernet][payload].
 * Context ID is a fixed 64-bit value whose interpretation is configured
 * between endpoints. Examples use untagged inner Ethernet frames without FCS.
 */

typedef bit<8> stt_flag_t;
typedef bit<16> stt_port_t;

const bit<8> STT_IP_PROTOCOL = 6;
const stt_port_t STT_TCP_PORT = 7471;
const bit<8> STT_VERSION = 0;

/* Frame flag masks from Figure 4 of draft-davie-stt-08. */
const stt_flag_t STT_FLAG_CHECKSUM_VERIFIED = 0x80;
const stt_flag_t STT_FLAG_CHECKSUM_PARTIAL = 0x40;
const stt_flag_t STT_FLAG_IPV4 = 0x20;
const stt_flag_t STT_FLAG_TCP = 0x10;

const bit<6> STT_TCP_FLAG_ACK = 0x10;
const bit<6> STT_TCP_FLAG_PSH = 0x08;

/**
 * TCP-like segment header (20-60 bytes)
 * Frame length and segment offset occupy the TCP Sequence Number field.
 * Frame ID occupies the TCP Acknowledgment Number field. All segments of one
 * frame use the same frame ID, source port and outer source/destination IPs.
 * Frame IDs must not be reused while earlier frames can still be in flight.
 * The source port supplies flow entropy and need not be 7471.
 * Data Offset counts header bytes in 4-byte units. Options follow the prefix.
 * The checksum uses the outer IP pseudoheader, this header and its payload.
 * Window and Urgent Pointer are ignored on receipt and should be zero on
 * transmission. ACK should be set, and PSH is recommended for the last segment.
 * Other flags should be zero on transmission and ignored on receipt.
 */
header stt_tcp_t {
    stt_port_t src_port;
    stt_port_t dst_port;
    bit<16> frame_length;
    bit<16> segment_offset;
    bit<32> frame_id;
    bit<4> data_offset;
    bit<6> reserved;
    bit<6> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_pointer;
    varbit<320> options;
};

/**
 * STT frame header (18 bytes, including 2-byte alignment padding)
 * L4 Offset is measured from the end of this header, at inner Ethernet.
 * MSS is zero when segmentation offload is not requested.
 * PCP and VLAN ID describe an egress 0x8100 tag when vlan_valid = 1.
 * vlan_valid occupies the DEI position in an ordinary VLAN TCI. It is not DEI.
 * Reserved and padding are zero on transmission and ignored on receipt.
 * C indicates an inner checksum verified by the sender. P indicates a partial
 * TCP/UDP pseudoheader checksum. C and P cannot both be set. P is required when
 * segmentation offload is requested. V selects IPv4 rather than IPv6, and T
 * selects TCP rather than UDP for an offloaded payload. The low four flag bits
 * are reserved, zero on transmission and ignored on receipt.
 */
header stt_t {
    bit<8> version;
    stt_flag_t flags;
    bit<8> l4_offset;
    bit<8> reserved;
    bit<16> mss;
    bit<3> pcp;
    bit<1> vlan_valid;
    bit<12> vlan_id;
    bit<64> context_id;
    bit<16> padding;
};

/* Inner Ethernet prefix (14 bytes). The enclosing owner validates its frame. */
header stt_inner_ethernet_t {
    bit<48> dst_mac;
    bit<48> src_mac;
    bit<16> eth_type;
};

struct stt_headers_t {
    stt_t base;
    stt_inner_ethernet_t inner;
};

struct stt_segment_metadata_t {
    bit<16> header_bytes;
    bit<16> payload_bytes;
    bool first_segment;
    bool last_segment;
    bool complete_frame;
};

struct stt_frame_metadata_t {
    bit<16> inner_frame_bytes;
    bit<16> payload_bytes;
    bool checksum_verified;
    bool checksum_partial;
    bool vlan_requested;
};

/**
 * Segment parsing and local delivery example (P4_16, v1model).
 * The cursor points to the TCP-like header after outer IP protocol 6
 * classification. segment_bytes is the validated IP payload length, excluding
 * IP options or extensions. destination_port is the configured STT port,
 * normally STT_TCP_PORT. The enclosing pipeline validates the peer, IP bounds,
 * IP fragmentation and the checksum over each complete STT segment.
 *
 * The parser checks the segment range within the advertised frame and keeps
 * its contents opaque. A first segment may contain only part of the 18-byte
 * frame header. Later segments do not start with an STT frame header.
 * TCP options, flags, Window and Urgent Pointer remain unchanged. An STT frame
 * contains at least its 18-byte header and 14-byte inner Ethernet prefix.
 * Emit the segment header and the unchanged segment payload in the deparser.
 *
 * The local owner reassembles by outer endpoints, ports and Frame ID, checks
 * frame-length consistency, duplicates, overlaps, timeouts and complete byte
 * coverage, and handles DSCP/ECN. NIC aggregation must preserve Frame ID.
 * Disable LRO if the NIC can merge segments with different ACK values.
 * An STT endpoint does not maintain a TCP connection or generate TCP ACKs.
 */
/*
parser stt_segment_parser(packet_in pkt, out stt_tcp_t hdr,
                          out stt_segment_metadata_t meta,
                          in bit<16> segment_bytes,
                          in stt_port_t destination_port) {
    bit<160> prefix;
    bit<32> segment_end;

    state start {
        meta.header_bytes = 0;
        meta.payload_bytes = 0;
        meta.first_segment = false;
        meta.last_segment = false;
        meta.complete_frame = false;
        verify(segment_bytes >= 20, error.HeaderTooShort);
        prefix = pkt.lookahead<bit<160>>();
        verify(prefix[63:60] >= 5, error.NoMatch);
        meta.header_bytes = (bit<16>)prefix[63:60] * 4;
        verify(meta.header_bytes <= segment_bytes, error.HeaderTooShort);
        pkt.extract(hdr, (bit<32>)(meta.header_bytes - 20) * 8);
        verify(hdr.dst_port == destination_port, error.NoMatch);
        verify(hdr.frame_length >= 32, error.HeaderTooShort);
        meta.payload_bytes = segment_bytes - meta.header_bytes;
        verify(meta.payload_bytes > 0, error.HeaderTooShort);
        segment_end = (bit<32>)hdr.segment_offset + (bit<32>)meta.payload_bytes;
        verify(segment_end <= (bit<32>)hdr.frame_length, error.NoMatch);
        meta.first_segment = hdr.segment_offset == 0;
        meta.last_segment = segment_end == (bit<32>)hdr.frame_length;
        meta.complete_frame = meta.first_segment && meta.last_segment;
        transition accept;
    }
}

control stt_segment_control(in stt_tcp_t hdr,
                            inout standard_metadata_t standard_metadata,
                            in bit<9> reassembly_port) {
    apply {
        if (standard_metadata.parser_error != error.NoError || !hdr.isValid()) {
            mark_to_drop(standard_metadata);
        } else {
            standard_metadata.egress_spec = reassembly_port;
        }
    }
}
*/

/**
 * Complete-frame parsing and local delivery example.
 * Use this separate parser only after the owner has reconstructed a complete
 * frame, or has verified that one segment contains the entire frame.
 * The cursor points to the frame header and frame_bytes is its validated
 * complete length, including the 18-byte header. No segment header precedes
 * this cursor. A reassembly owner can reinject the frame through this path.
 *
 * Only the frame header and inner Ethernet prefix are extracted. For P = 1,
 * the example supports TCP/UDP over IPv4/IPv6 and checks basic L4 bounds. The
 * handler still validates the actual inner protocol, exact L4 offset, length
 * fields, checksum seed and MSS before checksum completion or segmentation.
 * For P = 0, V, T, L4 Offset and MSS are ignored and preserved on receipt.
 * A checksum-verified flag is the sender's claim and requires a trusted peer.
 * Reserved bits and padding are ignored and preserved on receipt.
 *
 * VLAN metadata does not represent a VLAN tag in the payload. The payload is
 * untagged. A handler may apply the requested 0x8100 tag on egress, including
 * VLAN ID zero. The configured handler must support partial checksums and VLAN
 * insertion when requested. Context ID has no universal VNI or tenant format.
 * Bridge state, multicast replication and offloads belong to the owner.
 * Emit frame header, inner Ethernet and the opaque payload in the deparser.
 */
/*
parser stt_frame_parser(packet_in pkt, out stt_headers_t hdr,
                        out stt_frame_metadata_t meta, in bit<16> frame_bytes) {
    bit<16> minimum_l4_bytes;
    bit<16> l4_end;

    state start {
        meta.inner_frame_bytes = 0;
        meta.payload_bytes = 0;
        meta.checksum_verified = false;
        meta.checksum_partial = false;
        meta.vlan_requested = false;
        verify(frame_bytes >= 32, error.HeaderTooShort);
        pkt.extract(hdr.base);
        verify(hdr.base.version == STT_VERSION, error.NoMatch);
        meta.checksum_verified = (hdr.base.flags & STT_FLAG_CHECKSUM_VERIFIED) != 0;
        meta.checksum_partial = (hdr.base.flags & STT_FLAG_CHECKSUM_PARTIAL) != 0;
        verify(!(meta.checksum_verified && meta.checksum_partial), error.NoMatch);
        meta.vlan_requested = hdr.base.vlan_valid == 1;
        verify(!meta.vlan_requested || hdr.base.vlan_id != 0xFFF, error.NoMatch);
        pkt.extract(hdr.inner);
        verify(hdr.inner.eth_type != 0x8100 && hdr.inner.eth_type != 0x88A8,
               error.NoMatch);
        meta.inner_frame_bytes = frame_bytes - 18;
        meta.payload_bytes = meta.inner_frame_bytes - 14;
        transition select(meta.checksum_partial) {
            true: partial_checksum;
            default: accept;
        }
    }

    state partial_checksum {
        minimum_l4_bytes = 8;
        if ((hdr.base.flags & STT_FLAG_TCP) != 0) {
            minimum_l4_bytes = 20;
        }
        l4_end = (bit<16>)hdr.base.l4_offset + minimum_l4_bytes;
        verify(l4_end <= meta.inner_frame_bytes, error.HeaderTooShort);
        if ((hdr.base.flags & STT_FLAG_IPV4) != 0) {
            verify(hdr.inner.eth_type == 0x0800 && hdr.base.l4_offset >= 34,
                   error.NoMatch);
        } else {
            verify(hdr.inner.eth_type == 0x86DD && hdr.base.l4_offset >= 54,
                   error.NoMatch);
        }
        transition accept;
    }
}

control stt_frame_control(inout stt_headers_t hdr, in stt_frame_metadata_t meta,
                          inout standard_metadata_t standard_metadata) {
    action deliver_stt_frame(bit<9> handler_port,
                             bit<1> allow_partial, bit<1> allow_vlan) {
        if ((meta.checksum_partial && allow_partial == 0)
            || (meta.vlan_requested && allow_vlan == 0)) {
            mark_to_drop(standard_metadata);
        } else {
            standard_metadata.egress_spec = handler_port;
        }
    }

    action drop_stt_frame() {
        mark_to_drop(standard_metadata);
    }

    table stt_frame_handlers {
        key = {
            hdr.base.context_id: exact;
            hdr.inner.dst_mac: exact;
        }
        actions = {
            deliver_stt_frame;
            drop_stt_frame;
        }
        default_action = drop_stt_frame();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.base.isValid() || !hdr.inner.isValid()) {
            mark_to_drop(standard_metadata);
        } else {
            stt_frame_handlers.apply();
        }
    }
}
*/

/**
 * Frame-header construction without inner offloads (v1model).
 * The caller supplies a valid, fully formatted untagged Ethernet frame with
 * complete inner checksums, and a configured 64-bit Context ID. Remove a VLAN
 * tag before entry and pass any desired egress PCP/VLAN ID as metadata.
 * The example initializes Version, flags, L4 Offset, reserved, MSS and padding
 * to zero. It does not assert checksum verification or request inner offload.
 *
 * The enclosing owner checks the 16-bit frame-length limit, assigns a fresh
 * Frame ID and stable flow source port, segments according to underlay MTU,
 * constructs TCP-like/IP headers and completes each outer checksum.
 * Emit frame header, inner Ethernet and the unchanged payload.
 */
/*
control stt_frame_encapsulation(inout stt_headers_t hdr,
                                inout standard_metadata_t standard_metadata,
                                in bit<64> context_id, in bool vlan_requested,
                                in bit<3> pcp, in bit<12> vlan_id) {
    apply {
        if (!hdr.inner.isValid() || (vlan_requested && vlan_id == 0xFFF)) {
            mark_to_drop(standard_metadata);
        } else if (hdr.inner.eth_type == 0x8100 || hdr.inner.eth_type == 0x88A8) {
            mark_to_drop(standard_metadata);
        } else {
            hdr.base.setValid();
            hdr.base.version = STT_VERSION;
            hdr.base.flags = 0;
            hdr.base.l4_offset = 0;
            hdr.base.reserved = 0;
            hdr.base.mss = 0;
            hdr.base.pcp = 0;
            hdr.base.vlan_valid = 0;
            hdr.base.vlan_id = 0;
            if (vlan_requested) {
                hdr.base.pcp = pcp;
                hdr.base.vlan_valid = 1;
                hdr.base.vlan_id = vlan_id;
            }
            hdr.base.context_id = context_id;
            hdr.base.padding = 0;
        }
    }
}
*/

#endif
