#ifndef P4_PROTOCOL_HEADERS_VXLAN_P4
#define P4_PROTOCOL_HEADERS_VXLAN_P4

/**
 * VXLAN header definitions (RFC 7348)
 * 虚拟扩展局域网报头，以 UDP 承载内层以太网帧
 * A 24-bit VNI identifies the overlay network. The inner FCS is omitted.
 * Frame format: [outer Ethernet][IP][UDP][VXLAN][inner Ethernet][payload].
 * Gateway and tenant state are local metadata, not an extra wire header.
 */

const bit<16> VXLAN_UDP_PORT = 4789;

/* I is the only defined flag in the base VXLAN format. */
enum bit<8> vxlan_flags {
    I_FLAG = 0x08
};

/**
 * VXLAN base header (8 bytes)
 * I must be set to indicate a valid VNI. The other seven flag bits and both
 * reserved fields are transmitted as zero and ignored on receipt.
 * This format always carries Ethernet, including when reserved bits are set.
 * VXLAN-GPE on UDP port 4790 uses a separate format and receive path.
 */
header vxlan_header {
    bit<8> flags;
    bit<24> reserved1;
    bit<24> vni;
    bit<8> reserved2;
};

/* Inner Ethernet prefix (14 bytes). VLAN tags and payload follow unchanged. */
header inner_ethernet {
    bit<48> dst_mac;
    bit<48> src_mac;
    bit<16> eth_type;
};

/**
 * Outer UDP header (8 bytes)
 * The destination port defaults to 4789 and can be configured for legacy peers.
 * A hash of the inner flow can supply source-port entropy. RFC 7348 recommends
 * the dynamic/private range 49152-65535 for a source port chosen this way.
 * Length includes this header. IPv4 permits a zero UDP checksum.
 * IPv6 normally requires a checksum. Zero-checksum tunnels need the separate
 * configuration and requirements in RFC 6936 and RFC 8085, Section 3.4.
 */
header vxlan_udp {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
};

/**
 * Outer IPv4 header (20-60 bytes, RFC 791)
 * Protocol follows TTL and precedes the header checksum. VXLAN uses UDP (17).
 * IHL counts all header bytes, including options, in 4-byte units.
 * Extract (IHL - 5) * 32 bits into options. Preserve option values for the
 * enclosing IP pipeline to validate and process. IPv6 uses ipv6.p4 instead.
 */
header vxlan_ip {
    bit<8> version_ihl;
    bit<8> dscp_ecn;
    bit<16> total_length;
    bit<16> identification;
    bit<16> flags_frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> header_checksum;
    bit<32> src_ip;
    bit<32> dst_ip;
    varbit<320> options;
};

struct vxlan_headers_t {
    vxlan_header base;
    inner_ethernet inner;
};

struct vxlan_metadata_t {
    bit<16> inner_frame_bytes;
    bit<16> payload_bytes;
    bool inner_vlan;
};

/**
 * Parsing examples (P4_16).
 * The IPv4 helper starts at the IP header. received_ip_bytes is the number of
 * physically available bytes from that cursor, excluding any outer FCS.
 * It preserves options, checks length boundaries and selects unfragmented UDP.
 * This endpoint example discards fragments, as permitted by RFC 7348.
 * The enclosing pipeline verifies the IPv4 checksum and processes IP options.
 *
 * The VXLAN parser starts at the VXLAN header after UDP destination-port
 * classification and IP/UDP validation. Pass UDP length minus 8 as vxlan_bytes.
 * The caller checks those bytes against both the IP payload and received data.
 * UDP checksum handling follows the outer IP version and configured policy.
 *
 * Only the base and inner Ethernet prefix are extracted. VLAN tags, inner
 * protocols and padding remain unchanged. A tagged frame needs at least one
 * complete 4-byte tag. Nested tags and inner protocol bounds belong to the
 * handler. Configure VLAN preservation explicitly for the relevant VNI.
 * MAC learning, unknown unicast and multicast replication need bridge state.
 */
/*
parser vxlan_ipv4_parser(packet_in pkt, out vxlan_ip hdr,
                         out bit<16> ip_payload_bytes,
                         in bit<32> received_ip_bytes) {
    bit<8> version_ihl;
    bit<16> header_bytes;

    state start {
        ip_payload_bytes = 0;
        verify(received_ip_bytes >= 20, error.HeaderTooShort);
        version_ihl = pkt.lookahead<bit<8>>();
        verify(version_ihl[7:4] == 4 && version_ihl[3:0] >= 5, error.NoMatch);
        header_bytes = (bit<16>)version_ihl[3:0] * 4;
        verify((bit<32>)header_bytes <= received_ip_bytes, error.HeaderTooShort);
        pkt.extract(hdr, (bit<32>)(header_bytes - 20) * 8);
        verify(hdr.total_length >= header_bytes, error.HeaderTooShort);
        verify((bit<32>)hdr.total_length <= received_ip_bytes, error.HeaderTooShort);
        verify(hdr.protocol == 17, error.NoMatch);
        verify((hdr.flags_frag_offset & 0x3FFF) == 0, error.NoMatch);
        ip_payload_bytes = hdr.total_length - header_bytes;
        transition accept;
    }
}

parser vxlan_parser(packet_in pkt, out vxlan_headers_t hdr,
                    out vxlan_metadata_t meta, in bit<16> vxlan_bytes) {
    state start {
        meta.inner_frame_bytes = 0;
        meta.payload_bytes = 0;
        meta.inner_vlan = false;
        verify(vxlan_bytes >= 22, error.HeaderTooShort);
        pkt.extract(hdr.base);
        verify((hdr.base.flags & (bit<8>)vxlan_flags.I_FLAG) != 0, error.NoMatch);
        pkt.extract(hdr.inner);
        meta.inner_frame_bytes = vxlan_bytes - 8;
        meta.payload_bytes = meta.inner_frame_bytes - 14;
        transition select(hdr.inner.eth_type) {
            0x8100: tagged_frame;
            0x88A8: tagged_frame;
            default: accept;
        }
    }

    state tagged_frame {
        verify(meta.payload_bytes >= 4, error.HeaderTooShort);
        meta.inner_vlan = true;
        transition accept;
    }
}

// Handler ports receive the intact tunnel packet for local bridge processing.
// The enclosing pipeline strips outer headers and handles egress framing.
control vxlan_control(inout vxlan_headers_t hdr, in vxlan_metadata_t meta,
                      inout standard_metadata_t standard_metadata) {
    action deliver(bit<9> handler_port, bit<1> allow_inner_vlan) {
        if (meta.inner_vlan && allow_inner_vlan == 0) {
            mark_to_drop(standard_metadata);
        } else {
            standard_metadata.egress_spec = handler_port;
        }
    }

    action drop_vxlan() {
        mark_to_drop(standard_metadata);
    }

    table vxlan_handlers {
        key = {
            hdr.base.vni: exact;
            hdr.inner.dst_mac: exact;
        }
        actions = {
            deliver;
            drop_vxlan;
        }
        default_action = drop_vxlan();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.base.isValid() || !hdr.inner.isValid()) {
            drop_vxlan();
        } else {
            vxlan_handlers.apply();
        }
    }
}
*/

/**
 * Base header construction example (v1model).
 * The inner frame is already parsed and remains unchanged. A VNI supplied by
 * the enclosing pipeline identifies its configured segment. Tagged frames
 * require explicit permission. VLAN removal needs a separate parsing path.
 * The enclosing pipeline constructs outer Ethernet/IP/UDP headers, computes
 * lengths and checksums and checks the underlay MTU without fragmenting.
 * The deparser emits hdr.base followed by hdr.inner and the remaining payload.
 */
/*
control vxlan_encapsulation(inout vxlan_headers_t hdr,
                            inout standard_metadata_t standard_metadata,
                            in bit<24> vni, in bool allow_inner_vlan) {
    apply {
        if (!hdr.inner.isValid()) {
            mark_to_drop(standard_metadata);
        } else if (!allow_inner_vlan
                   && (hdr.inner.eth_type == 0x8100
                       || hdr.inner.eth_type == 0x88A8)) {
            mark_to_drop(standard_metadata);
        } else {
            hdr.base.setValid();
            hdr.base.flags = (bit<8>)vxlan_flags.I_FLAG;
            hdr.base.reserved1 = 0;
            hdr.base.vni = vni;
            hdr.base.reserved2 = 0;
        }
    }
}
*/

#endif
