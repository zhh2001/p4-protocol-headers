#ifndef P4_PROTOCOL_HEADERS_FP_P4
#define P4_PROTOCOL_HEADERS_FP_P4

/**
 * Frame preemption: IEEE 802.1Qbu and IEEE 802.3 Clause 99 (802.3br)
 * MAC Merge 分隔符、续片计数和原始 mPacket 解析示例
 */

// IEEE 802.3 Table 99-1. These are octet codewords, not bit fields.
enum bit<8> fp_smd {
    VERIFY = 0x07,
    RESPOND = 0x19,
    EXPRESS = 0xD5, // Same octet as the ordinary Ethernet SFD
    START_0 = 0xE6,
    START_1 = 0x4C,
    START_2 = 0x7F,
    START_3 = 0xB3,
    CONTINUATION_0 = 0x61,
    CONTINUATION_1 = 0x52,
    CONTINUATION_2 = 0x9E,
    CONTINUATION_3 = 0x2A
}

// Table 99-2. The encoded continuation-fragment count advances modulo four.
enum bit<8> fp_fragment_code {
    COUNT_0 = 0xE6,
    COUNT_1 = 0x4C,
    COUNT_2 = 0x7F,
    COUNT_3 = 0xB3
}

// Local parser classification, not an additional on-wire field.
enum bit<3> fp_packet_kind {
    EXPRESS = 0,
    PREEMPTABLE_START = 1,
    CONTINUATION = 2,
    VERIFY = 3,
    RESPOND = 4
}

/* Start mPacket Delimiter, one octet before the MAC data.
 * The wire preamble has seven 0x55 octets before SMD-E/S/V/R, or six before
 * SMD-C. SMD-Sx and SMD-Cx encode a modulo-four frame count. A start can carry
 * a complete preemptable frame or its initial fragment. Only a continuation
 * has the following Frag_count octet. It does not repeat the Ethernet header.
 */
header fp_t {
    bit<8> smd;
}

header fp_fragment_count_t {
    bit<8> frag_count;
}

/* Four-byte CRC trailer in wire order, extracted only at the mPacket end.
 * A non-final fragment, verify or respond packet has an mCRC. A complete
 * frame or final fragment carries the MAC frame's FCS. Identifying a final
 * fragment requires CRC checking and the reassembly context, not an SMD bit.
 */
header fp_crc_t {
    bit<32> value;
}

struct fp_headers_t {
    fp_t delimiter;
    fp_fragment_count_t continuation;
}

struct fp_metadata_t {
    bit<3> kind;
    bit<32> header_bytes;
    bit<32> data_bytes;
}

/**
 * Raw mPacket parsing and local delivery (P4_16, v1model).
 * The target supplies one bounded capture from SMD through the four-byte CRC,
 * with preamble removed and Frag_count retained. packet_bytes includes SMD,
 * optional Frag_count, data and CRC. Emit delimiter and continuation, then
 * the original remainder. The parser checks delimiter codes and header bounds.
 *
 * The owner for link_context handles CRC, packet sizes, verification and
 * reassembly. Verify/respond transmit data consists of 60 zero octets.
 * Ordinary MAC interfaces deliver complete Ethernet frames after MAC Merge
 * processing. Such frames use ethernet.p4, with no preemption header added
 * after the Ethernet header. Transmit preemption is configured per traffic
 * class and performed by the target's MAC Merge sublayer.
 */
/*
parser fp_parser(packet_in pkt, out fp_headers_t hdr,
                 out fp_metadata_t meta, in bit<32> packet_bytes) {
    state start {
        meta.kind = fp_packet_kind.EXPRESS;
        meta.header_bytes = 1;
        meta.data_bytes = 0;
        verify(packet_bytes >= 5, error.HeaderTooShort);
        pkt.extract(hdr.delimiter);
        transition select(hdr.delimiter.smd) {
            fp_smd.EXPRESS: end_header;
            fp_smd.START_0: preemptable_start;
            fp_smd.START_1: preemptable_start;
            fp_smd.START_2: preemptable_start;
            fp_smd.START_3: preemptable_start;
            fp_smd.CONTINUATION_0: continuation;
            fp_smd.CONTINUATION_1: continuation;
            fp_smd.CONTINUATION_2: continuation;
            fp_smd.CONTINUATION_3: continuation;
            fp_smd.VERIFY: verify_packet;
            fp_smd.RESPOND: respond_packet;
            default: unsupported;
        }
    }

    state preemptable_start {
        meta.kind = fp_packet_kind.PREEMPTABLE_START;
        transition end_header;
    }

    state continuation {
        meta.kind = fp_packet_kind.CONTINUATION;
        verify(packet_bytes >= 6, error.HeaderTooShort);
        pkt.extract(hdr.continuation);
        meta.header_bytes = 2;
        transition select(hdr.continuation.frag_count) {
            fp_fragment_code.COUNT_0: end_header;
            fp_fragment_code.COUNT_1: end_header;
            fp_fragment_code.COUNT_2: end_header;
            fp_fragment_code.COUNT_3: end_header;
            default: unsupported;
        }
    }

    state verify_packet {
        meta.kind = fp_packet_kind.VERIFY;
        transition end_header;
    }

    state respond_packet {
        meta.kind = fp_packet_kind.RESPOND;
        transition end_header;
    }

    state unsupported {
        verify(false, error.NoMatch);
        transition accept;
    }

    state end_header {
        meta.data_bytes = packet_bytes - meta.header_bytes - 4;
        transition accept;
    }
}

control fp_control(inout fp_headers_t hdr, in fp_metadata_t meta,
                   inout standard_metadata_t standard_metadata,
                   in bit<32> link_context) {
    action deliver_fp(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    action drop_fp() {
        mark_to_drop(standard_metadata);
    }
    table fp_links {
        key = {
            standard_metadata.ingress_port: exact;
            link_context: exact;
            meta.kind: exact;
        }
        actions = { deliver_fp; drop_fp; }
        default_action = drop_fp();
    }
    apply {
        if (standard_metadata.parser_error != error.NoError) {
            drop_fp();
        } else {
            fp_links.apply();
        }
    }
}
*/

#endif
