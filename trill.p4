#ifndef P4_PROTOCOL_HEADERS_TRILL_P4
#define P4_PROTOCOL_HEADERS_TRILL_P4

/**
 * TRILL data headers (RFC 6325, RFC 7455, RFC 7179, RFC 7780, RFC 9600)
 * TRILL 数据报头、扩展标志字和解析分流示例
 */
const bit<16> ETHERTYPE_TRILL = 16w0x22F3;
const bit<16> ETHERTYPE_L2_IS_IS = 16w0x22F4;
const bit<48> TRILL_ALL_RBRIDGES = 48w0x0180C2000040;
const bit<48> TRILL_ALL_IS_IS_RBRIDGES = 48w0x0180C2000041;

enum bit<2> trill_ecn {
    NOT_ECT = 0,
    ECT_1 = 1,
    ECT_0 = 2,
    NCCE = 3
}

/* Current six-byte base header, RFC 7780 Section 10.
 * A is the OAM Alert bit. C is the implementation-defined Color bit.
 * The former five-bit Op-Length is now four reserved bits and F. F selects
 * one four-byte flags word. Reserved bits are sent as zero, and receivers
 * discard nonzero values unless a supported future specification uses them.
 * With M=1, egress_rbridge identifies the distribution tree.
 */
header trill_t {
    bit<2> version;
    bit<1> alert;
    bit<1> color;
    bit<1> multi_dest;
    bit<4> reserved;
    bit<1> flags_present;
    bit<6> hop_count;
    bit<16> egress_rbridge;
    bit<16> ingress_rbridge;
}

/* Optional flags word, in IETF bit order (bit 0 is the most significant).
 * Summary bits describe critical hop-by-hop, ingress-to-egress and reserved
 * extensions. Extended Hop Count supplies the high three bits of a nine-bit
 * count. Channel Alert flags occupy bits 7 and 8. RFC 9600 assigns bits 12-13
 * to TRILL-ECN and bit 26 to CCE. Extended Color occupies bits 27-28.
 * Unassigned bits are retained for the owner's extension handling.
 * CCE is distinct from the two-bit TRILL-ECN codepoint.
 */
header trill_flags_t {
    bit<1> critical_hop_by_hop_summary;
    bit<1> critical_ingress_to_egress_summary;
    bit<1> critical_reserved_summary;
    bit<4> critical_hop_by_hop;
    bit<1> critical_channel_alert;
    bit<1> noncritical_channel_alert;
    bit<3> noncritical_hop_by_hop;
    bit<2> ecn;
    bit<3> extended_hop_count;
    bit<4> noncritical_reserved;
    bit<5> critical_ingress_to_egress;
    bit<1> critical_congestion_experienced;
    bit<2> extended_color;
    bit<3> noncritical_ingress_to_egress;
}

struct trill_headers_t {
    trill_t base;
    trill_flags_t flags;
}

struct trill_metadata_t {
    bit<32> header_bytes;
    bit<32> inner_bytes;
    bit<9> hop_count;
    bit<3> critical_summary;
}

/**
 * TRILL header parsing and local delivery (P4_16, v1model).
 * The caller removes the outer link header, selects EtherType 0x22F3 and
 * supplies the bounded TRILL payload length, excluding FCS.
 * EtherType 0x22F4 carries IS-IS directly and uses the parser in isis.p4.
 *
 * Emit base and flags, then the original remainder. The inner Ethernet frame,
 * including its VLAN/FGL tags and payload, stays intact. The example checks
 * header bounds and the minimum 18-byte inner Ethernet/VLAN header length.
 * The local owner handles critical extensions, OAM, hop-count processing,
 * inner-frame validation and routing state before forwarding or decapsulation.
 */
/*
parser trill_parser(packet_in pkt, out trill_headers_t hdr,
                    out trill_metadata_t meta, in bit<32> frame_bytes) {
    state start {
        meta.header_bytes = 0;
        meta.inner_bytes = 0;
        meta.hop_count = 0;
        meta.critical_summary = 0;
        verify(frame_bytes >= 6, error.HeaderTooShort);
        pkt.extract(hdr.base);
        verify(hdr.base.version == 0 && hdr.base.reserved == 0, error.NoMatch);
        meta.header_bytes = 6;
        meta.hop_count = (bit<9>) hdr.base.hop_count;
        transition select(hdr.base.flags_present) {
            1: parse_flags;
            default: end_header;
        }
    }

    state parse_flags {
        verify(frame_bytes >= 10, error.HeaderTooShort);
        pkt.extract(hdr.flags);
        meta.header_bytes = 10;
        meta.hop_count = hdr.flags.extended_hop_count ++ hdr.base.hop_count;
        meta.critical_summary = hdr.flags.critical_hop_by_hop_summary ++
                                hdr.flags.critical_ingress_to_egress_summary ++
                                hdr.flags.critical_reserved_summary;
        transition end_header;
    }

    state end_header {
        meta.inner_bytes = frame_bytes - meta.header_bytes;
        verify(meta.inner_bytes >= 18, error.HeaderTooShort);
        transition accept;
    }
}

control trill_control(inout trill_headers_t hdr, in trill_metadata_t meta,
                      inout standard_metadata_t standard_metadata,
                      in bit<32> link_context) {
    action deliver_trill(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    action drop_trill() {
        mark_to_drop(standard_metadata);
    }
    table trill_handlers {
        key = {
            link_context: exact;
            hdr.base.alert: exact;
            hdr.base.multi_dest: exact;
            meta.critical_summary: exact;
        }
        actions = { deliver_trill; drop_trill; }
        default_action = drop_trill();
    }
    apply {
        if (standard_metadata.parser_error != error.NoError) {
            drop_trill();
        } else {
            trill_handlers.apply();
        }
    }
}
*/

#endif
