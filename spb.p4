/**
 * Shortest Path Bridging (IEEE 802.1aq / IEEE 802.1Q, RFC 6329)
 * SPBM 数据标签、SPB IS-IS 扩展和有界解析示例
 */
#ifndef P4_PROTOCOL_HEADERS_SPB_P4
#define P4_PROTOCOL_HEADERS_SPB_P4

typedef bit<24> iSid_t;

const bit<16> SPB_B_TAG_TYPE = 16w0x88a8;
const bit<16> SPB_I_TAG_TYPE = 16w0x88e7;
const bit<8> SPB_NLPID = 8w0xc1; // In the IIH Protocols Supported TLV
const iSid_t I_SID_CONTROL_PLANE = 24w0x0000ff; // RFC 6329, Errata 3503

const bit<8> SPB_TLV_MT_PORT_CAP = 143; // IIH, RFC 6165
const bit<8> SPB_TLV_MT_CAP = 144; // LSP, RFC 6329
const bit<8> SPB_TLV_EXTENDED_IS_REACH = 22;
const bit<8> SPB_TLV_MT_IS_NEIGHBOR = 222;

// Sub-TLV numbers belong to their enclosing TLV's registry.
const bit<8> SPB_PORT_SUBTLV_MCID = 4;
const bit<8> SPB_PORT_SUBTLV_DIGEST = 5;
const bit<8> SPB_PORT_SUBTLV_BASE_VID = 6;
const bit<8> SPB_MT_SUBTLV_INSTANCE = 1;
const bit<8> SPB_MT_SUBTLV_OPAQUE_ECT = 2;
const bit<8> SPB_MT_SUBTLV_SPBM_SERVICE = 3;
const bit<8> SPB_MT_SUBTLV_SPBV_ADDRESS = 4;
const bit<8> SPB_LINK_SUBTLV_METRIC = 29;
const bit<8> SPB_LINK_SUBTLV_OPAQUE_ECT = 30;
const bit<24> SPB_LINK_METRIC_UNUSABLE = 24w0xffffff;

// SPB has no combined data/control header. SPBM uses PBB MAC-in-MAC
// encapsulation. SPBV uses the VLAN/PB/PBB formats of the configured network.
// SPBV VLAN tags can be represented by vlan_header from vlan.p4.
// An I-SID names a service instance, not a fixed application or media type.

// Four octets after the B-Tag TPID in the backbone Ethernet header.
// The TCI has the standard S-Tag layout. ether_type identifies the next tag.
// For the base SPBM encapsulation it is SPB_I_TAG_TYPE.
header spb_b_tag_t {
    bit<3> pcp;
    bit<1> dei;
    bit<12> b_vid;
    bit<16> ether_type;
}

// Four-octet I-TAG TCI, extracted after the I-TAG TPID 0x88e7.
// It is followed by C-DA and C-SA, then the customer's Type/Length or tags.
// Together the TPID, TCI and two customer MAC addresses form the I-TAG.
// UCA is the Use Customer Addresses indicator. Its processing depends on
// the receiving PIP/CBP role. Res1 is zero on transmission and ignored on
// receipt. Res2 is zero on transmission. A nonzero Res2 is not this format.
// Backbone PCP/DEI and these service PCP/DEI values are distinct.
header spb_t {
    bit<3> pcp;
    bit<1> dei;
    bit<1> uca;
    bit<1> res1;
    bit<2> res2;
    iSid_t i_sid;
}

// The first fourteen octets of the encapsulated customer frame.
// type_length can be an EtherType, a VLAN TPID or an 802.3 length.
header spb_customer_t {
    bit<48> dst_mac;
    bit<48> src_mac;
    bit<16> type_length;
}

// IS-IS TLV/sub-TLV framing. length counts value octets only.
// Extract this header before one of the fixed value prefixes below.
header spb_isis_tlv_t {
    bit<8> type;
    bit<8> length;
}

// Optional opaque sub-TLV representation for a bounded header stack.
// This maximum follows the eight-bit length, not an implementation profile.
header spb_sub_tlv_t {
    bit<8> type;
    bit<8> length;
    varbit<2040> value;
}

// First two value octets of MT-Port-Cap (143), followed by sub-TLVs.
// Reserved bits are transmitted zero and ignored on receipt (RFC 6165).
header spb_mt_port_capability_t {
    bit<4> reserved;
    bit<12> mt_id;
}

// First two value octets of MT-Capability (144), followed by sub-TLVs.
header spb_mt_capability_t {
    bit<1> overload;
    bit<3> reserved;
    bit<12> mt_id;
}

// SPB-MCID (143/4) value has two consecutive 51-octet identifiers:
// the MCID and the auxiliary MCID. The sub-TLV length is 102.
header spb_mcid_t {
    bit<8> format_selector;
    bit<256> configuration_name;
    bit<16> revision_level;
    bit<128> configuration_digest;
}

// First value octet of SPB-Digest (143/5), followed by Agreement Digest.
// The digest format and length are defined by the applicable IEEE profile.
header spb_digest_prefix_t {
    bit<3> reserved;
    bit<1> agreed_digest_valid;
    bit<2> agreement_number;
    bit<2> discarded_agreement_number;
}

// One six-octet tuple in SPB-B-VID (143/6). Value length is 6 * tuple count.
// mac_mode 1 selects SPBM, 0 selects SPBV. ECT encodes OUI (24) + index (8).
header spb_base_vid_tuple_t {
    bit<32> ect_algorithm;
    bit<12> base_vid;
    bit<1> use_flag;
    bit<1> mac_mode;
    bit<2> reserved;
}

// First nineteen value octets of SPB-Inst (144/1). Follow with num_trees
// eight-octet spb_vid_tuple_t entries. Value length is 19 + 8 * num_trees.
// The originating node's System ID is in the enclosing LSP, not this value.
// bridge_priority is the packed sixteen-bit component of its Bridge ID.
header spb_instance_prefix_t {
    bit<64> cist_root_id;
    bit<32> cist_external_root_path_cost;
    bit<16> bridge_priority;
    bit<11> reserved;
    bit<1> auto_source_id;
    bit<20> sp_source_id;
    bit<8> num_trees;
}

header spb_vid_tuple_t {
    bit<1> use_flag;
    bit<1> mac_mode;
    bit<1> auto_spvid;
    bit<5> reserved;
    bit<32> ect_algorithm;
    bit<12> base_vid;
    bit<12> spvid; // Zero in SPBM mode
}

// First four value octets of SPB-I-OALG (144/2) or SPB-A-OALG (22/30,
// 222/30). Any following algorithm information has its own opaque format.
header spb_opaque_ect_prefix_t {
    bit<32> ect_algorithm;
}

// First four value octets of SPB-Metric (22/29 or 222/29), followed by
// num_ports packed sixteen-bit IEEE Port Identifiers. Length is 4 + 2*n.
// Metric 0xffffff excludes the link from SPB forwarding computations.
header spb_link_metric_prefix_t {
    bit<24> link_metric;
    bit<8> num_ports;
}

header spb_port_identifier_t {
    bit<4> priority;
    bit<12> port_number;
}

// First eight value octets of SPBM-SI (144/3), followed by zero or more
// four-octet spb_service_entry_t values. Length is 8 + 4*n. Repeated
// sub-TLVs can advertise more I-SIDs for the same B-MAC (RFC 6329, 16.1).
header spbm_service_prefix_t {
    bit<48> b_mac;
    bit<4> reserved;
    bit<12> base_vid;
}

header spb_service_entry_t {
    bit<1> transmit;
    bit<1> receive;
    bit<6> reserved;
    iSid_t i_sid;
}

// First two value octets of SPBV-ADDR (144/4), followed by zero or more
// seven-octet spb_mac_entry_t values. Length is 2 + 7*n.
// service_requirement: 0 undeclared, 1 all groups, 2 unregistered groups.
header spbv_address_prefix_t {
    bit<2> reserved;
    bit<2> service_requirement;
    bit<12> spvid;
}

header spb_mac_entry_t {
    bit<1> transmit;
    bit<1> receive;
    bit<6> reserved;
    bit<48> mac;
}

struct spbm_metadata_t {
    bit<32> parsed_bytes; // Starts at I-TAG TCI, excludes backbone tags
    bit<32> unparsed_bytes;
}

struct spb_mt_metadata_t {
    bit<32> tlv_bytes; // Includes the two-octet TLV header
    bit<32> parsed_bytes;
    bit<32> trailing_bytes; // Outside this TLV, retained unchanged
    bit<16> remaining;
    bit<8> sub_tlv_count;
}

/**
 * SPBM I-TAG and customer prefix parser
 * headers contains spb_t spb and spb_customer_t spb_customer.
 * metadata contains spbm_metadata_t spbm. The enclosing parser verifies
 * I-TAG TPID 0x88e7, supplies physically bounded payload_bytes excluding
 * FCS, and places the cursor at the I-TAG TCI. It has already handled the
 * backbone Ethernet header and B-Tag, if present, with its VLAN context.
 * Emit spb, spb_customer and the remaining bytes in the original order.
 *
 * Customer tags, payload and padding remain unchanged. This decoder does
 * not decapsulate or forward customer traffic. The local handler checks
 * service membership, backbone addresses, UCA and PIP/CBP role rules.
 */
/*
parser spbm_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                   in bit<32> payload_bytes) {
    state start {
        hdr.spb.setInvalid();
        hdr.spb_customer.setInvalid();
        meta.spbm.parsed_bytes = 0;
        meta.spbm.unparsed_bytes = payload_bytes;
        verify(payload_bytes >= 18, error.HeaderTooShort);
        pkt.extract(hdr.spb);
        verify(hdr.spb.res2 == 0, error.NoMatch);
        pkt.extract(hdr.spb_customer);
        meta.spbm.parsed_bytes = 18;
        meta.spbm.unparsed_bytes = payload_bytes - 18;
        transition accept;
    }
}
*/

/**
 * Single MT-Port-Cap or MT-Capability TLV parser
 * headers contains spb_isis_tlv_t spb_tlv, spb_mt_port_capability_t
 * spb_mt_port, spb_mt_capability_t spb_mt and spb_sub_tlv_t[8] spb_sub.
 * metadata contains spb_mt_metadata_t spb_mt. The enclosing IS-IS parser
 * supplies available_bytes bounded by both the physical packet and PDU
 * length. The cursor starts at this TLV's type octet, not an IS-IS PDU.
 * Emit spb_tlv, whichever MT prefix is valid, spb_sub and remaining bytes.
 *
 * This example handles at most eight sub-TLVs. This is a local capacity,
 * not a protocol limit. Excess entries produce a parser error. Zero-length
 * and unknown values are preserved. The handler validates known value
 * layouts, tuple counts, PDU placement, repeated advertisements, NLPID
 * support, digests and topology state. Link sub-TLVs in TLVs 22/222 need
 * their enclosing neighbor entry and are not parsed by this example.
 */
/*
parser spb_mt_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                     in bit<32> available_bytes) {
    bit<32> value_bytes;

    state start {
        hdr.spb_tlv.setInvalid();
        hdr.spb_mt_port.setInvalid();
        hdr.spb_mt.setInvalid();
        hdr.spb_sub[0].setInvalid();
        hdr.spb_sub[1].setInvalid();
        hdr.spb_sub[2].setInvalid();
        hdr.spb_sub[3].setInvalid();
        hdr.spb_sub[4].setInvalid();
        hdr.spb_sub[5].setInvalid();
        hdr.spb_sub[6].setInvalid();
        hdr.spb_sub[7].setInvalid();
        meta.spb_mt.tlv_bytes = 0;
        meta.spb_mt.parsed_bytes = 0;
        meta.spb_mt.trailing_bytes = available_bytes;
        meta.spb_mt.remaining = 0;
        meta.spb_mt.sub_tlv_count = 0;
        verify(available_bytes >= 2, error.HeaderTooShort);
        pkt.extract(hdr.spb_tlv);
        verify(hdr.spb_tlv.length >= 2, error.HeaderTooShort);
        meta.spb_mt.tlv_bytes = (bit<32>) hdr.spb_tlv.length + 2;
        verify(meta.spb_mt.tlv_bytes <= available_bytes,
               error.HeaderTooShort);
        meta.spb_mt.remaining = (bit<16>) hdr.spb_tlv.length - 2;
        meta.spb_mt.trailing_bytes = available_bytes - meta.spb_mt.tlv_bytes;
        meta.spb_mt.parsed_bytes = 4;
        transition select(hdr.spb_tlv.type) {
            SPB_TLV_MT_PORT_CAP: parse_port_capability;
            SPB_TLV_MT_CAP: parse_capability;
            default: unsupported_type;
        }
    }

    state parse_port_capability {
        pkt.extract(hdr.spb_mt_port);
        transition next_sub_tlv;
    }

    state parse_capability {
        pkt.extract(hdr.spb_mt);
        transition next_sub_tlv;
    }

    state next_sub_tlv {
        transition select(meta.spb_mt.remaining, meta.spb_mt.sub_tlv_count) {
            (0, _): accept;
            (_, 8): capacity_exceeded;
            default: parse_sub_tlv;
        }
    }

    state parse_sub_tlv {
        verify(meta.spb_mt.remaining >= 2, error.HeaderTooShort);
        value_bytes = (bit<32>) (pkt.lookahead<bit<16>>() & 16w0x00ff);
        verify(value_bytes + 2 <= (bit<32>) meta.spb_mt.remaining,
               error.HeaderTooShort);
        pkt.extract(hdr.spb_sub.next, value_bytes * 8);
        meta.spb_mt.remaining = meta.spb_mt.remaining
                              - (bit<16>) value_bytes - 2;
        meta.spb_mt.parsed_bytes = meta.spb_mt.parsed_bytes + value_bytes + 2;
        meta.spb_mt.sub_tlv_count = meta.spb_mt.sub_tlv_count + 1;
        transition next_sub_tlv;
    }

    state unsupported_type {
        verify(false, error.NoMatch);
        transition accept;
    }

    state capacity_exceeded {
        verify(false, error.StackOutOfBounds);
        transition accept;
    }
}
*/

/**
 * SPBM service delivery to a local application (v1model)
 * handler_port and table action ports are local application endpoints.
 * This table selects a decoder, not a backbone forwarding path. SPF, ECT,
 * source forwarding checks and multicast replication need IS-IS state.
 * Keep receiving port and backbone VLAN context with the delivered frame.
 */
/*
control spbm_control(inout headers hdr,
                     inout standard_metadata_t standard_metadata,
                     in bit<9> handler_port) {
    action deliver(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action deliver_default() {
        standard_metadata.egress_spec = handler_port;
    }

    table service_handlers {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.spb.i_sid: exact;
            hdr.spb.uca: exact;
        }
        actions = {
            deliver;
            deliver_default;
        }
        default_action = deliver_default();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.spb.isValid() || !hdr.spb_customer.isValid()) {
            mark_to_drop(standard_metadata);
        } else {
            service_handlers.apply();
        }
    }
}
*/

/** Local delivery of the parsed MT TLV with original PDU/port context. */
/*
control spb_mt_control(inout headers hdr,
                       inout standard_metadata_t standard_metadata,
                       in bit<9> handler_port) {
    bit<12> mt_id;

    action deliver(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action deliver_default() {
        standard_metadata.egress_spec = handler_port;
    }

    table topology_handlers {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.spb_tlv.type: exact;
            mt_id: exact;
        }
        actions = {
            deliver;
            deliver_default;
        }
        default_action = deliver_default();
    }

    apply {
        mt_id = 0;
        if (standard_metadata.parser_error != error.NoError
            || !hdr.spb_tlv.isValid()
            || (!hdr.spb_mt.isValid() && !hdr.spb_mt_port.isValid())) {
            mark_to_drop(standard_metadata);
        } else {
            if (hdr.spb_mt.isValid()) {
                mt_id = hdr.spb_mt.mt_id;
            } else {
                mt_id = hdr.spb_mt_port.mt_id;
            }
            topology_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_SPB_P4
