#ifndef P4_PROTOCOL_HEADERS_OFP_P4
#define P4_PROTOCOL_HEADERS_OFP_P4

/**
 * OpenFlow 1.0-1.5 wire formats (ONF Switch Specifications)
 * OpenFlow 公共头、端口描述、匹配与 Flow-Mod 固定消息体
 */
const bit<16> OFP_TCP_PORT = 6653;
const bit<16> OFP_LEGACY_TCP_PORT = 6633;
const bit<32> OFP_NO_BUFFER = 0xFFFFFFFF;
const bit<32> OFP_PORT_ANY = 0xFFFFFFFF;
const bit<16> OFP10_PORT_NONE = 0xFFFF;
const bit<16> OFP_MATCH_STANDARD = 0; // OpenFlow 1.1
const bit<16> OFP_MATCH_OXM = 1;      // OpenFlow 1.2+
const bit<16> OFP_HELLO_VERSIONBITMAP = 1;

enum bit<8> ofp_version {
    OFP_1_0 = 0x01,
    OFP_1_1 = 0x02,
    OFP_1_2 = 0x03,
    OFP_1_3 = 0x04,
    OFP_1_4 = 0x05,
    OFP_1_5 = 0x06
}

// These message codes are shared by 1.0-1.5. Other codes depend on version.
enum bit<8> ofp_type {
    OFPT_HELLO = 0,
    OFPT_ERROR = 1,
    OFPT_ECHO_REQUEST = 2,
    OFPT_ECHO_REPLY = 3,
    OFPT_FEATURES_REQUEST = 5,
    OFPT_FEATURES_REPLY = 6,
    OFPT_GET_CONFIG_REQUEST = 7,
    OFPT_GET_CONFIG_REPLY = 8,
    OFPT_SET_CONFIG = 9,
    OFPT_PACKET_IN = 10,
    OFPT_FLOW_REMOVED = 11,
    OFPT_PORT_STATUS = 12,
    OFPT_PACKET_OUT = 13,
    OFPT_FLOW_MOD = 14
}

// Common message header, eight bytes. Length includes header and body.
header ofp_header {
    bit<8> version;
    bit<8> type;
    bit<16> length;
    bit<32> xid;
}

// OpenFlow 1.0 port description, 48 bytes. Name holds a NUL-terminated string.
header ofp10_port_t {
    bit<16> port_no;
    bit<48> hw_addr;
    bit<128> name;
    bit<32> config;
    bit<32> state;
    bit<32> curr;
    bit<32> advertised;
    bit<32> supported;
    bit<32> peer;
}

// OpenFlow 1.1-1.3 port description, 64 bytes. Speeds are in kbps.
header ofp_port {
    bit<32> port_no;
    bit<32> pad1;
    bit<48> hw_addr;
    bit<16> pad2;
    bit<128> name;
    bit<32> config;
    bit<32> state;
    bit<32> curr;
    bit<32> advertised;
    bit<32> supported;
    bit<32> peer;
    bit<32> curr_speed;
    bit<32> max_speed;
}

typedef ofp_port ofp11_port_t;
typedef ofp_port ofp12_port_t;
typedef ofp_port ofp13_port_t;

/* OpenFlow 1.4-1.5 port prefix, 40 bytes. Length includes this prefix and
 * the complete property list. Capability and speed fields moved to properties.
 */
header ofp14_port_t {
    bit<32> port_no;
    bit<16> length;
    bit<16> pad1;
    bit<48> hw_addr;
    bit<16> pad2;
    bit<128> name;
    bit<32> config;
    bit<32> state;
}

typedef ofp14_port_t ofp15_port_t;

// Port-Status body prefix, eight bytes. A version-specific port follows it.
header ofp_port_status_prefix_t {
    bit<8> reason; // 0: add, 1: delete, 2: modify
    bit<56> pad;
}

// OpenFlow 1.0 match, 40 bytes. No Type or Length prefix is present.
header ofp10_match_t {
    bit<32> wildcards;
    bit<16> in_port;
    bit<48> dl_src;
    bit<48> dl_dst;
    bit<16> dl_vlan;
    bit<8> dl_vlan_pcp;
    bit<8> pad1;
    bit<16> dl_type;
    bit<8> nw_tos;
    bit<8> nw_proto;
    bit<16> pad2;
    bit<32> nw_src;
    bit<32> nw_dst;
    bit<16> tp_src;
    bit<16> tp_dst;
}

// OpenFlow 1.1 standard match, 88 bytes, Type = 0 and Length = 88.
header ofp11_match_t {
    bit<16> type;
    bit<16> length;
    bit<32> in_port;
    bit<32> wildcards;
    bit<48> dl_src;
    bit<48> dl_src_mask;
    bit<48> dl_dst;
    bit<48> dl_dst_mask;
    bit<16> dl_vlan;
    bit<8> dl_vlan_pcp;
    bit<8> pad1;
    bit<16> dl_type;
    bit<8> nw_tos;
    bit<8> nw_proto;
    bit<32> nw_src;
    bit<32> nw_src_mask;
    bit<32> nw_dst;
    bit<32> nw_dst_mask;
    bit<16> tp_src;
    bit<16> tp_dst;
    bit<32> mpls_label;
    bit<8> mpls_tc;
    bit<24> pad2;
    bit<64> metadata;
    bit<64> metadata_mask;
}

header ofp_match_prefix_t {
    bit<16> type;
    bit<16> length;
}

/* OpenFlow 1.2-1.5 OXM match. Length counts the four-byte prefix and fields,
 * excluding the following zero to seven bytes of padding to an eight-byte
 * boundary. OXM TLVs have no individual alignment padding.
 */
header ofp_match {
    bit<16> type;
    bit<16> length;
    varbit<524248> fields;
}

header ofp_match_padding_t {
    varbit<56> bytes;
}

// OXM prefix, four bytes. Length counts value and optional mask bytes only.
// Class 0xFFFF includes an experimenter ID in that length before its value.
header ofp_oxm_prefix_t {
    bit<16> oxm_class;
    bit<7> field;
    bit<1> has_mask;
    bit<8> length;
}

/* OpenFlow 1.0 Flow-Mod body after the 40-byte match, 24 bytes.
 * Wire order: ofp_header, ofp10_match_t, this body, then the action list.
 */
header ofp10_flow_mod_t {
    bit<64> cookie;
    bit<16> command;
    bit<16> idle_timeout;
    bit<16> hard_timeout;
    bit<16> priority;
    bit<32> buffer_id;
    bit<16> out_port;
    bit<16> flags;
}

/* OpenFlow 1.1-1.3 Flow-Mod body before the match, 40 bytes.
 * Wire order: ofp_header, this body, the match, then instructions.
 * Idle/hard timeouts are in seconds. A zero timeout leaves that timer disabled.
 */
header ofp_flow_mod {
    bit<64> cookie;
    bit<64> cookie_mask;
    bit<8> table_id;
    bit<8> command;
    bit<16> idle_timeout;
    bit<16> hard_timeout;
    bit<16> priority;
    bit<32> buffer_id;
    bit<32> out_port;
    bit<32> out_group;
    bit<16> flags;
    bit<16> pad;
}

typedef ofp_flow_mod ofp11_flow_mod_t;
typedef ofp_flow_mod ofp12_flow_mod_t;
typedef ofp_flow_mod ofp13_flow_mod_t;

// OpenFlow 1.4-1.5 replaces the final two pad bytes with Importance.
header ofp14_flow_mod_t {
    bit<64> cookie;
    bit<64> cookie_mask;
    bit<8> table_id;
    bit<8> command;
    bit<16> idle_timeout;
    bit<16> hard_timeout;
    bit<16> priority;
    bit<32> buffer_id;
    bit<32> out_port;
    bit<32> out_group;
    bit<16> flags;
    bit<16> importance;
}

typedef ofp14_flow_mod_t ofp15_flow_mod_t;

/* Hello element and port property prefix. Length includes the prefix and
 * value but excludes the following padding to an eight-byte boundary.
 * padded_value retains the value and padding together. Transmit padding as
 * zero and ignore its content on reception, as for fixed padding fields.
 */
header ofp_aligned_tlv_prefix_t {
    bit<16> type;
    bit<16> length;
}

header ofp_aligned_tlv_t {
    bit<16> type;
    bit<16> length;
    varbit<524256> padded_value;
}

// Action and instruction lengths include padding and are multiples of eight.
// Type-specific fields follow these four-byte prefixes.
header ofp_action_prefix_t {
    bit<16> type;
    bit<16> length;
}

header ofp_instruction_prefix_t {
    bit<16> type;
    bit<16> length;
}

enum bit<8> ofp_body_kind {
    OPAQUE = 0,
    HELLO_ELEMENTS = 1,
    PORT_STATUS = 2,
    FLOW_MOD = 3
}

struct ofp_headers_t {
    ofp_header message;
    ofp_port_status_prefix_t port_status;
    ofp10_port_t port_1_0;
    ofp_port port_1_1;
    ofp14_port_t port_1_4;
    ofp10_match_t match_1_0;
    ofp10_flow_mod_t flow_1_0;
    ofp_flow_mod flow_1_1;
    ofp14_flow_mod_t flow_1_4;
    ofp11_match_t match_1_1;
    ofp_match match_oxm;
    ofp_match_padding_t match_padding;
    ofp_aligned_tlv_t[16] records;
}

struct ofp_metadata_t {
    ofp_body_kind body_kind;
    bit<32> remaining_bytes;
    bool body_complete;
    bit<5> parsed_records;
    bool match_present;
    bit<16> match_length;
    bit<3> match_padding_bytes;
    bit<32> port_no;
    bit<8> port_reason;
    bit<8> table_id;
    bit<16> command;
    bit<16> importance;
}

/**
 * Bounded parsing and local delivery (P4_16, v1model).
 * The caller supplies one complete message and its exact byte count after
 * TCP reassembly and any TLS decryption. Transport and link padding are
 * outside message_bytes. context_id identifies the control session.
 *
 * Port-Status and Flow-Mod bodies are parsed for wire versions 1-6. Hello
 * elements are framed for versions 4-6, up to 16 elements or port properties.
 * Match fields, property values and Hello bitmaps keep their wire encoding.
 * Actions/instructions, other message bodies and unknown match formats stay
 * opaque. remaining_bytes counts the untouched body and body_complete marks
 * whether the cursor reached the message end. An unknown Hello version can
 * still be delivered to the session handler for version negotiation.
 *
 * Emit the headers in ofp_headers_t order, then the original remainder.
 * The session handler negotiates versions, validates message roles, match
 * prerequisites, property/action/instruction formats, and updates flow state.
 */
/*
parser ofp_parser(packet_in pkt, out ofp_headers_t hdr,
                  out ofp_metadata_t meta, in bit<32> message_bytes) {
    bit<32> remaining;
    bit<32> padded_bytes;

    state start {
        meta.body_kind = ofp_body_kind.OPAQUE;
        meta.remaining_bytes = 0;
        meta.body_complete = false;
        meta.parsed_records = 0;
        meta.match_present = false;
        meta.match_length = 0;
        meta.match_padding_bytes = 0;
        meta.port_no = 0;
        meta.port_reason = 0;
        meta.table_id = 0;
        meta.command = 0;
        meta.importance = 0;
        verify(message_bytes >= 8, error.HeaderTooShort);
        pkt.extract(hdr.message);
        verify(hdr.message.length >= 8, error.NoMatch);
        verify((bit<32>)hdr.message.length == message_bytes, error.NoMatch);
        remaining = message_bytes - 8;
        transition select(hdr.message.type, hdr.message.version) {
            (ofp_type.OFPT_HELLO, 4..6): start_hello;
            (ofp_type.OFPT_PORT_STATUS, 1..6): start_port_status;
            (ofp_type.OFPT_FLOW_MOD, 1): parse_flow_1_0;
            (ofp_type.OFPT_FLOW_MOD, 2..4): parse_flow_1_1;
            (ofp_type.OFPT_FLOW_MOD, 5..6): parse_flow_1_4;
            default: finish;
        }
    }

    state finish {
        meta.remaining_bytes = remaining;
        meta.body_complete = remaining == 0;
        transition accept;
    }

    state start_hello {
        meta.body_kind = ofp_body_kind.HELLO_ELEMENTS;
        transition check_record;
    }

    state check_record {
        transition select(remaining, meta.parsed_records) {
            (0, _): finish;
            (_, 16): finish;
            default: parse_record;
        }
    }

    state parse_record {
        ofp_aligned_tlv_prefix_t prefix;
        verify(remaining >= 4, error.HeaderTooShort);
        prefix = pkt.lookahead<ofp_aligned_tlv_prefix_t>();
        verify(prefix.length >= 4, error.NoMatch);
        padded_bytes = ((bit<32>)prefix.length + 7) & 0xFFFFFFF8;
        verify(padded_bytes <= remaining, error.HeaderTooShort);
        if (meta.body_kind == ofp_body_kind.HELLO_ELEMENTS
            && prefix.type == OFP_HELLO_VERSIONBITMAP) {
            verify((prefix.length & 3) == 0, error.NoMatch);
        }
        pkt.extract(hdr.records.next, (padded_bytes - 4) * 8);
        meta.parsed_records = meta.parsed_records + 1;
        remaining = remaining - padded_bytes;
        transition check_record;
    }

    state start_port_status {
        meta.body_kind = ofp_body_kind.PORT_STATUS;
        verify(remaining >= 8, error.HeaderTooShort);
        pkt.extract(hdr.port_status);
        meta.port_reason = hdr.port_status.reason;
        remaining = remaining - 8;
        transition select(hdr.message.version) {
            1: parse_port_1_0;
            2..4: parse_port_1_1;
            default: parse_port_1_4;
        }
    }

    state parse_port_1_0 {
        verify(remaining == 48, error.NoMatch);
        pkt.extract(hdr.port_1_0);
        meta.port_no = (bit<32>)hdr.port_1_0.port_no;
        remaining = 0;
        transition finish;
    }

    state parse_port_1_1 {
        verify(remaining == 64, error.NoMatch);
        pkt.extract(hdr.port_1_1);
        meta.port_no = hdr.port_1_1.port_no;
        remaining = 0;
        transition finish;
    }

    state parse_port_1_4 {
        verify(remaining >= 40, error.HeaderTooShort);
        pkt.extract(hdr.port_1_4);
        verify((bit<32>)hdr.port_1_4.length == remaining
               && (hdr.port_1_4.length & 7) == 0, error.NoMatch);
        meta.port_no = hdr.port_1_4.port_no;
        remaining = remaining - 40;
        transition check_record;
    }

    state parse_flow_1_0 {
        meta.body_kind = ofp_body_kind.FLOW_MOD;
        verify(remaining >= 64, error.HeaderTooShort);
        pkt.extract(hdr.match_1_0);
        pkt.extract(hdr.flow_1_0);
        meta.match_present = true;
        meta.match_length = 40;
        meta.command = hdr.flow_1_0.command;
        remaining = remaining - 64;
        transition finish;
    }

    state parse_flow_1_1 {
        meta.body_kind = ofp_body_kind.FLOW_MOD;
        verify(remaining >= 40, error.HeaderTooShort);
        pkt.extract(hdr.flow_1_1);
        meta.table_id = hdr.flow_1_1.table_id;
        meta.command = (bit<16>)hdr.flow_1_1.command;
        remaining = remaining - 40;
        transition select(hdr.message.version) {
            2: check_match_1_1;
            default: check_oxm;
        }
    }

    state parse_flow_1_4 {
        meta.body_kind = ofp_body_kind.FLOW_MOD;
        verify(remaining >= 40, error.HeaderTooShort);
        pkt.extract(hdr.flow_1_4);
        meta.table_id = hdr.flow_1_4.table_id;
        meta.command = (bit<16>)hdr.flow_1_4.command;
        meta.importance = hdr.flow_1_4.importance;
        remaining = remaining - 40;
        transition check_oxm;
    }

    state check_match_1_1 {
        ofp_match_prefix_t prefix;
        verify(remaining >= 4, error.HeaderTooShort);
        prefix = pkt.lookahead<ofp_match_prefix_t>();
        transition select(prefix.type) {
            OFP_MATCH_STANDARD: parse_match_1_1;
            default: finish;
        }
    }

    state parse_match_1_1 {
        verify(remaining >= 88, error.HeaderTooShort);
        pkt.extract(hdr.match_1_1);
        verify(hdr.match_1_1.length == 88, error.NoMatch);
        meta.match_present = true;
        meta.match_length = 88;
        remaining = remaining - 88;
        transition finish;
    }

    state check_oxm {
        ofp_match_prefix_t prefix;
        verify(remaining >= 4, error.HeaderTooShort);
        prefix = pkt.lookahead<ofp_match_prefix_t>();
        transition select(prefix.type) {
            OFP_MATCH_OXM: parse_oxm;
            default: finish;
        }
    }

    state parse_oxm {
        ofp_match_prefix_t prefix;
        prefix = pkt.lookahead<ofp_match_prefix_t>();
        verify(prefix.length >= 4, error.NoMatch);
        padded_bytes = ((bit<32>)prefix.length + 7) & 0xFFFFFFF8;
        verify(padded_bytes <= remaining, error.HeaderTooShort);
        pkt.extract(hdr.match_oxm, ((bit<32>)prefix.length - 4) * 8);
        meta.match_padding_bytes = (bit<3>)(padded_bytes - (bit<32>)prefix.length);
        pkt.extract(hdr.match_padding, (padded_bytes - (bit<32>)prefix.length) * 8);
        meta.match_present = true;
        meta.match_length = prefix.length;
        remaining = remaining - padded_bytes;
        transition finish;
    }
}

control ofp_control(inout ofp_headers_t hdr, in ofp_metadata_t meta,
                    inout standard_metadata_t standard_metadata,
                    in bit<32> context_id) {
    action deliver_ofp(bit<9> handler_port) {
        standard_metadata.egress_spec = handler_port;
    }

    action drop_ofp() {
        mark_to_drop(standard_metadata);
    }

    table ofp_sessions {
        key = {
            context_id: exact;
            hdr.message.version: exact;
            hdr.message.type: exact;
        }
        actions = {
            deliver_ofp;
            drop_ofp;
        }
        default_action = drop_ofp();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.message.isValid()) {
            drop_ofp();
        } else {
            ofp_sessions.apply();
        }
    }
}
*/

#endif
