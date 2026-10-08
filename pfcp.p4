#ifndef P4_PROTOCOL_HEADERS_PFCP_P4
#define P4_PROTOCOL_HEADERS_PFCP_P4

/**
 * Packet Forwarding Control Protocol (3GPP TS 29.244 V18.10.0)
 * 控制面与用户面之间的会话和规则管理协议
 */

typedef bit<16> pfcp_ie_type_t;

// Request destination port. Responses use the request's source port.
const bit<16> PFCP_UDP_PORT = 8805;

/* Common message types */
const bit<8> PFCP_HEARTBEAT_REQUEST = 1;
const bit<8> PFCP_HEARTBEAT_RESPONSE = 2;
const bit<8> PFCP_SESSION_ESTABLISHMENT_REQUEST = 50;
const bit<8> PFCP_SESSION_ESTABLISHMENT_RESPONSE = 51;
const bit<8> PFCP_SESSION_MODIFICATION_REQUEST = 52;
const bit<8> PFCP_SESSION_MODIFICATION_RESPONSE = 53;
const bit<8> PFCP_SESSION_DELETION_REQUEST = 54;
const bit<8> PFCP_SESSION_DELETION_RESPONSE = 55;
const bit<8> PFCP_SESSION_REPORT_REQUEST = 56;
const bit<8> PFCP_SESSION_REPORT_RESPONSE = 57;

/**
 * Common Header Prefix (4 bytes)
 * Message Length counts every byte after this prefix, including the SEID,
 * sequence number, priority/spare octet and information elements.
 */
header pfcp_t {
    bit<3>  version;           // Version 1
    bit<2>  spare;             // Transmit zero, ignore on receipt
    bit<1>  fo_bit;            // Another bundled PFCP message follows
    bit<1>  mp_bit;            // Message priority is meaningful
    bit<1>  s_bit;             // SEID is present
    bit<8>  message_type;
    bit<16> message_length;
};

// S=0: complete PFCP header is 8 bytes.
header pfcp_node_t {
    bit<24> seq_number;
    bit<8>  spare;             // Transmit zero, ignore on receipt
};

// S=1: complete PFCP header is 16 bytes.
header pfcp_session_t {
    bit<64> seid;              // Session Endpoint Identifier
    bit<24> seq_number;
    bit<4>  priority;          // Evaluate only when MP=1, 0 is highest
    bit<4>  spare;             // Transmit zero, ignore on receipt
};

/**
 * Information Element (4-byte prefix followed by its value)
 * IE Length excludes Type and Length. A zero-length value is permitted.
 * A vendor-specific type has its high bit set. Its value includes Enterprise
 * ID when present. Grouped IE values contain nested TLVs, not a PDI count.
 * The varbit limit represents the full 16-bit IE Length range.
 */
header pfcp_ie_t {
    pfcp_ie_type_t ie_type;
    bit<16>       ie_length;
    varbit<524280> ie_value;
};

/* Common IE types */
const pfcp_ie_type_t PFCP_IE_CREATE_PDR = 1;
const pfcp_ie_type_t PFCP_IE_PDI = 2;
const pfcp_ie_type_t PFCP_IE_CREATE_FAR = 3;
const pfcp_ie_type_t PFCP_IE_CREATE_URR = 6;
const pfcp_ie_type_t PFCP_IE_CREATE_QER = 7;
const pfcp_ie_type_t PFCP_IE_MBR = 26;
const pfcp_ie_type_t PFCP_IE_PRECEDENCE = 29;
const pfcp_ie_type_t PFCP_IE_PDR_ID = 56;
const pfcp_ie_type_t PFCP_IE_F_SEID = 57;
const pfcp_ie_type_t PFCP_IE_NODE_ID = 60;
const pfcp_ie_type_t PFCP_IE_QFI = 124;

/**
 * IE Value Prefixes (exclude the 4-byte IE header)
 * Parse these only after handling a null value and checking the IE length.
 * Extendable IEs may contain additional bytes after the known prefix.
 * Create PDR, PDI and Create QER are grouped IEs whose contents are separate
 * TLVs. QFI and MBR are separate IEs within the applicable grouped IE.
 */
header pfcp_pdr_id_t {
    bit<16> pdr_id;
};

header pfcp_precedence_t {
    bit<32> precedence;       // Lower value means higher precedence
};

header pfcp_qfi_t {
    bit<2> spare;             // Transmit zero, ignore on receipt
    bit<6> qfi;               // QoS Flow Identifier
};

header pfcp_mbr_t {
    bit<40> mbr_ul;           // Uplink, in kilobits per second (1000 bit/s)
    bit<40> mbr_dl;           // Downlink, in kilobits per second (1000 bit/s)
};

header pfcp_enterprise_id_t {
    bit<16> enterprise_id;
};

/**
 * P4 Parser Logic for PFCP
 * The packet cursor must point to the PFCP common prefix. Pass the validated
 * UDP payload length as pfcp_length. This example parses one complete message.
 * FO=1 needs a separate bundled-message path and is rejected here.
 * The headers struct contains pfcp_t pfcp, pfcp_node_t pfcp_node,
 * pfcp_session_t pfcp_session and pfcp_ie_t[16] pfcp_ies.
 * The IE stack must be empty on entry. More than 16 top-level IEs cause a
 * parser error. Increase the stack size to suit the target and application.
 *
 * IE values remain opaque, including grouped IEs and vendor-specific values.
 * The enclosing pipeline handles parser errors, IP/UDP bounds, checksums,
 * message-type/flag rules, IE semantics and PFCP error responses. In particular,
 * node messages require S=0 and MP=0, while session messages require S=1.
 * Handling null values, nested TLVs, mandatory/repeated IEs, vendor IDs,
 * retransmissions and session state belongs to the PFCP application.
 */
/*
parser pfcp_parser(packet_in pkt, inout headers hdr,
                   in bit<16> pfcp_length) {
    bit<16> message_left;
    bit<32> ie_prefix;
    bit<16> value_length;
    bit<32> value_bits;

    state start {
        hdr.pfcp_node.setInvalid();
        hdr.pfcp_session.setInvalid();
        verify(pfcp_length >= 4, error.HeaderTooShort);
        pkt.extract(hdr.pfcp);
        verify(hdr.pfcp.version == 1, error.NoMatch);
        verify(hdr.pfcp.fo_bit == 0, error.NoMatch);
        verify(hdr.pfcp.message_length == pfcp_length - 4, error.HeaderTooShort);
        message_left = hdr.pfcp.message_length;
        transition select(hdr.pfcp.s_bit) {
            0: parse_node;
            1: parse_session;
        }
    }

    state parse_node {
        verify(message_left >= 4, error.HeaderTooShort);
        pkt.extract(hdr.pfcp_node);
        message_left = message_left - 4;
        transition check_ies;
    }

    state parse_session {
        verify(message_left >= 12, error.HeaderTooShort);
        pkt.extract(hdr.pfcp_session);
        message_left = message_left - 12;
        transition check_ies;
    }

    state check_ies {
        transition select(message_left) {
            0: accept;
            default: parse_ie;
        }
    }

    state parse_ie {
        verify(message_left >= 4, error.HeaderTooShort);
        ie_prefix = pkt.lookahead<bit<32>>();
        value_length = ie_prefix[15:0];
        verify((bit<32>) value_length + 4 <= (bit<32>) message_left,
               error.HeaderTooShort);
        value_bits = (bit<32>) value_length * 8;
        pkt.extract(hdr.pfcp_ies.next, value_bits);
        message_left = message_left - 4 - value_length;
        transition check_ies;
    }
}
*/

/**
 * P4 Match-Action Pipeline for PFCP (v1model)
 * Select a handler port after message and IE validation. Packets stay intact.
 * Keep SEID presence in the key so that a node message differs from a session
 * message with SEID zero, as used in a Session Establishment Request.
 * The PFCP application manages sessions and programs forwarding rules.
 */
/*
control pfcp_control(inout headers hdr,
                     inout standard_metadata_t standard_metadata) {
    bit<64> session_id;

    action send_pfcp(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action drop_pfcp() {
        mark_to_drop(standard_metadata);
    }

    table pfcp_handlers {
        key = {
            hdr.pfcp.message_type: exact;
            hdr.pfcp.s_bit: exact;
            session_id: exact;
        }
        actions = {
            send_pfcp;
            drop_pfcp;
            NoAction;
        }
        default_action = drop_pfcp();
    }

    apply {
        session_id = 0;
        if (standard_metadata.parser_error != error.NoError
            || !hdr.pfcp.isValid()) {
            drop_pfcp();
        } else {
            if (hdr.pfcp_session.isValid()) {
                session_id = hdr.pfcp_session.seid;
            }
            pfcp_handlers.apply();
        }
    }
}
*/

#endif
