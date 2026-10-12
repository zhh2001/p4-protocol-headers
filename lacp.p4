/**
 * LACP headers (IEEE 802.1AX, 6.4.2)
 * 标准 LACPDU、状态位和基础信息解析示例
 */
#ifndef P4_PROTOCOL_HEADERS_LACP_P4
#define P4_PROTOCOL_HEADERS_LACP_P4

#include "ethernet.p4"

// Protocol-specific aliases avoid collisions with other header files.
typedef bit<48> lacp_mac_t;
typedef bit<16> lacp_port_t;
typedef bit<8> lacpState_t;

const bit<16> LACP_ETHER_TYPE = 16w0x8809; // Slow Protocols
const bit<48> LACP_MULTICAST = 48w0x0180c2000002;
const bit<8> LACP_SUBTYPE = 1; // Marker uses a different subtype, 2
const bit<8> LACP_VERSION_1 = 1;
const bit<8> LACP_VERSION_2 = 2;

// Ordinary TLV lengths include type and length octets. The Terminator
// carries two octets on the wire but its length field is zero.
enum bit<8> lacp_tlv_type {
    LACP_TERMINATOR = 0,
    LACP_ACTOR_INFORMATION = 1,
    LACP_PARTNER_INFORMATION = 2,
    LACP_COLLECTOR_INFORMATION = 3,
    LACP_PORT_ALGORITHM = 4,
    LACP_PORT_CONVERSATION_LINK_DIGEST = 5,
    LACP_PORT_CONVERSATION_SERVICE_DIGEST = 10
}

// Masks for the eight Actor/Partner State bits, from LSB to MSB.
// Defaulted means administratively supplied Partner information is in use.
// Expired describes the Receive machine state. There is no universal
// default operational state bitmap.
const lacpState_t LACP_STATE_ACTIVE = 8w0x01;
const lacpState_t LACP_STATE_TIMEOUT = 8w0x02; // Short timeout preference
const lacpState_t LACP_STATE_AGG = 8w0x04;
const lacpState_t LACP_STATE_SYNC = 8w0x08;
const lacpState_t LACP_STATE_COLLECT = 8w0x10;
const lacpState_t LACP_STATE_DISTRIB = 8w0x20;
const lacpState_t LACP_STATE_DEFAULTED = 8w0x40;
const lacpState_t LACP_STATE_EXPIRED = 8w0x80;

// Fast/slow periodic transmission intervals are 1/30 seconds. The short
// and long receive timeouts are 3/90 seconds. The TIMEOUT bit requests a
// short receive timeout, rather than directly encoding a one-second timer.

header lacp_prefix {
    bit<8> subtype;
    bit<8> version;
}

// Complete twenty-octet Actor Information TLV. All multioctet integers
// use network byte order. Transmit type 1, length 20 and zero reserved.
header lacp_actor_info {
    bit<8> type;
    bit<8> length;
    bit<16> actor_sys_priority;
    lacp_mac_t actor_sys_id;
    bit<16> actor_key;
    bit<16> actor_port_priority;
    lacp_port_t actor_port;
    lacpState_t actor_state;
    bit<24> reserved;
}

// Complete twenty-octet Partner Information TLV. Transmit type 2 and
// length 20. Fields describe the sender's current view of its Partner.
header lacp_partner_info {
    bit<8> type;
    bit<8> length;
    bit<16> partner_sys_priority;
    lacp_mac_t partner_sys_id;
    bit<16> partner_key;
    bit<16> partner_port_priority;
    lacp_port_t partner_port;
    lacpState_t partner_state;
    bit<24> reserved;
}

// Complete sixteen-octet Collector Information TLV. Transmit type 3,
// length 16 and zero reserved. Maximum delay is in units of 10 microseconds.
header lacp_collector_info {
    bit<8> type;
    bit<8> length;
    bit<16> collector_max_delay;
    bit<96> reserved;
}

header lacp_terminator {
    bit<8> type; // Transmit 0
    bit<8> length; // Transmit 0
}

// Complete Version 1 LACPDU, 110 octets from subtype through its pad.
// This preserves the original Actor/Partner field names. Version 2 inserts
// other TLVs between Collector and Terminator, reducing the pad accordingly.
// Use the separate headers for that layout, rather than this fixed view.
header lacp_t {
    bit<8> subtype;
    bit<8> version;
    bit<8> actor_type;
    bit<8> actor_length;
    bit<16> actor_sys_priority;
    lacp_mac_t actor_sys_id;
    bit<16> actor_key;
    bit<16> actor_port_priority;
    lacp_port_t actor_port;
    lacpState_t actor_state;
    bit<24> actor_reserved;
    bit<8> partner_type;
    bit<8> partner_length;
    bit<16> partner_sys_priority;
    lacp_mac_t partner_sys_id;
    bit<16> partner_key;
    bit<16> partner_port_priority;
    lacp_port_t partner_port;
    lacpState_t partner_state;
    bit<24> partner_reserved;
    bit<8> collector_type;
    bit<8> collector_length;
    bit<16> collector_max_delay;
    bit<96> collector_reserved;
    bit<8> terminator_type;
    bit<8> terminator_length;
    bit<400> pad; // 50 octets for the Version 1 transmit format
}

// Generic additional Version 2 TLV. For a non-Terminator TLV, length is
// 2..255 and the variable value occupies (length - 2) * 8 bits. Do not use
// this header for a Terminator. Unknown/deprecated types remain opaque.
// The containing PDU and registered TLV format impose their own bounds.
header lacp_extension_tlv {
    bit<8> type;
    bit<8> length;
    varbit<2024> value;
}

// Complete Version 2 views. Validate each type/length before choosing it.
// The four-octet Port Algorithm carries an OUI/CID and algorithm number.
// Digest computation and Conversation-sensitive Collection/Distribution
// require negotiated LAG information outside the parser.
header lacp_port_algorithm_tlv {
    bit<8> type; // 4
    bit<8> length; // 6
    bit<32> actor_port_algorithm;
}

header lacp_link_digest_tlv {
    bit<8> type; // 5
    bit<8> length; // 20
    bit<16> link_number;
    bit<128> actor_conv_link_digest;
}

header lacp_service_digest_tlv {
    bit<8> type; // 10
    bit<8> length; // 18
    bit<128> actor_conv_service_digest;
}

// Full Ethernet II header. The enclosing parser dispatches on EtherType
// 0x8809 and then Slow Protocol subtype 1. Destination selection can use
// the Slow Protocols group address or an administratively configured DA.
// Source/destination policy and FCS handling belong to the link handler.
typedef ethernet_header lacp_transport;

struct lacp_metadata_t {
    bit<32> parsed_bytes;
    bit<32> unparsed_bytes;
}

/**
 * Bounded common-information parser
 * The cursor starts at the Slow Protocol subtype. link_type is the
 * validated innermost EtherType. payload_length is the physically bounded
 * link payload, including any pad but excluding an FCS.
 *
 * headers contains lacp_prefix lacp, lacp_actor_info lacp_actor,
 * lacp_partner_info lacp_partner and lacp_collector_info lacp_collector.
 * metadata contains lacp_metadata_t lacp. Emit these headers in this order.
 * The complete lacp_t is an alternative Version 1 view, not another header
 * to emit alongside them.
 *
 * This example extracts the common 58 octets at fixed offsets for Version 1,
 * Version 2 and later compatible versions. It checks the link type, subtype,
 * nonzero version and available bytes. Following IEEE 802.1AX recordPDU
 * rules, it does not validate the first three TLV type/length fields or any
 * reserved fields.
 * Receive processing of Version 1 also ignores Terminator type/length.
 * Transmitters still populate all these fields with their standard values.
 *
 * Terminator, pad and Version 2 extensions stay unparsed and unchanged.
 * A message's total length is not used to validate the common information.
 * At least 58 physically available octets are needed to extract these
 * headers. The application validates and processes later-version TLVs,
 * skipping unknown/deprecated types and inappropriate lengths safely within
 * the link payload. Neither a fixed Version 1 pad nor a missing extension
 * is used here to discard otherwise available common information.
 *
 * Parsed state bits report the peer's advertised state. They do not enable
 * forwarding by themselves. Partner matching, Selection Logic, Receive and
 * Mux state machines, timeout handling and transmission require per-port
 * LACP state outside this pipeline.
 */
/*
parser lacp_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                   in bit<16> link_type, in bit<32> payload_length) {
    state start {
        hdr.lacp.setInvalid();
        hdr.lacp_actor.setInvalid();
        hdr.lacp_partner.setInvalid();
        hdr.lacp_collector.setInvalid();
        meta.lacp.parsed_bytes = 0;
        meta.lacp.unparsed_bytes = payload_length;
        verify(link_type == LACP_ETHER_TYPE, error.NoMatch);
        verify(payload_length >= 58, error.HeaderTooShort);
        pkt.extract(hdr.lacp);
        verify(hdr.lacp.subtype == LACP_SUBTYPE, error.NoMatch);
        verify(hdr.lacp.version >= LACP_VERSION_1, error.NoMatch);
        pkt.extract(hdr.lacp_actor);
        pkt.extract(hdr.lacp_partner);
        pkt.extract(hdr.lacp_collector);
        meta.lacp.parsed_bytes = 58;
        meta.lacp.unparsed_bytes = payload_length - 58;
        transition accept;
    }
}
*/

/**
 * Local application delivery (v1model)
 * A receiving physical port identifies its LACP protocol entity. The
 * table selects an application destination using that port and version,
 * with handler_port as the default. Parser errors drop the packet.
 * No aggregation membership or traffic distribution is changed here.
 */
/*
control lacp_control(inout headers hdr,
                     inout standard_metadata_t standard_metadata,
                     in bit<9> handler_port) {
    action send_lacp(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action send_default() {
        standard_metadata.egress_spec = handler_port;
    }

    table lacp_handlers {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.lacp.version: exact;
        }
        actions = {
            send_lacp;
            send_default;
        }
        default_action = send_default();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.lacp.isValid() || !hdr.lacp_actor.isValid()
            || !hdr.lacp_partner.isValid() || !hdr.lacp_collector.isValid()) {
            mark_to_drop(standard_metadata);
        } else {
            lacp_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_LACP_P4
