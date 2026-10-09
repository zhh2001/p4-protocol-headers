/**
 * DHCPv6 headers (RFC 9915 and RFC 6355)
 * DHCPv6 普通消息、中继报头和顶层选项解析示例
 */
#ifndef P4_PROTOCOL_HEADERS_DHCPV6_P4
#define P4_PROTOCOL_HEADERS_DHCPV6_P4

const bit<16> DHCPV6_CLIENT_PORT = 546;
const bit<16> DHCPV6_SERVER_PORT = 547;
const bit<128> DHCPV6_ALL_RELAY_AGENTS_AND_SERVERS =
    128w0xff020000000000000000000000010002;
const bit<128> DHCPV6_ALL_SERVERS =
    128w0xff050000000000000000000000010003;
const bit<8> DHCPV6_HOP_COUNT_LIMIT = 8;
const bit<16> DHCPV6_DUID_MIN_LENGTH = 3;
const bit<16> DHCPV6_DUID_MAX_LENGTH = 130;

// Core RFC 9915 message types. Other registered types need their own
// message-format and transport rules in the enclosing implementation.
enum bit<8> dhcpv6_type {
    SOLICIT = 1,
    ADVERTISE = 2,
    REQUEST = 3,
    CONFIRM = 4,
    RENEW = 5,
    REBIND = 6,
    REPLY = 7,
    RELEASE = 8,
    DECLINE = 9,
    RECONFIGURE = 10,
    INFORMATION_REQUEST = 11,
    RELAY_FORW = 12,
    RELAY_REPL = 13
}

// Selected current option codes. IA_TA (4) and Unicast (12) are obsolete
// in RFC 9915. Unknown and obsolete options remain opaque generic records.
enum bit<16> dhcpv6_option_code {
    CLIENTID = 1,
    SERVERID = 2,
    IA_NA = 3,
    IAADDR = 5,
    ORO = 6,
    PREFERENCE = 7,
    ELAPSED_TIME = 8,
    RELAY_MSG = 9,
    AUTH = 11,
    STATUS_CODE = 13,
    RAPID_COMMIT = 14,
    USER_CLASS = 15,
    VENDOR_CLASS = 16,
    VENDOR_OPTS = 17,
    INTERFACE_ID = 18,
    RECONF_MSG = 19,
    RECONF_ACCEPT = 20,
    IA_PD = 25,
    IAPREFIX = 26,
    INFORMATION_REFRESH_TIME = 32,
    SOL_MAX_RT = 82,
    INF_MAX_RT = 83
}

// Ordinary client/server message header, four octets. Options follow it.
header dhcpv6 {
    bit<8> msg_type;
    bit<24> transaction_id;
}

// Relay-forward and Relay-reply share this 34-octet header. They have no
// transaction ID. The Relay Message option contains the inner message.
header dhcpv6_relay {
    bit<8> msg_type;
    bit<8> hop_count;
    bit<128> link_address;
    bit<128> peer_address;
}

// Complete option. option_len counts data octets, excluding this four-octet
// prefix. The varbit limit covers the full 16-bit length range.
// There are no PAD/END markers or alignment bytes between DHCPv6 options.
header dhcpv6_option {
    bit<16> option_code;
    bit<16> option_len;
    varbit<524280> data;
}

enum bit<16> dhcpv6_duid_type {
    DUID_LLT = 1,
    DUID_EN = 2,
    DUID_LL = 3,
    DUID_UUID = 4
}

// DUID value views, excluding the containing option's code and length.
// A DUID has a two-octet type and 1..128 identifier octets. Client and server
// identifiers carry this entire DUID as their option value. Treat that value
// as an opaque key and compare it for equality, including unknown DUID types.
header dhcpv6_duid {
    bit<16> type;
    varbit<1024> identifier;
}

// Known formats for applications that generate or inspect DUIDs. Check the
// containing length and type before extracting. The top-level parser below
// leaves DUIDs opaque and does not derive forwarding addresses from them.
header dhcpv6_duid_llt {
    bit<16> type; // 1
    bit<16> hardware_type;
    bit<32> time; // Seconds since 2000-01-01 UTC, modulo 2^32
    varbit<976> link_layer_address; // DUID length minus 8 octets
}

header dhcpv6_duid_en {
    bit<16> type; // 2
    bit<32> enterprise_number;
    varbit<992> identifier; // DUID length minus 6 octets
}

header dhcpv6_duid_ll {
    bit<16> type; // 3
    bit<16> hardware_type;
    varbit<1008> link_layer_address; // DUID length minus 4 octets
}

header dhcpv6_duid_uuid {
    bit<16> type; // 4
    bit<128> uuid; // RFC 6355 network byte order, complete DUID length 18
}

struct dhcpv6_metadata_t {
    bit<8> message_type;
    bit<1> is_relay;
    bit<1> is_opaque; // Message type outside the base 1..13 formats
    bit<16> option_count;
    bit<32> option_bytes;
}

/**
 * Base message and top-level option parser
 * The cursor starts at msg-type. payload_length is the validated UDP payload
 * length, excluding UDP and outer padding. The enclosing parser validates
 * IPv6/UDP bounds, checksums, fragment completeness and transport selection.
 * Client/server exchanges use UDP 546/547. Relay/server traffic normally uses
 * 547 at both ends. Additional transports and relay source-port extensions
 * are handled by the enclosing implementation.
 *
 * headers contains dhcpv6 dhcpv6, dhcpv6_relay dhcpv6_relay and
 * dhcpv6_option[128] dhcpv6_options. The stack must be empty on entry.
 * metadata contains dhcpv6_metadata_t dhcpv6. The 128-option storage limit
 * is an example capacity, not a DHCPv6 limit. Emit the ordinary or relay
 * header followed by this stack. Outer padding remains unparsed and unchanged.
 *
 * Each option is bounded by payload_length and retained in wire order.
 * Zero-length values are structurally valid. There are no PAD/END markers.
 * Repeated options remain separate and are not concatenated as in DHCPv4.
 * Nested IA options, Relay Message contents, DUIDs and authentication values
 * stay opaque. Message types outside 1..13 leave the entire message unparsed
 * for the default application path, without assuming a transaction ID layout.
 *
 * The application validates required and singleton options, value lengths,
 * DUIDs, lifetimes and nested messages. It applies relay hop-count limits
 * according to its role. This parser does not relay messages, allocate
 * addresses, maintain leases or generate replies.
 */
/*
parser dhcpv6_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                     in bit<32> payload_length) {
    bit<32> remaining;
    bit<32> option_prefix;
    bit<16> value_bytes;
    bit<32> value_bits;

    state start {
        hdr.dhcpv6.setInvalid();
        hdr.dhcpv6_relay.setInvalid();
        meta.dhcpv6.message_type = 0;
        meta.dhcpv6.is_relay = 0;
        meta.dhcpv6.is_opaque = 0;
        meta.dhcpv6.option_count = 0;
        meta.dhcpv6.option_bytes = 0;
        verify(payload_length >= 1, error.HeaderTooShort);
        meta.dhcpv6.message_type = pkt.lookahead<bit<8>>();
        transition select(meta.dhcpv6.message_type) {
            1 .. 11: parse_message;
            12: parse_relay;
            13: parse_relay;
            default: parse_opaque;
        }
    }

    state parse_message {
        verify(payload_length >= 4, error.HeaderTooShort);
        pkt.extract(hdr.dhcpv6);
        remaining = payload_length - 4;
        transition check_options;
    }

    state parse_relay {
        verify(payload_length >= 34, error.HeaderTooShort);
        pkt.extract(hdr.dhcpv6_relay);
        meta.dhcpv6.is_relay = 1;
        remaining = payload_length - 34;
        transition check_options;
    }

    state parse_opaque {
        meta.dhcpv6.is_opaque = 1;
        transition accept;
    }

    state check_options {
        transition select(remaining) {
            0: accept;
            default: parse_option;
        }
    }

    state parse_option {
        verify(remaining >= 4, error.HeaderTooShort);
        verify(meta.dhcpv6.option_count < 128, error.StackOutOfBounds);
        option_prefix = pkt.lookahead<bit<32>>();
        value_bytes = option_prefix[15:0];
        verify((bit<32>) value_bytes <= remaining - 4, error.HeaderTooShort);
        value_bits = (bit<32>) value_bytes * 8;
        pkt.extract(hdr.dhcpv6_options.next, value_bits);
        meta.dhcpv6.option_count = meta.dhcpv6.option_count + 1;
        meta.dhcpv6.option_bytes = meta.dhcpv6.option_bytes + 4
                                   + (bit<32>) value_bytes;
        remaining = remaining - 4 - (bit<32>) value_bytes;
        transition check_options;
    }
}
*/

/**
 * DHCPv6 application dispatch (v1model)
 * handler_port is the default application destination. The table selects
 * a handler by the outer message type. Packets and option values stay intact.
 */
/*
control dhcpv6_control(inout headers hdr, inout metadata meta,
                       inout standard_metadata_t standard_metadata,
                       in bit<9> handler_port) {
    action send_dhcpv6(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action send_default() {
        standard_metadata.egress_spec = handler_port;
    }

    action drop_dhcpv6() {
        mark_to_drop(standard_metadata);
    }

    table dhcpv6_handlers {
        key = {
            meta.dhcpv6.message_type: exact;
        }
        actions = {
            send_dhcpv6;
            send_default;
        }
        default_action = send_default();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError) {
            drop_dhcpv6();
        } else if (meta.dhcpv6.is_opaque == 1) {
            send_default();
        } else if (hdr.dhcpv6.isValid() || hdr.dhcpv6_relay.isValid()) {
            dhcpv6_handlers.apply();
        } else {
            drop_dhcpv6();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_DHCPV6_P4
