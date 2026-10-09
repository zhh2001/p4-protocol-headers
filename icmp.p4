/**
 * ICMPv4 and ICMPv6 headers (RFC 792, RFC 1191, RFC 4443 and RFC 4861)
 * ICMP 通用头、固定消息体和分流示例，兼容 RFC 4884 长度字段
 */
#ifndef P4_PROTOCOL_HEADERS_ICMP_P4
#define P4_PROTOCOL_HEADERS_ICMP_P4

#include "ipv4.p4"
#include "ipv6.p4"

const bit<8> ICMPV4_IP_PROTOCOL = 1;
const bit<8> ICMPV6_NEXT_HEADER = 58;
const bit<8> ICMPV6_RA_FLAG_MANAGED = 8w0x80;
const bit<8> ICMPV6_RA_FLAG_OTHER = 8w0x40;
const bit<32> ICMPV6_NA_FLAG_ROUTER = 32w0x80000000;
const bit<32> ICMPV6_NA_FLAG_SOLICITED = 32w0x40000000;
const bit<32> ICMPV6_NA_FLAG_OVERRIDE = 32w0x20000000;

// Selected types. Source Quench is deprecated by RFC 6633 and must not be
// generated. Its numeric value remains available for recognizing old traffic.
enum bit<8> icmpv4_type {
    ECHO_REPLY = 0,
    DEST_UNREACHABLE = 3,
    SOURCE_QUENCH = 4,
    REDIRECT = 5,
    ECHO_REQUEST = 8,
    TIME_EXCEEDED = 11,
    PARAMETER_PROBLEM = 12,
    TIMESTAMP_REQUEST = 13,
    TIMESTAMP_REPLY = 14
}

enum bit<8> icmpv4_unreach_code {
    NET_UNREACHABLE = 0,
    HOST_UNREACHABLE = 1,
    PROTO_UNREACHABLE = 2,
    PORT_UNREACHABLE = 3,
    FRAG_NEEDED = 4,
    SRC_ROUTE_FAILED = 5,
    DST_NET_UNKNOWN = 6,
    DST_HOST_UNKNOWN = 7,
    SRC_HOST_ISOLATED = 8,
    NET_ADMIN_PROHIBITED = 9,
    HOST_ADMIN_PROHIBITED = 10,
    NET_UNREACHABLE_FOR_TOS = 11,
    HOST_UNREACHABLE_FOR_TOS = 12,
    ADMIN_PROHIBITED = 13,
    HOST_PRECEDENCE_VIOLATION = 14,
    PRECEDENCE_CUTOFF = 15
}

enum bit<8> icmpv6_type {
    DEST_UNREACHABLE = 1,
    PACKET_TOO_BIG = 2,
    TIME_EXCEEDED = 3,
    PARAMETER_PROBLEM = 4,
    ECHO_REQUEST = 128,
    ECHO_REPLY = 129,
    ROUTER_SOLICITATION = 133,
    ROUTER_ADVERTISEMENT = 134,
    NEIGHBOR_SOLICITATION = 135,
    NEIGHBOR_ADVERTISEMENT = 136,
    REDIRECT = 137
}

// Common four-octet prefix. The selected message body follows this header.
// ICMPv4 covers the whole message in its checksum. ICMPv6 also includes the
// IPv6 pseudo-header, with Next Header 58 and the ICMPv6 upper-layer length.
header icmpv4_header {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
}

typedef icmpv4_header icmpv6_header;

// Echo body, four octets. Echo data follows without a fixed size.
header icmpv4_echo {
    bit<16> identifier;
    bit<16> sequence;
}

typedef icmpv4_echo icmpv6_echo;

// Error-message bodies below exclude the common header and quoted packet.
// RFC 4884 claims previously unused octets for original_datagram_length.
// For IPv4, that field counts padded quote octets in units of four. Zero
// preserves the legacy layout. Quote and extension boundaries are checked
// by the application, including RFC 4884 compatibility and padding rules.
header icmpv4_unreachable {
    bit<8> unused;
    bit<8> original_datagram_length;
    bit<16> next_hop_mtu; // RFC 1191, meaningful for Type 3 Code 4
}

header icmpv4_time_exceeded {
    bit<8> unused;
    bit<8> original_datagram_length;
    bit<16> unused_tail;
}

header icmpv4_parameter_problem {
    bit<8> pointer; // Octet offset in the quoted IPv4 header for Code 0
    bit<8> original_datagram_length;
    bit<16> unused;
}

header icmpv4_redirect {
    bit<32> gateway_address;
}

// Timestamp messages carry the four-octet identifier/sequence body first,
// then these 12 octets, for a total ICMP message prefix of 20 octets.
// Values normally count milliseconds since midnight UTC. A set high bit
// denotes a nonstandard time value. Time generation belongs to the application.
header icmpv4_timestamp {
    bit<32> originate;
    bit<32> receive;
    bit<32> transmit;
}

// RFC 4884's IPv6 quote length is the first body octet and counts units of
// eight octets. Both Destination Unreachable and Time Exceeded use this body.
header icmpv6_unreachable {
    bit<8> original_datagram_length;
    bit<24> unused;
}

typedef icmpv6_unreachable icmpv6_time_exceeded;

header icmpv6_packet_too_big {
    bit<32> mtu;
}

header icmpv6_parameter_problem {
    bit<32> pointer; // Octet offset into the invoking IPv6 packet
}

// RFC 4861 fixed bodies, excluding the common ICMPv6 header and ND options.
header icmpv6_router_solicitation {
    bit<32> reserved;
}

header icmpv6_router_advertisement {
    bit<8> current_hop_limit;
    bit<8> flags; // M/O and flags assigned by later extensions
    bit<16> router_lifetime; // Seconds
    bit<32> reachable_time; // Milliseconds
    bit<32> retrans_timer; // Milliseconds
}

// Only Neighbor Solicitation and Neighbor Advertisement share this body.
// flags is reserved in a Solicitation. Advertisement uses the high R/S/O
// bits. Router Solicitation, Advertisement and Redirect have other layouts.
header icmpv6_neighbor_discovery {
    bit<32> flags;
    bit<128> target_address;
}

typedef icmpv6_neighbor_discovery icmpv6_neighbor_solicitation;
typedef icmpv6_neighbor_discovery icmpv6_neighbor_advertisement;

header icmpv6_redirect {
    bit<32> reserved;
    bit<128> target_address;
    bit<128> destination_address;
}

// Compatibility names for the enclosing IP headers. IPv4 extraction must
// account for IHL-selected options. IPv6 needs its own header and extension
// chain before ICMPv6, rather than selecting Protocol 58 in an IPv4 header.
typedef ipv4_header icmp_transport;
typedef ipv6_header icmpv6_transport;

struct icmp_metadata_t {
    bit<4> ip_version;
    bit<32> parsed_bytes; // Common header and selected fixed message body
    bit<32> remainder_bytes; // Data, quote, ND options or extensions
}

/**
 * Fixed-message parser
 * The cursor starts at the ICMP type octet. ip_version comes from the outer
 * IP parser, which validates Protocol 1 for IPv4 or final Next Header 58 for
 * IPv6. message_length is the validated complete upper-layer message length,
 * excluding IP headers, IPv6 extension headers and outer padding. The caller
 * checks physical bounds, fragment completeness and the appropriate checksum.
 *
 * headers contains icmpv4_header icmp and icmpv4_echo icmp_echo, together
 * with the following type/instance pairs: icmpv4_unreachable icmpv4_unreachable,
 * icmpv4_time_exceeded icmpv4_time_exceeded, icmpv4_parameter_problem
 * icmpv4_parameter_problem, icmpv4_redirect icmpv4_redirect, icmpv4_timestamp
 * icmpv4_timestamp, icmpv6_unreachable icmpv6_unreachable,
 * icmpv6_packet_too_big icmpv6_packet_too_big, icmpv6_parameter_problem
 * icmpv6_parameter_problem, icmpv6_router_solicitation icmpv6_router_solicitation,
 * icmpv6_router_advertisement icmpv6_router_advertisement,
 * icmpv6_neighbor_discovery icmpv6_neighbor_discovery and icmpv6_redirect
 * icmpv6_redirect. metadata contains icmp_metadata_t icmp.
 *
 * Emit the common header and the valid fixed body in wire order. Timestamp
 * messages emit icmp_echo before icmpv4_timestamp. Remaining bytes stay
 * unparsed and unchanged. Unknown types retain their entire body this way.
 * The application validates type/code rules, reserved fields, quoted packets,
 * RFC 4884 lengths, extension structures and ND options. ND also needs the
 * RFC 4861 address and Hop Limit 255 checks. Reply generation, rate limits,
 * neighbor state and path-MTU updates belong to the enclosing implementation.
 */
/*
parser icmp_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                   in bit<4> ip_version, in bit<32> message_length) {
    state start {
        hdr.icmp.setInvalid();
        hdr.icmp_echo.setInvalid();
        hdr.icmpv4_unreachable.setInvalid();
        hdr.icmpv4_time_exceeded.setInvalid();
        hdr.icmpv4_parameter_problem.setInvalid();
        hdr.icmpv4_redirect.setInvalid();
        hdr.icmpv4_timestamp.setInvalid();
        hdr.icmpv6_unreachable.setInvalid();
        hdr.icmpv6_packet_too_big.setInvalid();
        hdr.icmpv6_parameter_problem.setInvalid();
        hdr.icmpv6_router_solicitation.setInvalid();
        hdr.icmpv6_router_advertisement.setInvalid();
        hdr.icmpv6_neighbor_discovery.setInvalid();
        hdr.icmpv6_redirect.setInvalid();
        meta.icmp.ip_version = ip_version;
        meta.icmp.parsed_bytes = 0;
        meta.icmp.remainder_bytes = 0;
        verify(ip_version == 4 || ip_version == 6, error.NoMatch);
        verify(message_length >= 4, error.HeaderTooShort);
        pkt.extract(hdr.icmp);
        meta.icmp.parsed_bytes = 4;
        meta.icmp.remainder_bytes = message_length - 4;
        transition select(ip_version, hdr.icmp.type) {
            (4, 0): parse_echo;
            (4, 8): parse_echo;
            (4, 3): parse_v4_unreachable;
            (4, 5): parse_v4_redirect;
            (4, 11): parse_v4_time_exceeded;
            (4, 12): parse_v4_parameter_problem;
            (4, 13): parse_timestamp;
            (4, 14): parse_timestamp;
            (6, 1): parse_v6_unreachable;
            (6, 3): parse_v6_unreachable;
            (6, 2): parse_v6_packet_too_big;
            (6, 4): parse_v6_parameter_problem;
            (6, 128): parse_echo;
            (6, 129): parse_echo;
            (6, 133): parse_router_solicitation;
            (6, 134): parse_router_advertisement;
            (6, 135): parse_neighbor;
            (6, 136): parse_neighbor;
            (6, 137): parse_v6_redirect;
            default: accept;
        }
    }

    state parse_echo {
        verify(meta.icmp.remainder_bytes >= 4, error.HeaderTooShort);
        pkt.extract(hdr.icmp_echo);
        meta.icmp.parsed_bytes = 8;
        meta.icmp.remainder_bytes = message_length - 8;
        transition accept;
    }

    state parse_v4_unreachable {
        verify(meta.icmp.remainder_bytes >= 4, error.HeaderTooShort);
        pkt.extract(hdr.icmpv4_unreachable);
        meta.icmp.parsed_bytes = 8;
        meta.icmp.remainder_bytes = message_length - 8;
        transition accept;
    }

    state parse_v4_redirect {
        verify(meta.icmp.remainder_bytes >= 4, error.HeaderTooShort);
        pkt.extract(hdr.icmpv4_redirect);
        meta.icmp.parsed_bytes = 8;
        meta.icmp.remainder_bytes = message_length - 8;
        transition accept;
    }

    state parse_v4_time_exceeded {
        verify(meta.icmp.remainder_bytes >= 4, error.HeaderTooShort);
        pkt.extract(hdr.icmpv4_time_exceeded);
        meta.icmp.parsed_bytes = 8;
        meta.icmp.remainder_bytes = message_length - 8;
        transition accept;
    }

    state parse_v4_parameter_problem {
        verify(meta.icmp.remainder_bytes >= 4, error.HeaderTooShort);
        pkt.extract(hdr.icmpv4_parameter_problem);
        meta.icmp.parsed_bytes = 8;
        meta.icmp.remainder_bytes = message_length - 8;
        transition accept;
    }

    state parse_timestamp {
        verify(meta.icmp.remainder_bytes >= 16, error.HeaderTooShort);
        pkt.extract(hdr.icmp_echo);
        pkt.extract(hdr.icmpv4_timestamp);
        meta.icmp.parsed_bytes = 20;
        meta.icmp.remainder_bytes = message_length - 20;
        transition accept;
    }

    state parse_v6_unreachable {
        verify(meta.icmp.remainder_bytes >= 4, error.HeaderTooShort);
        pkt.extract(hdr.icmpv6_unreachable);
        meta.icmp.parsed_bytes = 8;
        meta.icmp.remainder_bytes = message_length - 8;
        transition accept;
    }

    state parse_v6_packet_too_big {
        verify(meta.icmp.remainder_bytes >= 4, error.HeaderTooShort);
        pkt.extract(hdr.icmpv6_packet_too_big);
        meta.icmp.parsed_bytes = 8;
        meta.icmp.remainder_bytes = message_length - 8;
        transition accept;
    }

    state parse_v6_parameter_problem {
        verify(meta.icmp.remainder_bytes >= 4, error.HeaderTooShort);
        pkt.extract(hdr.icmpv6_parameter_problem);
        meta.icmp.parsed_bytes = 8;
        meta.icmp.remainder_bytes = message_length - 8;
        transition accept;
    }

    state parse_router_solicitation {
        verify(meta.icmp.remainder_bytes >= 4, error.HeaderTooShort);
        pkt.extract(hdr.icmpv6_router_solicitation);
        meta.icmp.parsed_bytes = 8;
        meta.icmp.remainder_bytes = message_length - 8;
        transition accept;
    }

    state parse_router_advertisement {
        verify(meta.icmp.remainder_bytes >= 12, error.HeaderTooShort);
        pkt.extract(hdr.icmpv6_router_advertisement);
        meta.icmp.parsed_bytes = 16;
        meta.icmp.remainder_bytes = message_length - 16;
        transition accept;
    }

    state parse_neighbor {
        verify(meta.icmp.remainder_bytes >= 20, error.HeaderTooShort);
        pkt.extract(hdr.icmpv6_neighbor_discovery);
        meta.icmp.parsed_bytes = 24;
        meta.icmp.remainder_bytes = message_length - 24;
        transition accept;
    }

    state parse_v6_redirect {
        verify(meta.icmp.remainder_bytes >= 36, error.HeaderTooShort);
        pkt.extract(hdr.icmpv6_redirect);
        meta.icmp.parsed_bytes = 40;
        meta.icmp.remainder_bytes = message_length - 40;
        transition accept;
    }
}
*/

/**
 * Application dispatch (v1model)
 * handler_port is the default application destination. The IP version in the
 * table key keeps equal type numbers in ICMPv4 and ICMPv6 distinct. Packets
 * stay intact. No echo reply, error message or neighbor response is generated.
 */
/*
control icmp_control(inout headers hdr, inout metadata meta,
                     inout standard_metadata_t standard_metadata,
                     in bit<9> handler_port) {
    action send_icmp(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action send_default() {
        standard_metadata.egress_spec = handler_port;
    }

    action drop_icmp() {
        mark_to_drop(standard_metadata);
    }

    table icmp_handlers {
        key = {
            meta.icmp.ip_version: exact;
            hdr.icmp.type: exact;
            hdr.icmp.code: exact;
        }
        actions = {
            send_icmp;
            send_default;
        }
        default_action = send_default();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.icmp.isValid()) {
            drop_icmp();
        } else {
            icmp_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_ICMP_P4
