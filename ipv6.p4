#ifndef P4_PROTOCOL_HEADERS_IPV6_P4
#define P4_PROTOCOL_HEADERS_IPV6_P4

/**
 * IPv6 header definitions and basic unicast forwarding (RFC 8200)
 * IPv6 报头定义及基础单播转发示例
 */

/* IPv6 Protocol Numbers */
enum bit<8> ipv6_next_header {
    HOP_BY_HOP = 0,   // Hop-by-Hop Options
    ICMPv6 = 58,      // ICMP for IPv6
    TCP = 6,          // Same value as IPv4
    UDP = 17,         // Same value as IPv4
    ROUTING = 43,     // Routing Header
    FRAGMENT = 44,    // Fragmentation Header
    ESP = 50,         // Encapsulating Security Payload
    AH = 51,          // Authentication Header
    NONE = 59,        // No Next Header
    DST_OPTIONS = 60  // Destination Options
};

// Class Selector DSCP values (RFC 2474), carried in Traffic Class bits 7:2.
enum bit<6> ipv6_dscp {
    CS0 = 0,
    CS1 = 8,
    CS2 = 16,
    CS3 = 24,
    CS4 = 32,
    CS5 = 40,
    CS6 = 48,
    CS7 = 56
}

// ECN values (RFC 3168), carried in Traffic Class bits 1:0.
enum bit<2> ipv6_ecn {
    NOT_ECT = 0,
    ECT_1 = 1,
    ECT_0 = 2,
    CE = 3
}

/**
 * IPv6 Base Header (40 bytes)
 * Fixed-length mandatory header
 */
header ipv6_header {
    bit<4>   version;         // IP version (6)
    bit<8>   traffic_class;   // DSCP in bits 7:2, ECN in bits 1:0
    bit<20>  flow_label;      // Flow label
    bit<16>  payload_length;  // Extension headers + data, zero for jumbograms
    bit<8>   next_header;     // Next header type (ipv6_next_header)
    bit<8>   hop_limit;       // Hop limit (replaces TTL)
    bit<128> src_addr;        // Source IPv6 address
    bit<128> dst_addr;        // Destination IPv6 address
};

/**
 * IPv6 Hop-by-Hop Options Header (Variable length)
 * Optional extension header
 */
header ipv6_hop_options {
    bit<8> next_header;      // Next header type
    bit<8> hdr_ext_len;      // Header length in 8-byte units, excluding the first 8 bytes
    varbit<16368> options;   // Options and padding (6-2046 bytes)
};

/**
 * IPv6 Fragment Header (8 bytes)
 * Fragmentation/reassembly support
 */
header ipv6_fragment {
    bit<8>  next_header;     // Next header type
    bit<8>  reserved;        // Reserved field
    bit<13> frag_offset;    // Fragment offset (in 8-byte units)
    bit<2>  reserved2;       // Reserved
    bit<1>  m_flag;          // More fragments flag
    bit<32> identification;  // Packet identifier
};

// Local forwarding status for the example.
enum bit<8> ipv6_slow_path_reason {
    NONE = 0,
    JUMBO_PAYLOAD = 1,
    HOP_BY_HOP = 2,
    HOP_LIMIT_EXPIRED = 3,
    NO_ROUTE = 4,
    MTU_EXCEEDED = 5
}

struct ipv6_metadata_t {
    bit<32> packet_bytes;
    bit<32> payload_bytes;
    bit<32> trailing_bytes;
    bool length_known;
    bool forwarded;
    ipv6_slow_path_reason slow_path_reason;
}

/**
 * Bounded IPv6 base-header parsing. The cursor points to the IPv6 header,
 * and ipv6_bytes is the physically available link payload length, including
 * padding but excluding an FCS. Pass hdr.ipv6_header and meta.ipv6 to the
 * out parameters, using ipv6_header and ipv6_metadata_t for those members.
 *
 * Normal length metadata counts extension headers as payload. A zero
 * Payload Length followed by Hop-by-Hop needs Jumbo Payload processing
 * (RFC 2675), so length_known stays false and the length fields stay zero.
 * All extension headers, transport headers, fragment data and padding
 * remain unparsed and unchanged after the base header.
 * 固定头有界解析，扩展链、分片负载和链路填充保持原样。
 */
/*
parser ipv6_parser(packet_in pkt, out ipv6_header ip, out ipv6_metadata_t meta,
                   in bit<32> ipv6_bytes) {
    state start {
        ip.setInvalid();
        meta.packet_bytes = 0;
        meta.payload_bytes = 0;
        meta.trailing_bytes = 0;
        meta.length_known = false;
        meta.forwarded = false;
        meta.slow_path_reason = ipv6_slow_path_reason.NONE;
        verify(ipv6_bytes >= 40, error.PacketTooShort);
        pkt.extract(ip);
        verify(ip.version == 6, error.NoMatch);
        transition select(ip.payload_length, ip.next_header) {
            (0, ipv6_next_header.HOP_BY_HOP): accept;
            default: check_payload_length;
        }
    }

    state check_payload_length {
        meta.payload_bytes = (bit<32>)ip.payload_length;
        meta.packet_bytes = 40 + meta.payload_bytes;
        verify(meta.packet_bytes <= ipv6_bytes, error.PacketTooShort);
        meta.trailing_bytes = ipv6_bytes - meta.packet_bytes;
        meta.length_known = true;
        transition accept;
    }
}
*/

/**
 * Basic IPv6 unicast forwarding (P4_16, v1model).
 * headers contains ipv6_header ipv6_header, and metadata contains
 * ipv6_metadata_t ipv6. The enclosing pipeline selects transit unicast
 * traffic, handles local delivery and link-layer rewriting, and supplies a
 * slow-path port with slow_path_reason exported to its handler.
 *
 * Routes provide an egress port and IPv6 link MTU in octets, at least 1280.
 * Ordinary transit extension chains and fragments stay intact. Hop-by-Hop
 * and Jumbo Payload processing goes to the handler, as do expired Hop Limit,
 * route misses and MTU exceptions requiring ICMPv6 handling. These packets
 * retain their original IPv6 header. Routers do not fragment IPv6 packets.
 * Only successful forwarding decrements Hop Limit. Traffic Class and Flow
 * Label are preserved. Emit ipv6_header before the untouched payload.
 * 基础单播路由，逐跳选项、Jumbo Payload 和 ICMPv6 由上层处理。
 */
/*
control ipv6_control(inout headers hdr, inout metadata meta,
                     inout standard_metadata_t standard_metadata,
                     in bit<9> slow_path_port) {
    action punt_ipv6(ipv6_slow_path_reason reason) {
        meta.ipv6.slow_path_reason = reason;
        standard_metadata.egress_spec = slow_path_port;
    }

    action drop_ipv6() {
        mark_to_drop(standard_metadata);
    }

    action route_ipv6(bit<9> port, bit<32> mtu) {
        if (meta.ipv6.packet_bytes > mtu) {
            punt_ipv6(ipv6_slow_path_reason.MTU_EXCEEDED);
        } else {
            hdr.ipv6_header.hop_limit = hdr.ipv6_header.hop_limit - 1;
            meta.ipv6.forwarded = true;
            standard_metadata.egress_spec = port;
        }
    }

    table ipv6_routes {
        key = {
            hdr.ipv6_header.dst_addr: lpm;
        }
        actions = {
            route_ipv6;
            punt_ipv6;
            drop_ipv6;
        }
        default_action = punt_ipv6(ipv6_slow_path_reason.NO_ROUTE);
    }

    apply {
        meta.ipv6.forwarded = false;
        meta.ipv6.slow_path_reason = ipv6_slow_path_reason.NONE;
        if (standard_metadata.parser_error != error.NoError
            || !hdr.ipv6_header.isValid()) {
            drop_ipv6();
        } else if (!meta.ipv6.length_known) {
            punt_ipv6(ipv6_slow_path_reason.JUMBO_PAYLOAD);
        } else if (hdr.ipv6_header.hop_limit <= 1) {
            punt_ipv6(ipv6_slow_path_reason.HOP_LIMIT_EXPIRED);
        } else if (hdr.ipv6_header.next_header == ipv6_next_header.HOP_BY_HOP) {
            punt_ipv6(ipv6_slow_path_reason.HOP_BY_HOP);
        } else {
            ipv6_routes.apply();
        }
    }
}
*/

#endif
