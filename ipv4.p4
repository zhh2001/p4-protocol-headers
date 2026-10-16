#ifndef P4_PROTOCOL_HEADERS_IPV4_P4
#define P4_PROTOCOL_HEADERS_IPV4_P4

/**
 * IPv4 header definitions and basic unicast forwarding (RFC 791, RFC 1812)
 * IPv4 报头定义及基础单播转发示例
 */

/* IP Protocol Numbers */
enum bit<8> ip_protocol {
    ICMP = 1,    // Internet Control Message Protocol
    TCP = 6,     // Transmission Control Protocol
    UDP = 17,    // User Datagram Protocol
    GRE = 47,    // Generic Routing Encapsulation
    ESP = 50,    // Encapsulating Security Payload
    AH = 51      // Authentication Header
};

/* IP Precedence Levels */
enum bit<8> ip_precedence {
    ROUTINE = 0,    // Routine precedence
    PRIORITY = 1,   // Priority
    IMMEDIATE = 2,  // Immediate
    FLASH = 3,      // Flash
    OVERRIDE = 4,   // Flash Override
    CRITIC = 5,     // Critical
    INTERNET = 6,   // Internetwork Control
    NETWORK = 7     // Network Control
};

/**
 * IPv4 Header (20-60 bytes)
 * Standard IPv4 header with options
 */
header ipv4_header {
    bit<4>  version;          // IP version (4)
    bit<4>  ihl;              // Header length in 32-bit words (5-15)
    bit<6>  dscp;             // Differentiated Services Code Point
    bit<2>  ecn;              // Explicit Congestion Notification
    bit<16> total_length;     // Total packet length (bytes)
    bit<16> identification;   // Packet identification
    bit<1>  reserved;         // Reserved flag
    bit<1>  df;               // Don't Fragment flag
    bit<1>  mf;               // More Fragments flag
    bit<13> fragment_offset;  // Fragment offset in 8-byte units
    bit<8>  ttl;              // Time To Live
    bit<8>  protocol;         // Upper layer protocol (ip_protocol)
    bit<16> header_checksum;  // Header checksum
    bit<32> src_addr;         // Source IP address
    bit<32> dst_addr;         // Destination IP address
    varbit<320> options;      // Options and padding (0-40 bytes)
};

// Local forwarding status for the example.
enum bit<8> ipv4_slow_path_reason {
    NONE = 0,
    OPTIONS = 1,
    TTL_EXPIRED = 2,
    NO_ROUTE = 3,
    MTU_EXCEEDED = 4
}

struct ipv4_metadata_t {
    bit<32> header_bytes;
    bit<32> payload_bytes;
    bit<32> trailing_bytes;
    bool forwarded;
    ipv4_slow_path_reason slow_path_reason;
}

/**
 * Bounded IPv4 parsing. The cursor points to the IPv4 header and ipv4_bytes
 * is the physically available link payload length, including any padding
 * but excluding an FCS. headers contains ipv4_header ipv4_header, and
 * metadata contains ipv4_metadata_t ipv4. Pass those two members to the
 * parser's out parameters.
 *
 * The parser checks Version, IHL and Total Length, retaining all options.
 * It leaves the payload and link padding unchanged. All fragments follow
 * this same path, without attempting to extract a transport header.
 * IPv4 有界解析，保留选项、分片负载和链路填充。
 */
/*
parser ipv4_parser(packet_in pkt, out ipv4_header ip, out ipv4_metadata_t meta,
                   in bit<32> ipv4_bytes) {
    state start {
        bit<32> prefix;
        bit<32> total_bytes;
        ip.setInvalid();
        meta.header_bytes = 0;
        meta.payload_bytes = 0;
        meta.trailing_bytes = 0;
        meta.forwarded = false;
        meta.slow_path_reason = ipv4_slow_path_reason.NONE;
        verify(ipv4_bytes >= 20, error.PacketTooShort);
        prefix = pkt.lookahead<bit<32>>();
        verify(prefix[31:28] == 4 && prefix[27:24] >= 5, error.NoMatch);
        meta.header_bytes = (bit<32>)prefix[27:24] * 4;
        total_bytes = (bit<32>)prefix[15:0];
        verify(total_bytes >= meta.header_bytes, error.HeaderTooShort);
        verify(total_bytes <= ipv4_bytes, error.PacketTooShort);
        pkt.extract(ip, (meta.header_bytes - 20) * 8);
        meta.payload_bytes = total_bytes - meta.header_bytes;
        meta.trailing_bytes = ipv4_bytes - total_bytes;
        transition accept;
    }
}
*/

/**
 * Basic IPv4 unicast forwarding (P4_16, v1model).
 * Use ipv4_verify_checksum in VerifyChecksum, ipv4_control in Ingress,
 * and ipv4_compute_checksum in ComputeChecksum. Emit ipv4_header before
 * the unchanged payload. Include ethernet.p4 separately for Ethernet links.
 *
 * The enclosing pipeline selects transit unicast traffic and handles local
 * delivery and link-layer rewriting. It supplies a slow-path port and
 * exports slow_path_reason metadata to its handler. Each route gives an
 * egress port and IP MTU in octets. Parser and checksum errors are dropped.
 * Options, expired TTL, route misses and MTU exceptions reach the slow path
 * with the original IP header intact.
 * The handler processes options, fragmentation and ICMP using route state.
 * Only packets forwarded here have TTL decremented and their header
 * checksum updated.
 * 基础单播路由，选项、MTU 分片和 ICMP 由上层处理。
 */
/*
control ipv4_verify_checksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(hdr.ipv4_header.isValid(),
            { hdr.ipv4_header.version, hdr.ipv4_header.ihl,
              hdr.ipv4_header.dscp, hdr.ipv4_header.ecn,
              hdr.ipv4_header.total_length, hdr.ipv4_header.identification,
              hdr.ipv4_header.reserved, hdr.ipv4_header.df,
              hdr.ipv4_header.mf, hdr.ipv4_header.fragment_offset,
              hdr.ipv4_header.ttl, hdr.ipv4_header.protocol,
              hdr.ipv4_header.src_addr, hdr.ipv4_header.dst_addr,
              hdr.ipv4_header.options },
            hdr.ipv4_header.header_checksum, HashAlgorithm.csum16);
    }
}

control ipv4_control(inout headers hdr, inout metadata meta,
                     inout standard_metadata_t standard_metadata,
                     in bit<9> slow_path_port) {
    action punt_ipv4(ipv4_slow_path_reason reason) {
        meta.ipv4.slow_path_reason = reason;
        standard_metadata.egress_spec = slow_path_port;
    }

    action drop_ipv4() {
        mark_to_drop(standard_metadata);
    }

    action route_ipv4(bit<9> port, bit<16> mtu) {
        if (hdr.ipv4_header.total_length > mtu) {
            punt_ipv4(ipv4_slow_path_reason.MTU_EXCEEDED);
        } else {
            hdr.ipv4_header.ttl = hdr.ipv4_header.ttl - 1;
            meta.ipv4.forwarded = true;
            standard_metadata.egress_spec = port;
        }
    }

    table ipv4_routes {
        key = {
            hdr.ipv4_header.dst_addr: lpm;
        }
        actions = {
            route_ipv4;
            punt_ipv4;
            drop_ipv4;
        }
        default_action = punt_ipv4(ipv4_slow_path_reason.NO_ROUTE);
    }

    apply {
        meta.ipv4.forwarded = false;
        meta.ipv4.slow_path_reason = ipv4_slow_path_reason.NONE;
        if (standard_metadata.parser_error != error.NoError
            || !hdr.ipv4_header.isValid()
            || standard_metadata.checksum_error == 1) {
            drop_ipv4();
        } else if (hdr.ipv4_header.ttl <= 1) {
            punt_ipv4(ipv4_slow_path_reason.TTL_EXPIRED);
        } else if (hdr.ipv4_header.ihl > 5) {
            punt_ipv4(ipv4_slow_path_reason.OPTIONS);
        } else {
            ipv4_routes.apply();
        }
    }
}

control ipv4_compute_checksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(hdr.ipv4_header.isValid() && meta.ipv4.forwarded,
            { hdr.ipv4_header.version, hdr.ipv4_header.ihl,
              hdr.ipv4_header.dscp, hdr.ipv4_header.ecn,
              hdr.ipv4_header.total_length, hdr.ipv4_header.identification,
              hdr.ipv4_header.reserved, hdr.ipv4_header.df,
              hdr.ipv4_header.mf, hdr.ipv4_header.fragment_offset,
              hdr.ipv4_header.ttl, hdr.ipv4_header.protocol,
              hdr.ipv4_header.src_addr, hdr.ipv4_header.dst_addr,
              hdr.ipv4_header.options },
            hdr.ipv4_header.header_checksum, HashAlgorithm.csum16);
    }
}
*/

#endif
