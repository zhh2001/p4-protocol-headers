/**
 * ICMP Header Definition in P4
 * Internet Control Message Protocol for network diagnostics and error reporting
 * 
 * Note: ICMP is used by network devices to send error messages and operational information
 *       (IP protocol number 1 for IPv4, 58 for IPv6 ICMPv6)
 */

/* ICMPv4 Message Types */
enum bit<8> icmpv4_type {
    ECHO_REPLY        = 0,        // Echo reply (ping response)
    DEST_UNREACHABLE  = 3,        // Destination unreachable
    SOURCE_QUENCH     = 4,        // Source quench (congestion control)
    REDIRECT          = 5,        // Redirect message
    ECHO_REQUEST      = 8,        // Echo request (ping)
    TIME_EXCEEDED     = 11,       // Time exceeded
    PARAMETER_PROBLEM = 12,       // Parameter problem
    TIMESTAMP_REQUEST = 13,       // Timestamp request
    TIMESTAMP_REPLY   = 14        // Timestamp reply
};

/* ICMPv4 Destination Unreachable Codes */
enum bit<8> icmpv4_unreach_code {
    NET_UNREACHABLE       = 0,          // Network unreachable
    HOST_UNREACHABLE      = 1,          // Host unreachable
    PROTO_UNREACHABLE     = 2,          // Protocol unreachable
    PORT_UNREACHABLE      = 3,          // Port unreachable
    FRAG_NEEDED           = 4,          // Fragmentation needed
    SRC_ROUTE_FAILED      = 5,          // Source route failed
    DST_NET_UNKNOWN       = 6,          // Destination network unknown
    DST_HOST_UNKNOWN      = 7,          // Destination host unknown
    SRC_HOST_ISOLATED     = 8,          // Source host isolated
    NET_ADMIN_PROHIBITED  = 9,          // Network administratively prohibited
    HOST_ADMIN_PROHIBITED = 10          // Host administratively prohibited
};

/**
 * ICMPv4 Header (8+ bytes)
 * Basic ICMP message header
 */
header icmpv4_header {
    bit<8>  type;             // ICMP message type (icmpv4_type)
    bit<8>  code;             // Type sub-code (icmpv4_unreach_code etc.)
    bit<16> checksum;         // ICMP checksum
    bit<16> identifier;       // Echo/timestamp identifier
    bit<16> sequence;         // Echo/timestamp sequence number
};

/**
 * ICMPv4 Destination Unreachable (8+ bytes)
 * Extended header for unreachable messages
 */
header icmpv4_unreachable {
    bit<16> unused;             // Must be 0
    bit<16> next_hop_mtu;       // Next hop MTU (for fragmentation needed)
    varbit<1024> original_header;  // Original IP header + 8 bytes of payload
};

/**
 * ICMPv4 Time Exceeded (8+ bytes)
 * Extended header for time exceeded messages
 */
header icmpv4_time_exceeded {
    bit<32> unused;             // Must be 0
    varbit<1024> original_header;  // Original IP header + 8 bytes of payload
};

/**
 * ICMPv4 Redirect (8+ bytes)
 * Extended header for redirect messages
 */
header icmpv4_redirect {
    bit<32> gateway_address;    // Address of better gateway
    varbit<1024> original_header;  // Original IP header + 8 bytes of payload
};

/**
 * ICMPv4 Timestamp (12 bytes)
 * Header for timestamp messages
 */
header icmpv4_timestamp {
    bit<32> originate;       // Originate timestamp
    bit<32> receive;         // Receive timestamp
    bit<32> transmit;        // Transmit timestamp
};

/**
 * ICMPv6 Header (8+ bytes)
 * Basic ICMPv6 message header
 */
header icmpv6_header {
    bit<8>  type;             // ICMPv6 message type
    bit<8>  code;             // Type sub-code
    bit<16> checksum;         // ICMPv6 checksum
};

/**
 * ICMPv6 Neighbor Discovery (24+ bytes)
 * Used for IPv6 neighbor discovery
 */
header icmpv6_neighbor_discovery {
    bit<32>  flags;            // Neighbor discovery flags
    bit<128> target_address;   // Target IPv6 address
    varbit<1024> options;        // ND options (variable length)
};

/**
 * ICMP Transport Header (IP)
 * Outer IP header for ICMP messages
 */
header icmp_transport {
    bit<8>  version_ihl;        // Version (4) + IHL (5 for 20 byte header)
    bit<8>  dscp_ecn;           // DSCP (6 bits) + ECN (2 bits)
    bit<16> total_length;       // Total packet length
    bit<16> identification;     // IP identification
    bit<16> flags_frag_offset;  // Flags + Fragment offset
    bit<8>  ttl;                // Time to live
    bit<8>  protocol;           // Protocol (1 for ICMP, 58 for ICMPv6)
    bit<16> header_checksum;    // IP header checksum
    bit<32> src_ip;             // Source IP address
    bit<32> dst_ip;             // Destination IP address
};

/**
 * P4 Parser Logic for ICMP
 */
/*
parser icmp_parser(packet_in pkt, out headers hdr) {
    state start {
        pkt.extract(hdr.icmp_transport);
        transition select(hdr.icmp_transport.protocol) {
            1: parse_icmpv4;
            58: parse_icmpv6;
            default: accept;
        }
    }
    
    state parse_icmpv4 {
        pkt.extract(hdr.icmpv4_header);
        transition select(hdr.icmpv4_header.type) {
            DEST_UNREACHABLE: parse_icmpv4_unreach;
            TIME_EXCEEDED: parse_icmpv4_time_exceed;
            REDIRECT: parse_icmpv4_redirect;
            TIMESTAMP_REQUEST, TIMESTAMP_REPLY: parse_icmpv4_timestamp;
            default: accept;
        }
    }
    
    state parse_icmpv6 {
        pkt.extract(hdr.icmpv6_header);
        transition select(hdr.icmpv6_header.type) {
            133, 134, 135, 136: parse_icmpv6_nd;  // Neighbor discovery messages
            default: accept;
        }
    }
    
    // Additional parse states for specific ICMP types...
}
*/

/**
 * P4 Match-Action Pipeline for ICMP
 */
/*
control icmp_control(inout headers hdr) {
    action generate_echo_reply() {
        // Generate ICMP echo reply from request
        hdr.icmpv4_header.type = ECHO_REPLY;
        hdr.icmp_transport.src_ip = hdr.icmp_transport.dst_ip;
        hdr.icmp_transport.dst_ip = hdr.icmp_transport.src_ip;
        hdr.icmpv4_header.checksum = recalculate_checksum();
    }
    
    action send_time_exceeded() {
        // Generate ICMP time exceeded message
        hdr.icmpv4_header.type = TIME_EXCEEDED;
        hdr.icmpv4_header.code = 0;  // TTL expired in transit
        hdr.icmp_transport.src_ip = device_ip;
        hdr.icmpv4_header.checksum = recalculate_checksum();
    }
    
    action send_dest_unreachable(code, mtu) {
        // Generate destination unreachable message
        hdr.icmpv4_header.type = DEST_UNREACHABLE;
        hdr.icmpv4_header.code = code;
        if (code == FRAG_NEEDED) {
            hdr.icmpv4_unreachable.next_hop_mtu = mtu;
        }
        hdr.icmp_transport.src_ip = device_ip;
        hdr.icmpv4_header.checksum = recalculate_checksum();
    }
    
    table icmp_processing {
        key = {
            hdr.icmp_transport.protocol: exact;
            hdr.icmpv4_header.type: exact;
        }
        actions = {
            generate_echo_reply;
            send_time_exceeded;
            send_dest_unreachable;
            NoAction;
        }
        default_action = NoAction;
    }
    
    apply {
        icmp_processing.apply();
    }
}
*/
