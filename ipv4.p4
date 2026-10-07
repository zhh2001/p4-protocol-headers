#ifndef P4_PROTOCOL_HEADERS_IPV4_P4
#define P4_PROTOCOL_HEADERS_IPV4_P4

/**
 * IPv4 Header Definition in P4
 * Internet Protocol version 4 header for packet routing
 * 
 * Note: IPv4 is the fundamental protocol for internetworking that provides 
 *       logical addressing and packet fragmentation capabilities
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

/**
 * P4 Parser Logic for IPv4
 * The packet cursor must point to the start of the IPv4 header.
 * Include ethernet.p4 separately when parsing Ethernet frames.
 */
/*
parser ipv4_parser(packet_in pkt, inout headers hdr) {
    state start {
        bit<8> version_ihl;
        version_ihl = pkt.lookahead<bit<8>>();
        transition select(version_ihl[7:4], version_ihl[3:0]) {
            (4, 5..15): parse_ipv4;
            default: reject;
        }
    }
    
    state parse_ipv4 {
        bit<8> version_ihl;
        bit<32> options_length;
        version_ihl = pkt.lookahead<bit<8>>();
        options_length = ((bit<32>)version_ihl[3:0] - 5) * 32;
        pkt.extract(hdr.ipv4_header, options_length);
        transition select(hdr.ipv4_header.protocol) {
            ip_protocol.TCP: parse_tcp;
            ip_protocol.UDP: parse_udp;
            ip_protocol.ICMP: parse_icmp;
            default: accept;
        }
    }
    
    // Additional parse states for upper layer protocols...
}
*/

/**
 * P4 Match-Action Pipeline for IPv4
 */
/*
control ipv4_control(inout headers hdr) {
    action route_ipv4() {
        // Basic IPv4 routing
        standard_metadata.egress_spec = ipv4_route_table[hdr.ipv4_header.dst_addr];
    }
    
    action decrement_ttl() {
        // TTL processing
        hdr.ipv4_header.ttl = hdr.ipv4_header.ttl - 1;
        hdr.ipv4_header.header_checksum = update_checksum(hdr.ipv4_header);
    }
    
    action fragment_packet() {
        // IPv4 fragmentation logic
        if (hdr.ipv4_header.df == 0) {
            generate_fragments(
                hdr.ipv4_header.identification,
                hdr.ipv4_header.total_length
            );
        }
    }
    
    action process_dscp() {
        // QoS handling based on DSCP
        set_qos_queue(hdr.ipv4_header.dscp);
    }
    
    table ipv4_processing {
        key = {
            hdr.ipv4_header.dst_addr: lpm;  // Longest prefix match
            hdr.ipv4_header.protocol: exact;
        }
        actions = {
            route_ipv4;
            decrement_ttl;
            fragment_packet;
            process_dscp;
            NoAction;
        }
        default_action: NoAction;
    }
    
    apply {
        ipv4_processing.apply();
    }
}
*/

#endif
