#ifndef P4_PROTOCOL_HEADERS_IPV6_P4
#define P4_PROTOCOL_HEADERS_IPV6_P4

/**
 * IPv6 Header Definition in P4
 * Internet Protocol version 6 header for next-generation networking
 * 
 * Note: IPv6 provides expanded addressing (128-bit), simplified header structure,
 *       and built-in support for extension headers
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

/* IPv6 Traffic Class */
enum bit<8> ipv6_traffic_class {
    BACKGROUND = 0x0,   // Background traffic
    BEST_EFFORT = 0x1,  // Default class
    VIDEO = 0x4,        // Video streaming
    VOICE = 0x6,        // Voice traffic
    CONTROL = 0x7       // Network control
};

/**
 * IPv6 Base Header (40 bytes)
 * Fixed-length mandatory header
 */
header ipv6_header {
    bit<4>   version;         // IP version (6)
    bit<8>   traffic_class;   // Traffic class (ipv6_traffic_class)
    bit<20>  flow_label;      // Flow label
    bit<16>  payload_length;  // Extension headers + payload length
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
    bit<13> frag_offset;     // Fragment offset (in 8-byte units)
    bit<2>  reserved2;       // Reserved
    bit<1>  m_flag;          // More fragments flag
    bit<32> identification;  // Packet identifier
};

/**
 * P4 Parser Logic for IPv6
 * The packet cursor must point to the start of the IPv6 header.
 * This example handles one Hop-by-Hop header and one Fragment header.
 * Include ethernet.p4 separately when parsing Ethernet frames.
 */
/*
parser ipv6_parser(packet_in pkt, inout headers hdr) {
    bit<8> next_header;

    state start {
        transition select(pkt.lookahead<bit<4>>()) {
            6: parse_ipv6;
            default: reject;
        }
    }
    
    state parse_ipv6 {
        pkt.extract(hdr.ipv6_header);
        next_header = hdr.ipv6_header.next_header;
        transition select(next_header) {
            ipv6_next_header.HOP_BY_HOP: parse_hop_options;
            ipv6_next_header.FRAGMENT: parse_fragment;
            default: parse_upper_layer;
        }
    }
    
    state parse_hop_options {
        bit<16> next_header_length;
        bit<32> options_length;
        next_header_length = pkt.lookahead<bit<16>>();
        options_length = ((bit<32>)next_header_length[7:0] + 1) * 64 - 16;
        pkt.extract(hdr.ipv6_hop_options, options_length);
        next_header = hdr.ipv6_hop_options.next_header;
        transition select(next_header) {
            ipv6_next_header.FRAGMENT: parse_fragment;
            default: parse_upper_layer;
        }
    }
    
    state parse_fragment {
        pkt.extract(hdr.ipv6_fragment);
        next_header = hdr.ipv6_fragment.next_header;
        // Only the first fragment contains the start of the upper-layer header.
        transition select(hdr.ipv6_fragment.frag_offset) {
            0: parse_upper_layer;
            default: accept;
        }
    }
    
    state parse_upper_layer {
        transition select(next_header) {
            ipv6_next_header.TCP: parse_tcp;
            ipv6_next_header.UDP: parse_udp;
            ipv6_next_header.ICMPv6: parse_icmpv6;
            default: accept;
        }
    }
    
    // Additional parse states for upper layer protocols...
}
*/

/**
 * P4 Match-Action Pipeline for IPv6
 */
/*
control ipv6_control(inout headers hdr) {
    action route_ipv6() {
        // IPv6 routing with 128-bit addresses
        standard_metadata.egress_spec = 
            ipv6_route_table[hdr.ipv6_header.dst_addr];
    }
    
    action decrement_hop_limit() {
        // Hop limit processing (similar to TTL)
        hdr.ipv6_header.hop_limit = hdr.ipv6_header.hop_limit - 1;
    }
    
    action process_flow_label() {
        // Flow-based forwarding handling
        if (hdr.ipv6_header.flow_label != 0) {
            apply_flow_routing(hdr.ipv6_header.flow_label);
        }
    }
    
    action handle_fragmentation() {
        // IPv6 fragmentation (only by source)
        if (hdr.ipv6_fragment.m_flag == 1) {
            process_fragment(hdr.ipv6_fragment.identification);
        }
    }
    
    table ipv6_processing {
        key = {
            hdr.ipv6_header.dst_addr: lpm;  // 128-bit LPM
            hdr.ipv6_header.next_header: exact;
            hdr.ipv6_header.flow_label: exact;  // Optional
        }
        actions = {
            route_ipv6;
            decrement_hop_limit;
            process_flow_label;
            handle_fragmentation;
            NoAction;
        }
        default_action: NoAction;
    }
    
    apply {
        ipv6_processing.apply();
    }
}
*/

#endif
