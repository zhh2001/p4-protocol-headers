/**
 * GRE Header Definition in P4
 * Generic Routing Encapsulation protocol for tunneling
 * 
 * Note: GRE provides a simple, flexible tunneling mechanism that can encapsulate
 *       various network layer protocols over IP networks (IP protocol 47).
 */

/* GRE Flags */
enum bit<16> gre_flags {
    CHECKSUM_PRESENT = 0x8000,  // Checksum present
    KEY_PRESENT      = 0x2000,  // Key present
    SEQUENCE_PRESENT = 0x1000,  // Sequence number present
    STRICT_SOURCE    = 0x0800   // Strict source route
};

/* GRE Protocol Types */
enum bit<16> gre_protocol_type {
    IP     = 0x0800,        // IPv4 payload
    IPV6   = 0x86DD,        // IPv6 payload
    MPLS   = 0x8847,        // MPLS payload
    ERSPAN = 0x88BE,        // ERSPAN traffic
    VXLAN  = 0x6558         // VXLAN payload
};

/**
 * GRE Base Header (4-16 bytes)
 * Minimal GRE encapsulation header
 */
header gre_header {
    bit<1>  checksum_present;  // Checksum present flag
    bit<1>  reserved1;         // Must be 0
    bit<1>  key_present;       // Key present flag
    bit<1>  sequence_present;  // Sequence number present flag
    bit<3>  version;           // GRE version (0 for standard GRE)
    bit<7>  reserved2;         // Must be 0
    bit<16> protocol;          // Payload protocol type (gre_protocol_type)
};

/**
 * GRE Optional Fields
 * Variable-length optional fields
 */
header gre_options {
    bit<16> checksum;        // Optional checksum (if checksum_present set)
    bit<16> reserved;        // Must be 0 (with checksum)
    bit<32> key;             // Optional key field (if key_present set)
    bit<32> sequence;        // Optional sequence number (if sequence_present set)
};

/**
 * GRE Transport Header (IP)
 * Outer IP header for GRE encapsulation
 */
header gre_transport {
    bit<8>  version_ihl;        // Version (4) + IHL (5 for 20 byte header)
    bit<8>  dscp_ecn;           // DSCP (6 bits) + ECN (2 bits)
    bit<16> total_length;       // Total packet length
    bit<16> identification;     // IP identification
    bit<16> flags_frag_offset;  // Flags + Fragment offset
    bit<8>  ttl;                // Time to live
    // bit<8>  protocol = 47;  // (pseudocode: field initializer removed)      // GRE protocol number
    bit<16> header_checksum;    // IP header checksum
    bit<32> src_ip;             // Source IP address (tunnel endpoint)
    bit<32> dst_ip;             // Destination IP address (tunnel endpoint)
};

/**
 * GRE Packet Structure:
 * [Outer Ethernet][Outer IP][GRE][Options][Payload]
 */

/**
 * GRE Keepalive Header
 * Used for tunnel keepalive monitoring
 */
header gre_keepalive {
    bit<32> timestamp;      // Timestamp of keepalive
    bit<16> sequence;       // Sequence number
    bit<16> interval;       // Keepalive interval in seconds
};

/**
 * P4 Parser Logic for GRE
 */
/*
parser gre_parser(packet_in pkt, out headers hdr) {
    state start {
        pkt.extract(hdr.outer_ethernet);
        transition select(hdr.outer_ethernet.eth_type) {
            0x0800: parse_ip;
            default: accept;
        }
    }
    
    state parse_ip {
        pkt.extract(hdr.gre_transport);
        transition select(hdr.gre_transport.protocol) {
            47: parse_gre;
            default: accept;
        }
    }
    
    state parse_gre {
        pkt.extract(hdr.gre_header);
        transition parse_gre_options;
    }
    
    state parse_gre_options {
        // Dynamically parse optional fields based on flags
        if (hdr.gre_header.checksum_present) {
            pkt.extract(hdr.gre_options.checksum);
            pkt.extract(hdr.gre_options.reserved);
        }
        if (hdr.gre_header.key_present) {
            pkt.extract(hdr.gre_options.key);
        }
        if (hdr.gre_header.sequence_present) {
            pkt.extract(hdr.gre_options.sequence);
        }
        transition parse_payload;
    }
    
    state parse_payload {
        transition select(hdr.gre_header.protocol) {
            0x0800: parse_inner_ip;
            0x86DD: parse_inner_ipv6;
            0x8847: parse_mpls;
            default: accept;
        }
    }
    
    // Additional parse states for payload types...
}
*/

/**
 * P4 Match-Action Pipeline for GRE
 */
/*
control gre_control(inout headers hdr) {
    action encapsulate_ip() {
        // Encapsulate IPv4 payload in GRE tunnel
        hdr.gre_transport.src_ip = local_tunnel_ip;
        hdr.gre_transport.dst_ip = remote_tunnel_ip;
        hdr.gre_header.protocol = IP;
        hdr.gre_header.key_present = 1;
        hdr.gre_options.key = tunnel_id;
    }
    
    action decapsulate() {
        // Remove GRE encapsulation and process inner packet
        hdr.inner_ip.version_ihl = hdr.payload.version_ihl;
    }
    
    action route_tunnel() {
        // Perform tunnel routing based on optional fields
        if (hdr.gre_header.key_present) {
            hdr.gre_transport.dst_ip = lookup_tunnel_endpoint(hdr.gre_options.key);
        }
    }
    
    action process_keepalive() {
        // Process GRE keepalive messages
        if (hdr.gre_keepalive.interval > 0) {
            update_tunnel_health(hdr.gre_options.key);
        }
    }
    
    table gre_processing {
        key = {
            hdr.gre_header.protocol: exact;
            hdr.gre_options.key: optional;
        }
        actions = {
            encapsulate_ip;
            decapsulate;
            route_tunnel;
            process_keepalive;
            NoAction;
        }
        default_action = NoAction;
    }
    
    apply {
        gre_processing.apply();
    }
}
*/
