/**
 * Ethernet II Frame Header Definition in P4
 * Standard IEEE 802.3 frame format for local area networks
 * 
 * Note: This defines the most common Ethernet frame format used in IP networks
 */

/* Ethernet Frame Types */
enum bit<16> ether_type {
    IPv4  = 0x0800,     // Internet Protocol v4
    IPv6  = 0x86DD,     // Internet Protocol v6
    ARP   = 0x0806,     // Address Resolution Protocol
    VLAN  = 0x8100,     // IEEE 802.1Q VLAN tagging
    MPLS  = 0x8847,     // MPLS unicast
    PPPoE = 0x8864      // PPP over Ethernet
};

/**
 * Ethernet II Header (14 bytes)
 * Standard frame header without 802.1Q tag
 */
header ethernet_header {
    bit<48> dst_mac;     // Destination MAC address
    bit<48> src_mac;     // Source MAC address
    bit<16> ether_type;  // Protocol type (ether_type)
};

/**
 * 802.1Q VLAN Tagging Header (4 bytes)
 * Optional VLAN tagging extension
 */
header dot1q_header {
    bit<3>  pcp;         // Priority code point
    bit<1>  dei;         // Drop eligible indicator
    bit<12> vlan_id;     // VLAN identifier
    bit<16> ether_type;  // Protocol type (ether_type)
};

/**
 * Ethernet Frame Trailer (4 bytes)
 * Frame check sequence (CRC32)
 */
header ethernet_trailer {
    bit<32> fcs;   // Frame check sequence
};

/**
 * P4 Parser Logic for Ethernet
 */
/*
parser ethernet_parser(packet_in pkt, out headers hdr) {
    state start {
        pkt.extract(hdr.ethernet_header);
        transition select(hdr.ethernet_header.ether_type) {
            VLAN: parse_dot1q;
            default: parse_payload;
        }
    }
    
    state parse_dot1q {
        pkt.extract(hdr.dot1q_header);
        transition parse_payload;
    }
    
    state parse_payload {
        // Payload parsing based on ether_type
        transition select(hdr.ethernet_header.ether_type) {
            IPv4: parse_ipv4;
            IPv6: parse_ipv6;
            ARP: parse_arp;
            default: accept;
        }
    }
    
    state parse_trailer {
        pkt.extract(hdr.ethernet_trailer);
        transition verify_fcs;
    }
}
*/

/**
 * P4 Match-Action Pipeline for Ethernet
 */
/*
control ethernet_control(inout headers hdr) {
    action forward_frame() {
        // Basic MAC forwarding logic
        standard_metadata.egress_spec = 
            mac_table[hdr.ethernet_header.dst_mac];
    }
    
    action add_vlan_tag(vlan_id) {
        // Insert 802.1Q VLAN tag
        hdr.dot1q_header.vlan_id = vlan_id;
        hdr.dot1q_header.ether_type = hdr.ethernet_header.ether_type;
        hdr.ethernet_header.ether_type = VLAN;
    }
    
    action remove_vlan_tag() {
        // Remove 802.1Q VLAN tag
        hdr.ethernet_header.ether_type = hdr.dot1q_header.ether_type;
    }
    
    action calculate_crc() {
        // Recalculate frame check sequence
        hdr.ethernet_trailer.fcs = compute_crc32();
    }
    
    table mac_forwarding {
        key = {
            hdr.ethernet_header.dst_mac: exact;
            hdr.dot1q_header.vlan_id: exact; // Optional VLAN
        }
        actions = {
            forward_frame;
            add_vlan_tag;
            remove_vlan_tag;
            NoAction;
        }
        default_action = drop;
    }
    
    apply {
        mac_forwarding.apply();
    }
}
*/
