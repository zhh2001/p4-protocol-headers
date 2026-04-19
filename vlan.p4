/**
 * 802.1Q VLAN Header Definition in P4
 * Virtual LAN tagging protocol for network segmentation
 * 
 * Note: 802.1Q inserts a 4-byte tag between Ethernet header and payload
 *       to support VLAN trunking and quality of service
 */

/* VLAN Priority Levels (PCP) */
enum bit<8> vlan_priority {
    BK = 0,  // Background (lowest)
    BE = 1,  // Best Effort
    EE = 2,  // Excellent Effort
    CA = 3,  // Critical Applications
    VI = 4,  // Video
    VO = 5,  // Voice
    IC = 6,  // Internetwork Control
    NC = 7,  // Network Control (highest)
};

/* VLAN Encapsulation Types */
enum bit<16> vlan_encap {
    DOT1Q    = 0x8100,  // Standard 802.1Q
    DOT1AD   = 0x88A8,  // Q-in-Q (802.1ad)
    DOT1QINQ = 0x9100,  // Legacy QinQ
};

/**
 * 802.1Q VLAN Tag (4 bytes)
 * Inserted after Ethernet header
 */
header dot1q_header {
    bit<3> pcp;          // Priority code point (vlan_priority)
    bit<1> dei;          // Drop eligible indicator
    bit<12> vlan_id;     // VLAN identifier (1-4094)
    bit<16> ether_type;  // Encapsulated protocol
};

/**
 * Ethernet Header (14 bytes)
 * Original header before VLAN insertion
 */
header ethernet_header {
    bit<48> dst_mac;     // Destination MAC
    bit<48> src_mac;     // Source MAC
    bit<16> ether_type;  // Original EtherType or VLAN tag
};

/**
 * P4 Parser Logic for VLAN
 */
/*
parser vlan_parser(packet_in pkt, out headers hdr) {
    state start {
        pkt.extract(hdr.ethernet_header);
        transition select(hdr.ethernet_header.ether_type) {
            DOT1Q: parse_dot1q;
            DOT1AD: parse_dot1ad;
            default: parse_payload;
        }
    }
    
    state parse_dot1q {
        pkt.extract(hdr.dot1q_header);
        transition select(hdr.dot1q_header.ether_type) {
            DOT1AD: parse_dot1ad; // Q-in-Q scenario
            default: parse_payload;
        }
    }
    
    state parse_dot1ad {
        // For Q-in-Q double tagging
        pkt.extract(hdr.dot1q_header);
        transition parse_payload;
    }
    
    state parse_payload {
        // Continue parsing based on EtherType
        transition accept;
    }
}
*/

/**
 * P4 Match-Action Pipeline for VLAN
 */
/*
control vlan_control(inout headers hdr) {
    action route_by_vlan() {
        // VLAN-based forwarding
        standard_metadata.egress_spec = 
            vlan_table[hdr.dot1q_header.vlan_id];
    }
    
    action set_pcp(pcp) {
        // Set priority code point
        hdr.dot1q_header.pcp = pcp;
    }
    
    action strip_vlan() {
        // Remove VLAN tag (pop operation)
        hdr.ethernet_header.ether_type = hdr.dot1q_header.ether_type;
    }
    
    action add_vlan(vlan_id) {
        // Add VLAN tag (push operation)
        hdr.dot1q_header.ether_type = hdr.ethernet_header.ether_type;
        hdr.ethernet_header.ether_type = DOT1Q;
        hdr.dot1q_header.vlan_id = vlan_id;
    }
    
    table vlan_processing {
        key = {
            hdr.dot1q_header.vlan_id: exact;
            hdr.dot1q_header.pcp: exact;
        }
        actions = {
            route_by_vlan;
            set_pcp;
            strip_vlan;
            add_vlan;
            NoAction;
        }
        default_action: NoAction;
    }
    
    apply {
        if (hdr.dot1q_header.isValid()) {
            vlan_processing.apply();
        }
    }
}
*/
