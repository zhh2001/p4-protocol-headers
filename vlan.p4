#ifndef P4_PROTOCOL_HEADERS_VLAN_P4
#define P4_PROTOCOL_HEADERS_VLAN_P4

/**
 * 802.1Q VLAN Header Definition in P4
 * Virtual LAN tagging protocol for network segmentation
 * 
 * The Ethernet EtherType carries the outer tag's TPID.
 * Each VLAN header below holds the TCI and the next EtherType.
 */

/* VLAN Priority Levels (PCP) */
enum bit<3> vlan_priority {
    BE = 0,  // Best Effort (default)
    BK = 1,  // Background (lowest)
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
 * Extract after a TPID has been identified in the preceding EtherType.
 */
header vlan_header {
    bit<3> pcp;          // Priority code point (vlan_priority)
    bit<1> dei;          // Drop eligible indicator
    bit<12> vlan_id;     // 0: priority tag, 1-4094: VLAN ID, 4095: reserved
    bit<16> ether_type;  // Encapsulated protocol
};

/**
 * P4 Parser Logic for VLAN
 * Extract the Ethernet header first and include ethernet.p4 separately.
 * Pass the Ethernet EtherType as outer_type and hdr.vlan as the output,
 * using vlan_header[2] for that member. The output starts with invalid
 * headers and a stack index of zero. This example handles up to two tags.
 * Select the payload parser from the last tag's EtherType, or outer_type
 * for an untagged frame.
 */
/*
parser vlan_parser(packet_in pkt, in bit<16> outer_type,
                   out vlan_header[2] vlan) {
    state start {
        transition select(outer_type) {
            vlan_encap.DOT1Q: parse_vlan;
            vlan_encap.DOT1AD: parse_vlan;
            vlan_encap.DOT1QINQ: parse_vlan;
            default: accept;
        }
    }
    
    state parse_vlan {
        pkt.extract(vlan.next);
        verify(vlan.last.vlan_id != 4095, error.NoMatch);
        transition select(vlan.last.ether_type) {
            vlan_encap.DOT1Q: parse_vlan;
            vlan_encap.DOT1AD: parse_vlan;
            vlan_encap.DOT1QINQ: parse_vlan;
            default: accept;
        }
    }
}
*/

/**
 * P4 Match-Action Pipeline for VLAN (v1model)
 * headers contains ethernet_header ethernet_header and a two-tag vlan stack.
 * Forwarding and PCP changes use the outer tag. Push and pop affect one tag.
 * The table also accepts untagged frames so it can add their first VLAN tag.
 * Apply tag edits before Ethernet forwarding, or use route_by_vlan directly.
 * Parser errors and rejected tag additions drop and exit the ingress pipeline.
 */
/*
control vlan_control(inout headers hdr,
                     inout standard_metadata_t standard_metadata) {
    bit<1> tagged;
    bit<12> vid;
    bit<3> priority;

    action route_by_vlan(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    
    action set_pcp(bit<3> pcp) {
        if (hdr.vlan[0].isValid()) {
            hdr.vlan[0].pcp = pcp;
        }
    }
    
    action strip_vlan() {
        if (hdr.vlan[0].isValid()) {
            hdr.ethernet_header.ether_type = hdr.vlan[0].ether_type;
            hdr.vlan.pop_front(1);
        }
    }
    
    action add_vlan(bit<12> vlan_id) {
        if (hdr.vlan[1].isValid() || vlan_id == 4095) {
            mark_to_drop(standard_metadata);
            exit;
        } else {
            hdr.vlan.push_front(1);
            hdr.vlan[0].setValid();
            hdr.vlan[0].pcp = vlan_priority.BE;
            hdr.vlan[0].dei = 0;
            hdr.vlan[0].vlan_id = vlan_id;
            hdr.vlan[0].ether_type = hdr.ethernet_header.ether_type;
            hdr.ethernet_header.ether_type = vlan_encap.DOT1Q;
        }
    }
    
    table vlan_processing {
        key = {
            tagged: exact;
            vid: exact;
            priority: exact;
        }
        actions = {
            route_by_vlan;
            set_pcp;
            strip_vlan;
            add_vlan;
            NoAction;
        }
        default_action = NoAction();
    }
    
    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.ethernet_header.isValid()) {
            mark_to_drop(standard_metadata);
            exit;
        }
        tagged = 0;
        vid = 0;
        priority = 0;
        if (hdr.vlan[0].isValid()) {
            tagged = 1;
            vid = hdr.vlan[0].vlan_id;
            priority = hdr.vlan[0].pcp;
        }
        vlan_processing.apply();
    }
}
*/

#endif
