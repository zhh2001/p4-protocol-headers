#ifndef P4_PROTOCOL_HEADERS_ETHERNET_P4
#define P4_PROTOCOL_HEADERS_ETHERNET_P4

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
    VLAN_AD = 0x88A8,   // Service VLAN tag (802.1ad)
    VLAN_QINQ = 0x9100, // Legacy QinQ
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
 * The preceding EtherType carries the TPID. This header holds TCI and next EtherType.
 * vlan.p4 provides the same wire layout under the vlan_header type.
 */
header dot1q_header {
    bit<3>  pcp;         // Priority code point
    bit<1>  dei;         // Drop eligible indicator
    bit<12> vlan_id;     // 0: priority tag, 1-4094: VLAN ID, 4095: reserved
    bit<16> ether_type;  // Protocol type (ether_type)
};

/**
 * Ethernet Frame Trailer (4 bytes)
 * Frame check sequence (CRC32)
 * Extract only when the packet cursor reaches an FCS supplied by the target.
 * FCS framing and CRC processing depend on the target configuration.
 */
header ethernet_trailer {
    bit<32> fcs;   // Frame check sequence
};

/**
 * P4 Parser Logic for Ethernet
 * The packet cursor must point to the destination MAC address.
 * The enclosing headers struct contains ethernet_header ethernet_header
 * and dot1q_header[2] vlan. This example handles up to two VLAN tags.
 * It dispatches on the innermost EtherType and leaves FCS handling to the target.
 */
/*
parser ethernet_parser(packet_in pkt, inout headers hdr) {
    bit<16> payload_type;

    state start {
        pkt.extract(hdr.ethernet_header);
        payload_type = hdr.ethernet_header.ether_type;
        transition parse_payload;
    }
    
    state parse_dot1q {
        pkt.extract(hdr.vlan.next);
        verify(hdr.vlan.last.vlan_id != 4095, error.NoMatch);
        payload_type = hdr.vlan.last.ether_type;
        transition parse_payload;
    }
    
    state parse_payload {
        transition select(payload_type) {
            ether_type.VLAN: parse_dot1q;
            ether_type.VLAN_AD: parse_dot1q;
            ether_type.VLAN_QINQ: parse_dot1q;
            ether_type.IPv4: parse_ipv4;
            ether_type.IPv6: parse_ipv6;
            ether_type.ARP: parse_arp;
            default: accept;
        }
    }
    
    // Add parse_ipv4, parse_ipv6 and parse_arp states for upper-layer headers.
}
*/

/**
 * P4 Match-Action Pipeline for Ethernet (v1model)
 * Include the outer VLAN ID and tag presence in the MAC forwarding key.
 * Use vlan.p4 for tag push/pop and PCP changes.
 */
/*
control ethernet_control(inout headers hdr,
                         inout standard_metadata_t standard_metadata) {
    bit<1> tagged;
    bit<12> vid;

    action forward_frame(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    
    action drop_frame() {
        mark_to_drop(standard_metadata);
    }
    
    table mac_forwarding {
        key = {
            hdr.ethernet_header.dst_mac: exact;
            tagged: exact;
            vid: exact;
        }
        actions = {
            forward_frame;
            drop_frame;
            NoAction;
        }
        default_action = drop_frame();
    }
    
    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.ethernet_header.isValid()) {
            drop_frame();
        } else {
            tagged = 0;
            vid = 0;
            if (hdr.vlan[0].isValid()) {
                tagged = 1;
                vid = hdr.vlan[0].vlan_id;
            }
            mac_forwarding.apply();
        }
    }
}
*/

#endif
