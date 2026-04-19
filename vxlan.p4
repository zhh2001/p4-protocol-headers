/**
 * VXLAN Header Definition in P4
 * Virtual Extensible LAN protocol for network virtualization
 * 
 * Note: VXLAN provides Layer 2 overlay networks over Layer 3 infrastructure
 *       using MAC-in-UDP encapsulation with 24-bit VXLAN Network Identifier (VNI)
 */

/* VXLAN Flags */
enum bit<8> vxlan_flags {
    I_FLAG  = 0x08,  // Indicates valid VNI present
    R_FLAG  = 0x04,  // Reserved for future use
    R_FLAG2 = 0x02,  // Reserved for future use
    R_FLAG3 = 0x01   // Reserved for future use
};

/**
 * VXLAN Header (8 bytes)
 * Encapsulation header for overlay networks
 */
header vxlan_header {
    bit<8>  flags;          // VXLAN flags (I/R/R/R bits)
    bit<24> reserved1;      // Reserved field (must be 0)
    bit<24> vni;            // VXLAN Network Identifier
    bit<8>  reserved2;      // Reserved field (must be 0)
};

/**
 * Inner Ethernet Header (14 bytes)
 * Original L2 frame being encapsulated
 */
header inner_ethernet {
    bit<48> dst_mac;      // Destination MAC address
    bit<48> src_mac;      // Source MAC address
    bit<16> eth_type;     // EtherType of payload
};

/**
 * UDP Header (8 bytes)
 * Transport protocol for VXLAN
 */
header vxlan_udp {
    bit<16> src_port;     // Source port (often hash of inner frame)
    bit<16> dst_port;     // Destination port (4789 by default)
    bit<16> length;       // UDP length including header
    bit<16> checksum;     // UDP checksum (optional for IPv4)
};

/**
 * Outer IP Header (20 bytes)
 * Underlay routing header
 */
header vxlan_ip {
    bit<8>  version_ihl;        // Version (4) + IHL (5 for 20 byte header)
    bit<8>  dscp_ecn;           // DSCP (6 bits) + ECN (2 bits)
    bit<16> total_length;       // Total packet length
    bit<16> identification;     // IP identification
    bit<16> flags_frag_offset;  // Flags (3 bits) + Fragment offset (13 bits)
    bit<8>  ttl;                // Time to live
    // bit<8>  protocol = 17;  // (pseudocode: field initializer removed)      // UDP protocol number
    bit<16> header_checksum;    // IP header checksum
    bit<32> src_ip;             // Source IP address (VTEP address)
    bit<32> dst_ip;             // Destination IP address (VTEP address)
};

/**
 * VXLAN Packet Structure:
 * [Outer Ethernet][Outer IP][UDP][VXLAN][Inner Ethernet][Payload]
 */

/**
 * VXLAN Termination Header
 * Used by VXLAN gateways for additional processing
 */
header vxlan_termination {
    bit<8>  gateway_type;  // 0=regular, 1=L2 gateway, 2=L3 gateway
    bit<16> context_id;    // Gateway context identifier
    bit<8>  policy_flags;  // Policy enforcement flags
    bit<32> tenant_id;     // Tenant identifier
};

/**
 * P4 Parser Logic for VXLAN
 */
/*
parser vxlan_parser(packet_in pkt, out headers hdr) {
    state start {
        pkt.extract(hdr.outer_ethernet);
        transition select(hdr.outer_ethernet.eth_type) {
            0x0800: parse_ip;
            default: accept;
        }
    }
    
    state parse_ip {
        pkt.extract(hdr.vxlan_ip);
        transition select(hdr.vxlan_ip.protocol) {
            17: parse_udp;
            default: accept;
        }
    }
    
    state parse_udp {
        pkt.extract(hdr.vxlan_udp);
        transition select(hdr.vxlan_udp.dst_port) {
            4789: parse_vxlan;
            default: accept;
        }
    }
    
    state parse_vxlan {
        pkt.extract(hdr.vxlan_header);
        transition parse_inner_ethernet;
    }
    
    state parse_inner_ethernet {
        pkt.extract(hdr.inner_ethernet);
        transition select(hdr.inner_ethernet.eth_type) {
            0x0800: parse_inner_ip;
            0x0806: parse_inner_arp;
            default: accept;
        }
    }
    
    // Additional parse states for inner payload...
}
*/

/**
 * P4 Match-Action Pipeline for VXLAN
 */
/*
control vxlan_control(inout headers hdr) {
    action encapsulate() {
        // Apply VXLAN encapsulation to original frame
        hdr.vxlan_ip.src_ip = vtep_address;
        hdr.vxlan_ip.dst_ip = lookup_vtep(hdr.inner_ethernet.dst_mac);
        hdr.vxlan_header.vni = lookup_vni(hdr.inner_ethernet.vlan_id);
    }
    
    action decapsulate() {
        // Remove VXLAN encapsulation and process inner frame
        hdr.inner_ethernet.eth_type = hdr.payload.eth_type;
    }
    
    action route_overlay() {
        // Perform overlay routing based on inner headers
        hdr.vxlan_ip.dst_ip = overlay_routing(hdr.inner_ip.dst_addr);
    }
    
    table vxlan_processing {
        key = {
            hdr.vxlan_header.vni: exact;
            hdr.inner_ethernet.dst_mac: exact;
        }
        actions = {
            encapsulate;
            decapsulate;
            route_overlay;
            NoAction;
        }
        default_action = NoAction;
    }
    
    apply {
        vxlan_processing.apply();
    }
}
*/
