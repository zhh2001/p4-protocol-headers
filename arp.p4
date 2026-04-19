/**
 * ARP Header Definition in P4
 * Address Resolution Protocol for mapping IP addresses to MAC addresses
 * 
 * Note: ARP is used to resolve network layer addresses (IPv4) to link layer addresses (MAC)
 *       Operates directly over Ethernet (type 0x0806)
 */

/* ARP Operation Codes */
enum bit<8> arp_opcode {
    ARP_REQUEST  = 1,      // Request target MAC address
    ARP_REPLY    = 2,      // Response with MAC address
    RARP_REQUEST = 3,      // Reverse ARP request
    RARP_REPLY   = 4       // Reverse ARP reply
};

/* Hardware Types */
enum bit<8> arp_hardware_type {
    ETHERNET      = 1,        // Ethernet (10Mb)
    IEEE802       = 6,        // IEEE 802 networks
    ARCNET        = 7,        // ARCNET
    FRAME_RELAY   = 15,       // Frame Relay
    FIBRE_CHANNEL = 18,       // Fibre Channel
    IEEE1394      = 24,       // IEEE 1394 (FireWire)
    INFINIBAND    = 32        // InfiniBand
};

/* Protocol Types */
enum bit<16> arp_protocol_type {
    IPV4 = 0x0800,      // Internet Protocol v4
    IPV6 = 0x86DD,      // Internet Protocol v6
    MPLS = 0x8847       // MPLS
};

/**
 * ARP Packet Header (28 bytes for IPv4 over Ethernet)
 * Standard ARP request/reply format
 */
header arp_header {
    bit<16> hw_type;            // Hardware type (arp_hardware_type)
    bit<16> proto_type;         // Protocol type (arp_protocol_type)
    bit<8>  hw_addr_len;        // Hardware address length (6 for Ethernet)
    bit<8>  proto_addr_len;     // Protocol address length (4 for IPv4)
    bit<16> opcode;             // Operation code (arp_opcode)
    bit<48> sender_hw_addr;     // Sender hardware address
    bit<32> sender_proto_addr;  // Sender protocol address
    bit<48> target_hw_addr;     // Target hardware address
    bit<32> target_proto_addr;  // Target protocol address
};

/**
 * Gratuitous ARP Extension
 * Special ARP used for duplicate IP detection and updates
 */
header gratuitous_arp {
    bit<8>  flags;            // Special flags for gratuitous ARP
    bit<16> reserved;         // Must be 0
    bit<32> update_interval;  // Cache update interval in seconds
};

/**
 * Proxy ARP Extension
 * Used when devices answer ARP requests on behalf of others
 */
header proxy_arp {
    bit<8>  proxy_type;        // Proxy type (0=standard, 1=local, 2=remote)
    bit<16> proxy_id;          // Proxy identifier
    bit<32> original_sender;   // Original sender IP (for validation)
};

/**
 * ARP Transport Header (Ethernet)
 * Ethernet frame format for ARP packets
 */
header arp_transport {
    bit<48> dst_mac;            // Destination MAC (FF:FF:FF:FF:FF:FF for request)
    bit<48> src_mac;            // Source MAC address
    // bit<16> eth_type = 0x0806;  // (pseudocode: field initializer removed)  // ARP protocol type
};

/**
 * P4 Parser Logic for ARP
 */
/*
parser arp_parser(packet_in pkt, out headers hdr) {
    state start {
        pkt.extract(hdr.arp_transport);
        transition parse_arp;
    }
    
    state parse_arp {
        pkt.extract(hdr.arp_header);
        transition select(hdr.arp_header.opcode) {
            ARP_REQUEST: parse_arp_request;
            ARP_REPLY: parse_arp_reply;
            RARP_REQUEST: parse_rarp_request;
            RARP_REPLY: parse_rarp_reply;
            default: accept;
        }
    }
    
    state parse_arp_request {
        // Additional processing for ARP requests
        transition accept;
    }
    
    // Additional parse states for other ARP variants...
}
*/

/**
 * P4 Match-Action Pipeline for ARP
 */
/*
control arp_control(inout headers hdr) {
    action generate_arp_reply() {
        // Generate ARP reply from request
        hdr.arp_header.opcode = ARP_REPLY;
        hdr.arp_transport.dst_mac = hdr.arp_transport.src_mac;
        hdr.arp_header.target_hw_addr = hdr.arp_header.sender_hw_addr;
        hdr.arp_header.target_proto_addr = hdr.arp_header.sender_proto_addr;
        hdr.arp_header.sender_hw_addr = device_mac;
        hdr.arp_header.sender_proto_addr = hdr.arp_header.target_proto_addr;
    }
    
    action update_arp_cache() {
        // Update local ARP cache with new mapping
        arp_cache.update(
            hdr.arp_header.sender_proto_addr,
            hdr.arp_header.sender_hw_addr
        );
    }
    
    action send_gratuitous_arp() {
        // Send gratuitous ARP announcement
        hdr.arp_header.opcode = ARP_REPLY;
        hdr.arp_transport.dst_mac = 48w0xFFFFFFFFFFFF;
        hdr.arp_header.sender_proto_addr = device_ip;
        hdr.arp_header.target_proto_addr = device_ip;
        hdr.arp_header.sender_hw_addr = device_mac;
        hdr.arp_header.target_hw_addr = 48w0;
    }
    
    action process_proxy_arp() {
        // Handle proxy ARP scenarios
        if (is_proxy_target(hdr.arp_header.target_proto_addr)) {
            hdr.proxy_arp.proxy_type = 8w1;  // Local proxy
            generate_arp_reply();
        }
    }
    
    table arp_processing {
        key = {
            hdr.arp_header.opcode: exact;
            hdr.arp_header.target_proto_addr: exact;
        }
        actions = {
            generate_arp_reply;
            update_arp_cache;
            send_gratuitous_arp;
            process_proxy_arp;
            NoAction;
        }
        default_action = NoAction;
    }
    
    apply {
        arp_processing.apply();
    }
}
*/
