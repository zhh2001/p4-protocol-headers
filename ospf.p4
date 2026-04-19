/**
 * OSPF Header Definition in P4
 * Open Shortest Path First routing protocol for intra-domain routing
 * 
 * Note: OSPF is a link-state IGP that uses Dijkstra's algorithm to calculate
 *       the shortest path tree. It operates directly over IP (protocol 89).
 */

/* OSPF Packet Types */
enum bit<8> ospf_packet_type {
    HELLO     = 1,   // Discover/maintain neighbors
    DB_DESC   = 2,   // Database description
    LS_REQ    = 3,   // Link-state request
    LS_UPDATE = 4,   // Link-state update
    LS_ACK    = 5    // Link-state acknowledgment
};

/* OSPF Area Types */
enum bit<8> ospf_area_type {
    NORMAL = 0,      // Regular OSPF area
    STUB   = 1,      // Stub area (no external routes)
    NSSA   = 2       // Not-so-stubby area
};

/* OSPF Interface Types */
enum bit<8> ospf_interface_type {
    BROADCAST           = 1,  // Ethernet-style broadcast
    POINT_TO_POINT      = 2,  // PPP/HDLC links
    NBMA                = 3,  // Non-broadcast multi-access
    POINT_TO_MULTIPOINT = 4,
    VIRTUAL             = 5   // Virtual links
};

/**
 * OSPF Common Header (24 bytes)
 * Every OSPF packet starts with this header
 */
header ospf_header {
    bit<8>  version;     // OSPF version (2 for OSPFv2)
    bit<8>  type;        // Packet type (ospf_packet_type)
    bit<16> length;      // Packet length including header
    bit<32> router_id;   // Router ID (IPv4 address format)
    bit<32> area_id;     // Area identifier (0.0.0.0 for backbone)
    bit<16> checksum;    // Standard IP checksum
    bit<16> auth_type;   // Authentication type (0=none, 1=simple, 2=MD5)
    bit<64> auth_data;   // Authentication data (depends on auth_type)
};

/**
 * OSPF Hello Packet (44+ bytes)
 * Used for neighbor discovery/maintenance
 */
header ospf_hello {
    bit<32> network_mask;       // Network mask of originating interface
    bit<16> hello_interval;     // Seconds between hellos
    bit<8>  options;            // Optional capabilities
    bit<8>  priority;           // Router priority for DR election
    bit<32> dead_interval;      // Seconds before declaring neighbor down
    bit<32> designated_router;  // DR router ID
    bit<32> backup_dr;          // BDR router ID
    varbit<1024> neighbors;        // List of neighbor router IDs
};

/**
 * OSPF Database Description Packet (8+ bytes)
 * Used for LSDB synchronization
 */
header ospf_db_desc {
    bit<16> mtu;            // Interface MTU
    bit<8>  options;        // Optional capabilities
    bit<8>  flags;          // [I=init, M=more, MS=master/slave]
    bit<32> dd_seq;         // Sequence number
    varbit<1024> lsa_headers;  // List of LSA headers
};

/**
 * OSPF Link State Request Packet (Variable length)
 * Requests specific LSAs from neighbor
 */
header ospf_ls_request {
    varbit<1024> entries;  // List of [type, id, adv_router] tuples
};

/**
 * OSPF Link State Update Packet (Variable length)
 * Carries one or more LSAs
 */
header ospf_ls_update {
    bit<32> num_lsas;   // Number of LSAs in this update
    varbit<1024> lsas;     // List of LSAs (variable length)
};

/**
 * OSPF Link State Acknowledgment Packet (Variable length)
 * Acknowledges receipt of LSAs
 */
header ospf_ls_ack {
    varbit<1024> lsa_headers;  // List of LSA headers being acknowledged
};

/**
 * OSPF LSA Header (20 bytes)
 * Common header for all LSA types
 */
header ospf_lsa_header {
    bit<16> age;         // Seconds since originated
    bit<8>  options;     // Optional capabilities
    bit<8>  type;        // LSA type (1=router, 2=network, etc.)
    bit<32> id;          // LSA identifier (depends on type)
    bit<32> adv_router;  // Advertising router ID
    bit<32> seq_num;     // LSA sequence number
    bit<16> checksum;    // Fletcher checksum of LSA
    bit<16> length;      // Length of full LSA including header
};

/**
 * OSPF Router LSA (Variable length)
 * Describes router's links to area
 */
header ospf_router_lsa {
    bit<16> flags;      // [V=virtual link, E=ASBR, B=ABR]
    bit<16> num_links;  // Number of router links
    varbit<1024> links;    // List of router links (variable length)
};

/**
 * OSPF Network LSA (Variable length)
 * Describes multi-access network
 */
header ospf_network_lsa {
    bit<32> network_mask;  // Network mask for this network
    varbit<1024> routers;     // List of router IDs on network
};

/**
 * OSPF Summary LSA (Variable length)
 * Describes inter-area routes (Type 3/4)
 */
header ospf_summary_lsa {
    bit<32> network_mask;   // Network mask for this route
    bit<8>  metric;         // Cost to destination
    bit<24> padding;        // Must be 0
};

/**
 * OSPF External LSA (Variable length)
 * Describes AS external routes (Type 5)
 */
header ospf_external_lsa {
    bit<32> network_mask;   // Network mask for this route
    bit<8>  flags;          // [E=external metric type]
    bit<24> metric;         // Route cost
    bit<32> fwd_addr;       // Forwarding address
    bit<32> ext_route_tag;  // Route tag for policy
};

/**
 * OSPF Transport Header (IP)
 */
header ospf_transport {
    bit<8>  tos;            // Type of service (typically 0)
    bit<16> length;         // IP packet length
    bit<16> id;             // IP identification
    bit<16> frag_offset;    // Fragmentation offset
    bit<8>  ttl;            // Time to live (typically 1 for local networks)
    // bit<8>  protocol = 89;  // (pseudocode: field initializer removed)  // OSPF protocol number
    bit<16> checksum;       // IP header checksum
    bit<32> src_addr;       // Source IP address
    bit<32> dest_addr;      // Destination IP address (224.0.0.5/6 for multicast)
};

/**
 * P4 Parser Logic for OSPF
 */
/*
parser ospf_parser(packet_in pkt, out headers hdr) {
    state start {
        pkt.extract(hdr.ospf_transport);
        transition select(hdr.ospf_transport.protocol) {
            89: parse_ospf;
            default: accept;
        }
    }
    
    state parse_ospf {
        pkt.extract(hdr.ospf_header);
        transition select(hdr.ospf_header.type) {
            HELLO: parse_ospf_hello;
            DB_DESC: parse_ospf_db_desc;
            LS_REQ: parse_ospf_ls_req;
            LS_UPDATE: parse_ospf_ls_update;
            LS_ACK: parse_ospf_ls_ack;
            default: accept;
        }
    }
    
    // Additional parse states for each packet type...
}
*/

/**
 * P4 Match-Action Pipeline for OSPF
 */
/*
control ospf_control(inout headers hdr) {
    action process_hello() {
        // Process HELLO packet and update neighbor state
    }
    
    action process_db_desc() {
        // Process database description and determine LSDB sync state
    }
    
    action process_ls_update() {
        // Process LSAs and update link-state database
    }
    
    table ospf_packet_handling {
        key = {
            hdr.ospf_header.type: exact;
        }
        actions = {
            process_hello;
            process_db_desc;
            process_ls_update;
            NoAction;
        }
        default_action = NoAction;
    }
    
    apply {
        ospf_packet_handling.apply();
    }
}
*/
