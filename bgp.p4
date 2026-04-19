/**
 * BGP Header Definition in P4
 * Border Gateway Protocol for inter-domain routing
 * 
 * Note: BGP is the standardized exterior gateway protocol designed to exchange 
 *       routing and reachability information among autonomous systems (AS) on the Internet.
 */

/* BGP Message Types */
enum bit<8> bgp_message_type {
    OPEN          = 1,         // Initiate BGP peer connection
    UPDATE        = 2,         // Exchange routing information
    NOTIFICATION  = 3,         // Error notification
    KEEPALIVE     = 4,         // Maintain connection
    ROUTE_REFRESH = 5          // Request route refresh (RFC 2918)
};

/* BGP Attribute Types */
enum bit<8> bgp_attribute_type {
    ORIGIN = 1,            // Path origin attribute
    AS_PATH = 2,           // AS path attribute
    NEXT_HOP = 3,          // Next hop attribute
    MED = 4,               // Multi-Exit Discriminator
    LOCAL_PREF = 5,        // Local preference
    ATOMIC_AGGREGATE = 6,  // Atomic aggregate
    AGGREGATOR = 7,        // Route aggregator
    COMMUNITY = 8,         // BGP communities
    ORIGINATOR_ID = 9,     // Route reflector originator
    CLUSTER_LIST = 10      // Route reflector cluster list
};

/**
 * BGP Common Header (19 bytes)
 * Every BGP message starts with this header
 */
header bgp_header {
    bit<128> marker;     // Synchronization and authentication (all 1's for OPEN/KEEPALIVE)
    bit<16> length;        // Total message length including header
    bit<8> type;           // BGP message type (bgp_message_type enum)
};

/**
 * BGP OPEN Message (29+ bytes)
 * Used to establish BGP peer connection
 */
header bgp_open {
    bit<8>  version;        // BGP protocol version (currently 4)
    bit<16> my_as;          // Local AS number
    bit<16> hold_time;      // Proposed hold timer in seconds
    bit<32> bgp_id;         // BGP router ID (IPv4 address format)
    bit<8>  opt_param_len;  // Optional parameters length (0 if none)
};

/**
 * BGP Optional Parameter (Variable length)
 * Used in OPEN message for capabilities negotiation
 */
header bgp_opt_param {
    bit<8> param_type;     // Parameter type
    bit<8> param_len;      // Parameter length
    varbit<1024> param_value;  // Parameter value (variable length)
};

/**
 * BGP UPDATE Message (Variable length)
 * Carries routing information updates
 */
header bgp_update {
    bit<16> withdrawn_len; // Withdrawn routes length (0 if none)
    bit<16> path_attr_len; // Path attributes length (0 if none)
    bit<32> nlri_len;      // Network Layer Reachability Info length
};

/**
 * BGP Path Attribute (Variable length)
 * Describes characteristics of the advertised path
 */
header bgp_path_attr {
    bit<1>  optional;       // 0=Well-known, 1=Optional
    bit<1>  transitive;     // 0=Non-transitive, 1=Transitive
    bit<1>  partial;        // 0=Complete, 1=Partial
    bit<1>  extended_len;   // 0=1-byte length, 1=2-byte length
    bit<4>  unused;         // Must be 0
    bit<8>  type_code;      // Attribute type (bgp_attribute_type enum)
    bit<16> attr_len;       // Attribute length (1 or 2 bytes based on extended_len)
};

/**
 * BGP AS_PATH Attribute (Variable length)
 * Lists ASes through which routing info has passed
 */
header bgp_as_path {
    bit<8> path_seg_type;   // 1=AS_SET, 2=AS_SEQUENCE
    bit<8> path_seg_len;    // Number of ASes in this segment
    varbit<1024> as_numbers;   // AS numbers (variable length)
};

/**
 * BGP COMMUNITIES Attribute (Variable length)
 * Used for route tagging and policy applications
 */
header bgp_community {
    varbit<1024> community;  // List of community values
};

/**
 * BGP NOTIFICATION Message (Variable length)
 * Sent when error condition is detected
 */
header bgp_notification {
    bit<8> error_code;    // Major error category
    bit<8> error_subcode; // Specific error within category
    varbit<1024> data;       // Diagnostic data (variable length)
};

/**
 * BGP KEEPALIVE Message (19 bytes)
 * Consists only of BGP header (type=4)
 */

/**
 * BGP ROUTE_REFRESH Message (23 bytes)
 * Requests re-advertisement of routes (RFC 2918)
 */
header bgp_route_refresh {
    bit<16> afi;         // Address Family Identifier
    bit<8> safi;        // Subsequent Address Family Identifier
    bit<8> reserved;    // Must be 0
};

/**
 * BGP Transport Header (TCP)
 */
header bgp_transport {
    bit<16> source_port;  // Typically 179 for active connections
    bit<16> dest_port;    // Typically 179 for passive connections
    bit<32> sequence;     // TCP sequence number
    bit<32> ack_number;   // TCP acknowledgement number
    bit<16> window;       // TCP window size
    bit<16> checksum;     // TCP checksum
};

/**
 * P4 Parser Logic for BGP
 */
/*
parser bgp_parser(packet_in pkt, out headers hdr) {
    state start {
        pkt.extract(hdr.bgp_transport);
        transition select(hdr.bgp_transport.dest_port) {
            179: parse_bgp;
            default: accept;
        }
    }
    
    state parse_bgp {
        pkt.extract(hdr.bgp_header);
        transition select(hdr.bgp_header.type) {
            OPEN: parse_bgp_open;
            UPDATE: parse_bgp_update;
            NOTIFICATION: parse_bgp_notification;
            KEEPALIVE: accept;
            ROUTE_REFRESH: parse_bgp_route_refresh;
            default: accept;
        }
    }
    
    state parse_bgp_open {
        pkt.extract(hdr.bgp_open);
        transition parse_bgp_opt_params;
    }
    
    state parse_bgp_opt_params {
        /* Variable-length optional parameters parsing * /
        transition accept;
    }
    
    // Additional parse states for other message types...
}
*/

/**
 * P4 Match-Action Pipeline for BGP
 */
/*
control bgp_control(inout headers hdr) {
    action process_open() {
        // Process OPEN message and prepare response
    }
    
    action process_update() {
        // Process UPDATE message and update RIB/FIB
    }
    
    action send_notification() {
        // Generate NOTIFICATION message for errors
    }
    
    table bgp_message_handling {
        key = {
            hdr.bgp_header.type: exact;
        }
        actions = {
            process_open;
            process_update;
            send_notification;
            NoAction;
        }
        default_action = NoAction;
    }
    
    apply {
        bgp_message_handling.apply();
    }
}
*/
