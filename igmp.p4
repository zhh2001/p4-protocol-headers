/**
 * IGMP Header Definition in P4
 * Internet Group Management Protocol for IP multicast group management
 * 
 * Note: IGMP is used by hosts and adjacent routers to establish multicast group memberships
 *       (IP protocol number 2 for IPv4)
 */

/* IGMP Version Types */
enum bit<8> igmp_version {
    IGMPv1 = 1,
    IGMPv2 = 2, 
    IGMPv3 = 3
};

/* IGMP Message Types */
enum bit<8> igmp_type {
    MEMBERSHIP_QUERY = 0x11,        // Membership query
    V1_MEMBERSHIP_REPORT = 0x12,    // IGMPv1 report
    V2_MEMBERSHIP_REPORT = 0x16,    // IGMPv2 report
    V2_LEAVE_GROUP = 0x17,          // IGMPv2 leave group
    V3_MEMBERSHIP_REPORT = 0x22     // IGMPv3 report
};

/* IGMP Query Types */
enum bit<8> igmp_query_type {
    GENERAL_QUERY = 1,      // Query all groups
    GROUP_SPECIFIC_QUERY = 2, // Query specific group
    STATE_CHANGE_QUERY = 3   // Query for state change
};

/**
 * IGMP Common Header (8 bytes)
 * Base header for all IGMP messages
 */
header igmp_header {
    bit<8> type;             // IGMP message type (igmp_type)
    bit<8> max_resp_time;   // Max response time (in 1/10 seconds)
    bit<16> checksum;       // IGMP checksum
    bit<32> group_address;  // Multicast group address
};

/**
 * IGMPv3 Membership Query (12+ bytes)
 * Extended header for IGMPv3 queries
 */
header igmpv3_query {
    bit<8> flags;           // [S=suppress router side processing]
    bit<8> qqi;             // Querier's Query Interval
    bit<16> num_sources;    // Number of source addresses
    varbit<1024> sources;      // Source addresses (variable length)
};

/**
 * IGMPv3 Membership Report (8+ bytes)
 * Extended header for IGMPv3 reports
 */
header igmpv3_report {
    bit<16> reserved;       // Must be 0
    bit<16> num_group_recs; // Number of group records
    varbit<1024> group_records; // Group records (variable length)
};

/**
 * IGMPv3 Group Record (8+ bytes)
 * Individual group record in IGMPv3 report
 */
header igmpv3_group_rec {
    bit<8> rec_type;        // Record type (1-6)
    bit<8> aux_data_len;    // Length of auxiliary data
    bit<16> num_sources;    // Number of sources
    bit<32> mcast_addr;     // Multicast address
    varbit<1024> sources;      // Source addresses (variable length)
    varbit<1024> aux_data;      // Auxiliary data (variable length)
};

/**
 * IGMP Transport Header (IP)
 * Outer IP header for IGMP messages
 */
header igmp_transport {
    bit<8> version_ihl;     // Version (4) + IHL (5 for 20 byte header)
    bit<8> dscp_ecn;        // DSCP (6 bits) + ECN (2 bits)
    bit<16> total_length;   // Total packet length
    bit<16> identification; // IP identification
    bit<16> flags_frag_offset; // Flags + Fragment offset
    // bit<8> ttl = 1;  // (pseudocode: field initializer removed)        // Time to live (typically 1)
    // bit<8> protocol = 2;  // (pseudocode: field initializer removed)    // IGMP protocol number
    bit<16> header_checksum; // IP header checksum
    bit<32> src_ip;        // Source IP address
    bit<32> dst_ip;        // Destination IP address
};

/**
 * P4 Parser Logic for IGMP
 */
/*
parser igmp_parser(packet_in pkt, out headers hdr) {
    state start {
        pkt.extract(hdr.igmp_transport);
        transition select(hdr.igmp_transport.protocol) {
            2: parse_igmp;
            default: accept;
        }
    }
    
    state parse_igmp {
        pkt.extract(hdr.igmp_header);
        transition select(hdr.igmp_header.type) {
            MEMBERSHIP_QUERY: parse_igmp_query;
            V3_MEMBERSHIP_REPORT: parse_igmpv3_report;
            V2_MEMBERSHIP_REPORT: parse_igmpv2_report;
            V2_LEAVE_GROUP: parse_igmpv2_leave;
            default: accept;
        }
    }
    
    state parse_igmp_query {
        // Check group address to determine query type
        if (hdr.igmp_header.group_address == 0.0.0.0) {
            transition parse_general_query;
        } else {
            transition parse_group_specific_query;
        }
    }
    
    // Additional parse states for specific IGMP message types...
}
*/

/**
 * P4 Match-Action Pipeline for IGMP
 */
/*
control igmp_control(inout headers hdr) {
    action process_membership_query() {
        // Process membership query from router
        if (hdr.igmp_header.group_address == 0.0.0.0) {
            // General query - respond for all joined groups
            trigger_reports_for_all_groups();
        } else {
            // Group-specific query
            trigger_report_for_group(hdr.igmp_header.group_address);
        }
    }
    
    action process_v2_report() {
        // Process IGMPv2 membership report
        update_membership(hdr.igmp_header.group_address, 
                         hdr.igmp_transport.src_ip,
                         true);
    }
    
    action process_v3_report() {
        // Process IGMPv3 membership report
        for (int i = 0; i < hdr.igmpv3_report.num_group_recs; i++) {
            process_group_record(hdr.igmpv3_group_rec[i]);
        }
    }
    
    action send_leave_group() {
        // Send leave group message
        hdr.igmp_header.type = V2_LEAVE_GROUP;
        hdr.igmp_transport.dst_ip = 224.0.0.2; // All routers address
        hdr.igmp_header.checksum = calculate_checksum();
    }
    
    table igmp_processing {
        key = {
            hdr.igmp_header.type: exact;
            hdr.igmp_header.group_address: exact;
        }
        actions = {
            process_membership_query;
            process_v2_report;
            process_v3_report;
            send_leave_group;
            NoAction;
        }
        default_action = NoAction;
    }
    
    apply {
        igmp_processing.apply();
    }
}
*/
