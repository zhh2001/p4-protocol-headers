/**
 * NTP Header Definition in P4
 * Network Time Protocol for clock synchronization
 * 
 * Note: NTP provides clock synchronization between computer systems over packet-switched networks
 *       (UDP port 123)
 */

/* NTP Modes */
enum bit<8> ntp_mode {
    RESERVED          = 0,  // Reserved
    SYMMETRIC_ACTIVE  = 1,  // Symmetric active
    SYMMETRIC_PASSIVE = 2,  // Symmetric passive
    CLIENT            = 3,  // Client mode
    SERVER            = 4,  // Server mode
    BROADCAST         = 5,  // Broadcast mode
    CONTROL           = 6,  // NTP control message
    PRIVATE           = 7   // Private use
};

/* NTP Leap Indicator */
enum bit<8> ntp_leap {
    NO_WARNING  = 0,         // No leap second warning
    LAST_MIN_61 = 1,         // Last minute has 61 seconds
    LAST_MIN_59 = 2,         // Last minute has 59 seconds
    ALARM       = 3          // Clock not synchronized
};

/* NTP Version Numbers */
enum bit<8> ntp_version {
    NTPv3 = 3,        // NTP version 3
    NTPv4 = 4         // NTP version 4
};

/**
 * NTP Timestamp Format (64 bits)
 * NTP timestamp representation
 */
header ntp_timestamp {
    bit<32> seconds;   // Seconds since Jan 1, 1900
    bit<32> fraction;  // Fractional seconds
};

/**
 * NTP Header (48 bytes)
 * Basic NTP message header
 */
header ntp_header {
    bit<2> leap;                     // Leap indicator (ntp_leap)
    bit<3> version;                  // NTP version (ntp_version)
    bit<3> mode;                     // Mode (ntp_mode)
    bit<8> stratum;                  // Stratum level (1=primary, 2-15=secondary)
    bit<8> poll;                     // Poll interval (log2 seconds)
    bit<8> precision;                // Clock precision (log2 seconds)
    bit<32> root_delay;              // Roundtrip delay to reference clock
    bit<32> root_dispersion;         // Dispersion to reference clock
    bit<32> reference_id;            // Reference clock identifier
    // ntp_timestamp ref_timestamp;     // Reference timestamp  // (removed: nested header reference)
    // ntp_timestamp orig_timestamp;    // Originate timestamp  // (removed: nested header reference)
    // ntp_timestamp recv_timestamp;    // Receive timestamp  // (removed: nested header reference)
    // ntp_timestamp trans_timestamp;   // Transmit timestamp  // (removed: nested header reference)
};

/**
 * NTP Extension Fields
 * Optional extension fields
 */
header ntp_extension {
    bit<16> field_type;    // Extension field type
    bit<16> length;        // Length of extension
    varbit<1024> value;       // Extension value (variable length)
};

/**
 * NTP Authentication (20 bytes)
 * Optional authentication
 */
header ntp_auth {
    bit<16> key_id;       // Key identifier
    bit<16> digest_len;   // Digest length
    varbit<1024> digest;     // Message digest (variable length)
};

/**
 * NTP Kiss-o'-Death Codes
 * Special stratum 0 messages
 */
header ntp_kod {
    bit<32> code;       // ASCII KoD code
    varbit<1024> message;     // Optional message
};

/**
 * NTP Transport Header (UDP)
 */
header ntp_transport {
    bit<16> source_port;      // Source port (typically ephemeral)
    // bit<16> dest_port = 123;  // (pseudocode: field initializer removed)  // Destination port (123)
    bit<16> length;           // UDP length
    bit<16> checksum;         // UDP checksum
};

/**
 * P4 Parser Logic for NTP
 */
/*
parser ntp_parser(packet_in pkt, out headers hdr) {
    state start {
        pkt.extract(hdr.ntp_transport);
        transition select(hdr.ntp_transport.dest_port) {
            123: parse_ntp;
            default: accept;
        }
    }
    
    state parse_ntp {
        pkt.extract(hdr.ntp_header);
        transition select(hdr.ntp_header.mode) {
            CONTROL: parse_ntp_control;
            BROADCAST: parse_ntp_broadcast;
            default: parse_ntp_standard;
        }
    }
    
    state parse_ntp_standard {
        // Check for extensions or authentication
        if (hdr.ntp_header.version == NTPv4) {
            transition parse_ntp_extensions;
        } else {
            transition accept;
        }
    }
    
    // Additional parse states for NTP variants...
}
*/

/**
 * P4 Match-Action Pipeline for NTP
 */
/*
control ntp_control(inout headers hdr) {
    action process_client_request() {
        // Process NTP client request
        hdr.ntp_header.mode = SERVER;
        hdr.ntp_header.recv_timestamp = current_time();
        hdr.ntp_header.trans_timestamp = current_time();
        hdr.ntp_header.stratum = local_stratum;
        hdr.ntp_transport.dst_ip = hdr.ntp_transport.src_ip;
        hdr.ntp_header.checksum = calculate_checksum();
    }
    
    action adjust_clock_offset() {
        // Calculate clock offset from timestamps
        time_delay = (hdr.ntp_header.recv_timestamp - hdr.ntp_header.orig_timestamp) + (hdr.ntp_header.trans_timestamp - current_time());
        time_offset = (hdr.ntp_header.recv_timestamp - hdr.ntp_header.orig_timestamp) - (hdr.ntp_header.trans_timestamp - current_time());
        apply_clock_adjustment(time_offset / 2);
    }
    
    action send_kiss_code(code) {
        // Send KoD message
        hdr.ntp_header.stratum = 0;
        hdr.ntp_kod.code = code;
        hdr.ntp_header.mode = SERVER;
        hdr.ntp_transport.dst_ip = hdr.ntp_transport.src_ip;
    }
    
    table ntp_processing {
        key = {
            hdr.ntp_header.mode: exact;
            hdr.ntp_header.stratum: exact;
        }
        actions = {
            process_client_request;
            adjust_clock_offset;
            send_kiss_code;
            NoAction;
        }
        default_action = NoAction;
    }
    
    apply {
        ntp_processing.apply();
    }
}
*/
