/**
 * PTP (IEEE 1588) Header Definition in P4
 * Precision time protocol for clock synchronization
 */

/* PTP Message Types */
enum bit<8> ptp_message_type {
    SYNC                  = 0x0,
    DELAY_REQ             = 0x1,
    PDELAY_REQ            = 0x2,
    PDELAY_RESP           = 0x3,
    FOLLOW_UP             = 0x8,
    DELAY_RESP            = 0x9,
    PDELAY_RESP_FOLLOW_UP = 0xA,
    ANNOUNCE              = 0xB,
    SIGNALING             = 0xC,
    MANAGEMENT            = 0xD
}

/* PTP Transport Types */
enum bit<8> ptp_transport {
    UDP_IPv4   = 0x1,
    UDP_IPv6   = 0x2,
    IEEE_802_3 = 0x3,
    DEVICENET  = 0x4,
    CONTROLNET = 0x5,
    PROFINET   = 0x6
}

/**
 * PTP Common Header (34 bytes)
 */
header ptp_header {
    bit<4>  transportSpecific;    // Transport specific field
    bit<4>  messageType;          // From ptp_message_type enum
    bit<4>  reserved1;            // Must be 0
    bit<4>  versionPTP;           // PTP protocol version (2 for 1588v2)
    bit<16> messageLength;        // Total message length in bytes
    bit<8>  domainNumber;         // Clock domain number
    bit<8>  reserved2;            // Must be 0
    bit<16> flags;                // PTP message flags
    bit<64> correctionField;      // Correction for residence time
    bit<32> reserved3;            // Must be 0
    bit<80> sourcePortIdentity;   // Clock identity + port identity
    bit<16> sequenceId;           // Sequence number
    bit<8>  controlField;         // Depends on message type
    bit<8>  logMessageInterval;   // Logarithm of message period
}

/**
 * PTP Sync Message (Follow_Up has same structure)
 */
header ptp_sync {
    bit<48> originTimestamp;  // Timestamp from master clock
    bit<16> reserved;
}

/**
 * PTP Delay_Req Message
 */
header ptp_delay_req {
    bit<48> originTimestamp;  // When delay_req was sent
    bit<16> reserved;
}

/**
 * PTP Delay_Resp Message
 */
header ptp_delay_resp {
    bit<48> receiveTimestamp; // When delay_req was received
    bit<80> requestingPortIdentity; // Who sent the delay_req
    bit<16> reserved;
}

/**
 * PTP Announce Message
 */
header ptp_announce {
    bit<48> originTimestamp;
    bit<16> currentUtcOffset;
    bit<8>  grandmasterPriority1;
    bit<8>  grandmasterClockQuality;
    bit<8>  grandmasterPriority2;
    bit<80> grandmasterIdentity;
    bit<16> stepsRemoved;
    bit<8>  timeSource;
}

/**
 * PTP Signaling Message
 */
header ptp_signaling {
    bit<80> targetPortIdentity;
    bit<16> length;           // TLV length
    bit<16> reserved;
}

/**
 * PTP Management Message
 */
header ptp_management {
    bit<80> targetPortIdentity;
    bit<8>  startingBoundaryHops;
    bit<8>  boundaryHops;
    bit<8>  reserved1;
    bit<8>  flags;
    bit<16> length;           // TLV length
    bit<16> reserved2;
}

/**
 * PTP TLV Header
 */
header ptp_tlv {
    bit<16> tlvType;          // Type of TLV
    bit<16> length;           // Length of value field
}

/**
 * PTP Transport Header (UDP/IPv4)
 */
header ptp_transport_t {
    bit<16> sourcePort;       // Typically 319 for event messages
    bit<16> destPort;         // Typically 319 for event messages
    bit<16> length;           // UDP length
    bit<16> checksum;         // UDP checksum
    bit<32> sourceIP;         // IPv4 source address
    bit<32> destIP;           // IPv4 destination address
}

/**
 * PTP Clock Quality
 */
header ptp_clock_quality {
    bit<8>  clockClass;               // Clock class (6 for PRC, 7-10 for slave)
    bit<8>  clockAccuracy;            // See IEEE 1588-2008 Table 5
    bit<16> offsetScaledLogVariance;  // Clock stability metric
}

/**
 * P4 Parser Logic for PTP
 */
/*
parser ptp_parser(packet_in pkt, out headers hdr) {
    state start {
        pkt.extract(hdr.ptp_transport);
        transition select(hdr.ptp_transport.destPort) {
            319: parse_ptp;
            default: accept;
        }
    }
    
    state parse_ptp {
        pkt.extract(hdr.ptp_header);
        transition select(hdr.ptp_header.messageType) {
            SYNC: parse_sync;
            DELAY_REQ: parse_delay_req;
            DELAY_RESP: parse_delay_resp;
            FOLLOW_UP: parse_follow_up;
            ANNOUNCE: parse_announce;
            default: accept;
        }
    }
    
    // Additional parse states for each message type...
}
*/

/**
 * PTP Timestamp Format
 */
header ptp_timestamp {
    bit<48> seconds;          // Seconds since PTP epoch
    bit<32> nanoseconds;      // Nanoseconds portion
    bit<16> fractional_ns;    // Fractional nanoseconds
}

/**
 * PTP Path Trace TLV
 */
header ptp_path_trace {
    // bit<16> tlvType = 0x0008;  // (pseudocode: field initializer removed)  // Path trace TLV type
    bit<16> length;            // Length of path trace
    bit<128> pathSequence;  // Sequence of clock IDs
}

/**
 * PTP Clock Description TLV
 */
header ptp_clock_description {
    // bit<16> tlvType = 0x0009;  // (pseudocode: field initializer removed)
    bit<16> length;
    bit<80> clockIdentity;
    bit<8>  physicalLayerProtocol;
    bit<48> physicalAddress;
    bit<32> protocolAddress;
    bit<24> manufacturerIdentity;
    bit<160> productDescription;
    bit<160> revisionDescription;
    bit<160> userDescription;
}

/**
 * PTP Security TLV
 */
header ptp_security {
    // bit<16> tlvType = 0x000D;  // (pseudocode: field initializer removed)
    bit<16> length;
    bit<8>  securityModel;
    bit<256> keyIdentifier;
    bit<8>  securityOptions;
    bit<128> cryptographicValue;
}

/**
 * PTP Port Statistics TLV
 */
header ptp_port_stats {
    // bit<16> tlvType = 0x000E;  // (pseudocode: field initializer removed)
    bit<16> length;
    bit<64> rxMsgCount;
    bit<64> txMsgCount;
    bit<64> rxErrorCount;
    bit<64> txErrorCount;
    bit<64> rxDiscardCount;
    bit<64> txDiscardCount;
}

/**
 * P4 Match-Action Pipeline for PTP
 */
/*
control ptp_control(inout headers hdr) {
    action handle_sync() {
        // Process SYNC message
        hdr.ptp_header.correctionField = ...;
    }
    
    action handle_delay_req() {
        // Process DELAY_REQ message
        hdr.ptp_delay_resp.receiveTimestamp = ...;
    }
    
    table ptp_message_handling {
        key = {
            hdr.ptp_header.messageType: exact;
        }
        actions = {
            handle_sync;
            handle_delay_req;
            // Other handlers...
            NoAction;
        }
        default_action = NoAction;
    }
    
    apply {
        ptp_message_handling.apply();
    }
}
*/
