/* SNMP version enumeration */
enum bit<8> snmp_version {
    SNMPv1  = 0,    // SNMP version 1
    SNMPv2c = 1,    // SNMP version 2 community-based
    SNMPv3  = 2     // SNMP version 3 with security
}

/* SNMP PDU types */
enum bit<8> snmp_pdu_type {
    GET_REQUEST      = 0xA0,             // Manager to agent request
    GET_NEXT_REQUEST = 0xA1,             // Get next variable request
    GET_RESPONSE     = 0xA2,             // Agent to manager response
    SET_REQUEST      = 0xA3,             // Manager to agent set request
    TRAP             = 0xA4,             // Agent to manager trap (v1)
    GET_BULK_REQUEST = 0xA5,             // Get multiple variables (v2c/v3)
    INFORM_REQUEST   = 0xA6,             // Acknowledged trap (v2c/v3)
    SNMPv2_TRAP      = 0xA7              // Agent to manager trap (v2c/v3)
}

/* SNMP error status codes */
enum bit<8> snmp_error_status {
    NO_ERROR     = 0,       // No error occurred
    TOO_BIG      = 1,       // Response too big to transport
    NO_SUCH_NAME = 2,       // Variable not found
    BAD_VALUE    = 3,       // Invalid value in SET
    READ_ONLY    = 4,       // Attempt to write read-only var
    GEN_ERR      = 5        // Other error
}

/**
 * SNMP message header
 */
header snmp_message {
    bit<8>  version;          // SNMP protocol version
    bit<256> community;    // Community string for authentication
    bit<8>  pdu_type;         // Type of PDU (snmp_pdu_type)
    bit<32> request_id;       // Matches requests with responses
    bit<32> error_status;     // Error indication (snmp_error_status)
    bit<32> error_index;      // Points to problematic variable
}

/**
 * SNMP v3 security parameters
 */
header snmp_v3_security {
    bit<32> msg_id;           // Unique message ID
    bit<32> msg_max_size;     // Maximum supported message size
    bit<8>  msg_flags;        // Security flags
    bit<32> msg_security;     // Security model identifier
    bit<256> auth_engine;  // Authentication engine ID
    bit<96> auth_params;  // Authentication parameters
    bit<64> priv_params;   // Encryption parameters
}

/**
 * SNMP variable binding (VarBind)
 */
header snmp_varbind {
    bit<256> oid;         // Object identifier (OID)
    bit<8>  value_type;      // ASN.1 value type
    bit<16> value_length;    // Length of value field
    bit<2048> value;     // Actual value content
}

/**
 * SNMP Trap specific fields
 */
header snmp_trap {
    bit<256> enterprise;  // Vendor OID
    bit<32> agent_addr;      // Agent IP address
    bit<8>  generic_trap;    // Generic trap type
    bit<32> specific_trap;   // Specific trap code
    bit<32> time_stamp;      // Timestamp (sysUpTime)
}

/**
 * SNMP transport header (UDP)
 */
header snmp_transport {
    bit<16> source_port;    // Typically 161 (agent) or 162 (manager)
    bit<16> dest_port;      // Destination port number
    bit<16> length;         // UDP packet length
    bit<16> checksum;       // UDP checksum
}
