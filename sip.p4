/**
 * SIP Header Definition in P4
 * Session Initiation Protocol for VoIP
 */

/* SIP Methods */
enum bit<8> sip_method {
    INVITE   = 0,
    ACK      = 1,
    BYE      = 2,
    REGISTER = 3,
};

/**
 * SIP Base Header
 */
header sip {
    bit<16> src_port;         // Client port (5060 or ephemeral)
    // bit<16> dst_port = 5060;  // (pseudocode: field initializer removed)  // SIP port
    bit<32> call_id;          // Call identifier
    bit<8>  method;           // SIP method (sip_method)
    bit<8>  cseq;             // Command sequence
    bit<16> max_forwards;     // Hop count
    varbit<1024> via;             // Via headers
    varbit<1024> from;            // From header
    varbit<1024> to;              // To header
};
