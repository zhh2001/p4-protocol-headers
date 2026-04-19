/**
 * SMTP Header Definition in P4
 * Simple Mail Transfer Protocol for email transmission
 */

/* SMTP Command Types */
enum bit<8> smtp_command {
    HELO = 0,  // Initiate session
    MAIL = 1,  // Sender specification
    RCPT = 2,  // Recipient specification
    DATA = 3,  // Message data start
    QUIT = 4,  // Terminate session  
};

/**
 * SMTP Header (16 bytes)
 */
header smtp {
    bit<16> src_port;       // Client port (ephemeral)
    // bit<16> dst_port = 25;  // (pseudocode: field initializer removed)  // SMTP server port
    bit<16> length;         // Command length
    bit<8>  command;        // SMTP command (smtp_command)
    bit<8>  status;         // Response status code
    bit<32> session_id;     // Session identifier
    bit<32> msg_size;       // Message size (bytes)
};
