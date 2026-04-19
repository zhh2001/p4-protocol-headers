/**
 * SMB Header Definition in P4
 * Server Message Block protocol for file/printer sharing
 */

/* SMB Command Codes */
enum bit<8> smb_command {
    NEGOTIATE     = 0x72,
    SESSION_SETUP = 0x73,
    TREE_CONNECT  = 0x75,
    CREATE        = 0xA2,
    READ          = 0x2E,
    WRITE         = 0x2F,
};

/**
 * SMB2 Header (64 bytes)
 */
header smb2 {
    // bit<32>  protocol_id = 32w0x424D53FE;  // (pseudocode: field initializer removed)  // 'SMB2' marker
    bit<16>  header_len;                   // Header length
    bit<16>  credit_charge;                // Flow control
    bit<32>  status;                       // Operation status
    bit<16>  command;                      // SMB command (smb_command)
    bit<16>  credit_req;                   // Credits requested
    bit<32>  flags;                        // Session flags
    bit<32>  next_command;                 // Chained commands
    bit<64>  message_id;                   // Async message ID
    bit<32>  pid;                          // Process ID
    bit<32>  tid;                          // Tree ID
    bit<64>  session_id;                   // Session ID
    bit<128> signature;                    // Message signature
};
