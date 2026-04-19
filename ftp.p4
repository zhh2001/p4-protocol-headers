/**
 * FTP Header Definition in P4
 * File Transfer Protocol for network file operations
 * 
 * Note: FTP uses separate control (port 21) and data (port 20) connections
 */

/* FTP Command Types */
enum bit<8> ftp_command {
    USER = 0,  // Authentication username
    PASS = 1,  // Authentication password
    LIST = 2,  // Directory listing
    RETR = 3,  // Retrieve file
    STOR = 4,  // Store file
    QUIT = 5,  // Terminate session
};

/**
 * FTP Control Header
 */
header ftp_control {
    bit<16> src_port;       // Client port (ephemeral)
    // bit<16> dst_port = 21;  // (pseudocode: field initializer removed)  // FTP control port
    bit<16> length;         // Command length
    bit<16> seq_num;        // Command sequence
    bit<8>  command;        // FTP command (ftp_command)
    varbit<1024> args;         // Command arguments
};

/**
 * FTP Data Header (12 bytes)
 */
header ftp_data {
    bit<16> src_port;     // Server data port (20 or ephemeral)
    bit<16> dst_port;     // Client data port
    bit<32> file_offset;  // File transfer position
    bit<16> block_size;   // Data block size
    bit<16> checksum;     // Block checksum
};
