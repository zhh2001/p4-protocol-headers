/**
 * Telnet Header Definition in P4
 * Protocol for bidirectional interactive text communication
 */

/* Telnet Command Codes */
enum bit<8> telnet_command {
    SE   = 240,  // Subnegotiation End
    NOP  = 241,  // No Operation
    DM   = 242,  // Data Mark
    BRK  = 243,  // Break
    IP   = 244,  // Interrupt Process
    AO   = 245,  // Abort Output
    AYT  = 246,  // Are You There
    EC   = 247,  // Erase Character
    EL   = 248,  // Erase Line
    GA   = 249,  // Go Ahead
    SB   = 250,  // Subnegotiation Begin
    WILL = 251,
    WONT = 252,
    DO   = 253,
    DONT = 254,
    IAC  = 255,  // Interpret As Command
};

/**
 * Telnet Header (8 bytes)
 */
header telnet {
    bit<16> src_port;       // Client port (ephemeral)
    // bit<16> dst_port = 23;  // (pseudocode: field initializer removed)  // Telnet server port
    bit<8>  command;        // Telnet command (telnet_command)
    bit<8>  option;         // Negotiation option
    bit<16> sub_len;        // Subnegotiation length
    varbit<1024> data;         // Payload data
};
