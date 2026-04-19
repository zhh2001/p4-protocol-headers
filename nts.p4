/**
 * NTS Header Definition in P4
 * Network Time Security for authenticated NTP
 * 网络时间安全协议
 */

/* NTS Record Types */
enum bit<8> nts_record {
    COOKIE    = 0,
    AEAD      = 1,
    NONCE     = 2,
    EXTENSION = 3,
};

/**
 * NTS Base Header (8 bytes)
 */
header nts {
    bit<16> src_port;        // Client port (ephemeral)
    // bit<16> dst_port = 123;  // (pseudocode: field initializer removed)  // NTP port
    bit<16> record_type;     // NTS record type (nts_record)
    bit<16> record_len;      // Record length
    varbit<1024> data;          // Encrypted record
};

/**
 * NTS Cookie (Variable length)
 */
header nts_cookie {
    bit<16> key_id;        // Key identifier
    bit<32> expiration;    // Cookie expiration
    varbit<1024> ciphertext;  // Encrypted cookie
};
