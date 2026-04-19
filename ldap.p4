/**
 * LDAP Header Definition in P4
 * Lightweight Directory Access Protocol
 * 轻量级目录访问协议
 */

/* LDAP Message Types */
enum bit<8> ldap_message {
    BIND_REQUEST   = 0,
    BIND_RESPONSE  = 1,
    SEARCH_REQUEST = 3,
    SEARCH_ENTRY   = 4,
    MODIFY_REQUEST = 6,
};

/**
 * LDAP Header
 */
header ldap {
    bit<16> src_port;        // Client port (ephemeral)
    // bit<16> dst_port = 389;  // (pseudocode: field initializer removed)  // LDAP port
    bit<32> message_id;      // Message identifier
    bit<8>  message_type;    // LDAP message type (ldap_message)
    bit<24> length;          // Message length
    bit<8>  controls;        // Optional controls
};
