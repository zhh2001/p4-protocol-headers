/**
 * RADIUS Header Definition in P4
 * Remote Authentication Dial-In User Service
 * 远程认证拨号用户服务
 */

/* RADIUS Attribute Types */
enum bit<8> radius_attr {
    USER_NAME      = 1,
    USER_PASSWORD  = 2,
    NAS_IP_ADDRESS = 4,
    REPLY_MESSAGE  = 18,
};

/**
 * RADIUS Header (20 bytes)
 */
header radius {
    bit<8>   code;           // Packet type (1=Access-Request)
    bit<8>   identifier;     // Request identifier
    bit<16>  length;         // Packet length
    bit<128> authenticator;  // Request authenticator
    varbit<1024> attributes;   // Attribute list
};
