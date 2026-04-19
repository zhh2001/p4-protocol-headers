/**
 * NetBIOS Header Definition in P4
 * Network Basic Input/Output System
 * 网络基本输入输出系统
 */

/* NetBIOS Name Types */
enum bit<8> netbios_name {
    WORKSTATION    = 0x00,
    DOMAIN         = 0x1C,
    MASTER_BROWSER = 0x1D,
};

/**
 * NetBIOS Header (8 bytes)
 */
header netbios {
    bit<8>  msg_type;  // Message type
    bit<8>  flags;     // Operation flags
    bit<16> id;        // Transaction ID
    bit<16> qdcount;   // Question count
    bit<16> ancount;   // Answer count
    bit<16> nscount;   // Authority count
    bit<16> arcount;   // Additional count
};
