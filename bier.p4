/**********************************************************
 * BIER Header (RFC 8279)
 * 位索引显式复制协议报头 - 新一代高效组播转发
 * Bit Index Explicit Replication Header
 * Efficient stateless multicast forwarding
 **********************************************************/

header bier_t {
    bit<4>   bift_id_high;  // BIER forwarding table ID (high bits) BIFT 标识符 (高位)
    bit<2>   version;       // Version (must be 0)                  版本号 (必须为 0)
    bit<2>   bsl;           // BitString length encoding            位串长度编码
    bit<20>  entropy;       // Entropy for ECMP load balancing      ECMP 熵值
    bit<1>   oam;           // OAM flag                             OAM 标志位
    bit<1>   rsv;           // Reserved                             保留位
    bit<1>   dscp_flag;     // DSCP flag                            DSCP 标志
    bit<6>   dscp;          // Differentiated Services Code Point   差分服务代码点
    bit<8>   proto;         // Next protocol                        下层协议
    bit<16>  bfr_id_src;    // Source BFR-id                        源 BFR 标识符
    bit<256> bitstring;     // BitString (256-bit default)          位串 (默认 256 位)
}

// BIER 下层协议常量
const bit<8> BIER_PROTO_MPLS_DOWN = 8w1;   // MPLS downstream
const bit<8> BIER_PROTO_MPLS_UP   = 8w2;   // MPLS upstream
const bit<8> BIER_PROTO_ETHERNET  = 8w3;   // Ethernet
const bit<8> BIER_PROTO_IPV4      = 8w4;   // IPv4
const bit<8> BIER_PROTO_IPV6      = 8w5;   // IPv6
const bit<8> BIER_PROTO_OAM       = 8w6;   // BIER OAM

// BitString 长度编码常量
const bit<2> BIER_BSL_64   = 2w0;  // 64-bit BitString
const bit<2> BIER_BSL_128  = 2w1;  // 128-bit BitString
const bit<2> BIER_BSL_256  = 2w2;  // 256-bit BitString
const bit<2> BIER_BSL_512  = 2w3;  // 512-bit BitString
