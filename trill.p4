/**********************************************************
 * TRILL Header (RFC 6325)
 * 多链路透明互联协议报头 - 数据中心大二层路由
 * Transparent Interconnection of Lots of Links Header
 * L2 routing for data center networks
 **********************************************************/

header trill_t {
    bit<2>  version;        // Version (must be 0)           版本号 (必须为 0)
    bit<2>  reserved;       // Reserved                      保留位
    bit<1>  multi_dest;     // Multi-destination flag         多目的标志
    bit<5>  op_length;      // Options length (in 4-byte units) 选项长度 (4 字节为单位)
    bit<6>  hop_count;      // Hop count (TTL)               跳数 (TTL)
    bit<16> egress_rbridge; // Egress RBridge nickname        出口 RBridge 昵称
    bit<16> ingress_rbridge;// Ingress RBridge nickname       入口 RBridge 昵称
}

// TRILL EtherType
const bit<16> ETHERTYPE_TRILL = 16w0x22F3;   // TRILL 以太类型
const bit<16> ETHERTYPE_L2_IS_IS = 16w0x22F4; // L2 IS-IS 以太类型
