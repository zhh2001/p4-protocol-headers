/**********************************************************
 * NVGRE Header (RFC 7637)
 * 基于GRE的网络虚拟化协议报头 - 数据中心 overlay 技术
 * Network Virtualization using GRE Header
 * Data center multi-tenancy overlay encapsulation
 **********************************************************/

header nvgre_t {
    bit<1>  c_flag;       // Checksum present (must be 0)  校验和标志 (必须为 0)
    bit<1>  reserved0;    // Reserved (must be 0)          保留位
    bit<1>  k_flag;       // Key present (must be 1)       密钥标志 (必须为 1)
    bit<1>  s_flag;       // Sequence present (must be 0)  序列号标志 (必须为 0)
    bit<9>  reserved1;    // Reserved                      保留位
    bit<3>  version;      // Version (must be 0)           版本号 (必须为 0)
    bit<16> protocol;     // Protocol type (0x6558=Ethernet) 协议类型 (0x6558=透明以太网桥接)
    bit<24> vsid;         // Virtual Subnet ID (tenant)    虚拟子网标识符 (租户标识)
    bit<8>  flow_id;      // Flow ID (entropy for ECMP)    流标识符 (ECMP 负载均衡熵值)
}

// 常用常量
const bit<16> NVGRE_PROTO_ETHERNET = 16w0x6558;  // 透明以太网桥接
const bit<16> NVGRE_PROTO_IPV4     = 16w0x0800;  // IPv4
const bit<16> NVGRE_PROTO_IPV6     = 16w0x86DD;  // IPv6
