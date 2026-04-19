typedef bit<2> protocol_t;
typedef bit<8> next_protocol_t;

// VXLAN-GPE (Generic Protocol Extension)  支持多协议封装的下一代数据中心 overlay 技术
header vxlan_gpe_t {
    // 基础 VXLAN 头部 (32 bits) - 继承标准 VXLAN 格式
    // Base VXLAN header (32 bits) - Inherits standard VXLAN
    bit<8>  flags;     // 标志位（保留字段）
    bit<24> vxlan_id;  // 24 位 VNI 网络标识符

    // GPE 扩展头部 - 新增协议扩展能力
    // GPE extension header - New capabilities
    bit<3>          version;        // 版本号（固定为 1）
    bit<1>          bypass;         // 绕过策略处理标志
    protocol_t      protocol;       // 封装协议类型：0=IPv4 1=IPv6 2=Ethernet 3=NSH
    bit<6>          reserved;       // 保留位（必须置 0）
    next_protocol_t next_protocol;  // 下一层协议类型
    bit<24>         metadata;       // 可选的元数据字段
}

// 协议类型常量定义 (RFC 8926)
const protocol_t VXLAN_GPE_IPV4     = 2w0x0;  // IPv4 封装
const protocol_t VXLAN_GPE_IPV6     = 2w0x1;  // IPv6 封装
const protocol_t VXLAN_GPE_ETHERNET = 2w0x2;  // 以太网封装
const protocol_t VXLAN_GPE_NSH      = 2w0x3;  // 服务链 NSH 封装

// 下一层协议常量
const next_protocol_t VXLAN_GPE_NEXT_IP   = 8w0x01;  // IP 协议
const next_protocol_t VXLAN_GPE_NEXT_GRE  = 8w0x02;  // GRE 协议
const next_protocol_t VXLAN_GPE_NEXT_MPLS = 8w0x03;  // MPLS 协议


/**
 * 关键增强特性
 *     1. 多协议支持：通过 protocol 字段实现 L2/L3/NSH 的统一封装
 *     2. 元数据通道：24 位 metadata 字段可携带业务链信息
 *     3. 策略旁路：bypass 位允许跳过中间设备处理
 *     4. 兼容设计：当 protocol=0 时完全兼容传统 VXLAN
 */


// Example: 携带服务链信息的 IPv6 封装 (Pseudocode)
/*
action encapsulate_vxlan_gpe_nsh() {
    vxlan_gpe.setValid();
    vxlan_gpe.version = 1;
    vxlan_gpe.protocol = VXLAN_GPE_NSH;
    vxlan_gpe.next_protocol = VXLAN_GPE_NEXT_IP;
    vxlan_gpe.metadata = 0xABCDEF;  // 服务路径 ID
}
*/

// Example: 传统以太网兼容模式 (Pseudocode)
/*
action encapsulate_vxlan_gpe_eth() {
    vxlan_gpe.setValid();
    vxlan_gpe.protocol = VXLAN_GPE_ETHERNET;
    vxlan_gpe.next_protocol = VXLAN_GPE_NEXT_IP;
}
*/