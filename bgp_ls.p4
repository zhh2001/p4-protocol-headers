typedef bit<8> protocolId_t;
typedef bit<16> tlvType_t;
typedef bit<32> ip4Addr_t;

// BGP-LS (BGP Link-State)   将 IGP 拓扑信息通过 BGP 传播的关键协议，广泛应用于 SDN 控制器采集全网拓扑
header bgp_ls_t {
    // BGP 路径属性头部 (RFC 4271)
    // BGP Path Attribute Header
    bit<2>   flags;            // 可选/传递/部分标志
    bit<1>   extended_length;  // 使用 2 字节长度字段
    bit<5>   type_code;        // 属性类型代码
    
    // 属性长度 (16 bits) - 根据 extended_length 变化
    // Attribute length (varies)
    bit<16>  attr_length;
    
    // 链路状态 NLRI 类型 (8 bits) - 定义信息类型
    // LS NLRI Type (8 bits) - Information type
    bit<8>   ls_nlri_type;   // 1=节点 2=链路 3=前缀
    
    // 协议标识 (8 bits) - 原始协议类型
    // Protocol ID (8 bits) - Original protocol
    protocolId_t protocol_id;    // 1=IS-IS 2=OSPF 3=Direct
    
    // 实例标识 (64 bits) - 区分多实例
    // Instance ID (64 bits) - Multi-instance
    bit<64>  instance_id;
    
    // 节点描述符 (可变长度)
    // Node Descriptors (variable)
    // bgp_ls_node_desc_t node_desc;  // (removed: nested header reference)
    
    // 链路/前缀描述符 (可变长度)
    // Link/Prefix Descriptors
    varbit<2048> descriptors;
}

// 节点描述符 TLV 结构
header bgp_ls_node_desc_t {
    tlvType_t   tlv_type;    // 描述符类型
    bit<16>     tlv_length;  // 值长度
    varbit<512> tlv_value;   // 描述符值
}

// 常用 TLV 类型常量 (RFC 7752)
const tlvType_t BGP_LS_LOCAL_AS      = 16w512;  // 本地 AS 号
const tlvType_t BGP_LS_BGP_ROUTER_ID = 16w513;  // BGP 路由器 ID
const tlvType_t BGP_LS_IGP_ROUTER_ID = 16w514;  // IGP 路由器 ID
const tlvType_t BGP_LS_IPV4_ADDR     = 16w515;  // IPv4 地址
const tlvType_t BGP_LS_IPV6_ADDR     = 16w516;  // IPv6 地址

// 协议扩展常量
const protocolId_t BGP_LS_PROTO_OSPFv3 = 8w4;  // OSPFv3 支持
const protocolId_t BGP_LS_PROTO_BABEL  = 8w5;  // Babel 协议


// 关键特性说明：
//     1. 多协议支持：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action encode_isis_topology() {
    bgp_ls.protocol_id = 8w1;  // IS-IS
    bgp_ls.node_desc.tlv_type = BGP_LS_IGP_ROUTER_ID;
}
*/
//     2. 拓扑元素编码：( ↓↓↓ Example, Pseudocode ↓↓↓ )
header bgp_ls_link_tlv_t {
    bit<32>   local_node_id;   // 本地节点标识
    bit<32>   remote_node_id;  // 远端节点标识
    ip4Addr_t interface_addr;  // 接口 IPv4 地址
    ip4Addr_t neighbor_addr;   // 邻居 IPv4 地址
    bit<24>   te_metric;       // 流量工程度量
}
//     3. SDN集成：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action send_to_controller() {
    bgp_ls.ls_nlri_type = 1;  // 节点 NLRI
    bgp_ls.instance_id = 64w0x12345678;
}
*/


// 典型工作流程：
//     1. 拓扑采集：
//         - 路由器将 IGP 拓扑转换为 BGP-LS NLRI
//         - 通过 MP_REACH_NLRI 属性传播
//     2. 控制器同步：
/*
table bgp_ls_export {
    key = {
        igp_protocol: exact;
    }
    actions = {
        encode_bgp_ls;
        drop;
    }
    size = 3;
}
*/
//     3. 路径计算：
//         - 控制器基于全网拓扑计算跨域路径
//         - 通过 PCEP/BGP-SR 下发路径策略
