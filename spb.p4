typedef bit<16> etherType_t;
typedef bit<48> macAddr_t;
typedef bit<32> iSid_t;

// Shortest Path Bridging, IEEE 802.1aq  新一代数据中心和运营商级以太网的核心协议
header spb_t {
    // 协议标识 (16 bits) - 固定为 0x88A8
    // EtherType (16 bits) - Fixed to 0x88A8
    etherType_t  ether_type;

    // 控制标志 (8 bits) - 拓扑控制信息
    // Control flags (8 bits) - Topology control
    bit<1>       topology_change;  // 拓扑变化标志
    bit<1>       agreement_flag;   // 同步状态标志
    bit<6>       reserved_flags;   // 保留标志位

    // 协议版本 (8 bits) - 当前为 0x01
    // Version (8 bits) - Currently 0x01
    bit<8>       version;

    // 桥 ID (64 bits) - 系统标识符 + 优先级
    // Bridge ID (64 bits) - System ID + Priority
    bit<16>      bridge_priority;  // 桥优先级
    macAddr_t    system_id;        // 交换机 MAC 地址

    // 根路径开销 (32 bits) - 到根桥的累计开销
    // Root path cost (32 bits) - Cumulative cost
    bit<32>      root_path_cost;

    // 根桥 ID (64 bits) - 当前根桥标识
    // Root bridge ID (64 bits) - Current root
    bit<16>      root_priority;
    bit<48>      root_system_id;

    // IS-IS 协议字段 (可变长度) - 继承 IS-IS TLV
    // IS-IS fields (variable) - Extended from IS-IS
    varbit<1024> isis_fields;
}

// SPB 特定的 IS-IS TLV 扩展
header spb_isis_tlv_t {
    // SPB 实例 ID (16 bits) - 多实例标识
    // SPB Instance ID (16 bits) - Multi-instance
    bit<16>  instance_id;

    // VLAN 标识 (12 bits) - 关联的 VLAN ID
    // VLAN ID (12 bits) - Associated VLAN
    bit<12>  vlan_id;

    // 多拓扑 ID (16 bits) - 区分拓扑类型
    // Multi-topology ID (16 bits) - Topology type
    bit<16>  mt_id;

    // SPB 链路度量 (24 bits) - 链路开销
    // SPB Link metric (24 bits) - Path cost
    bit<24>  link_metric;

    // 服务标识 (32 bits) - I-SID 服务实例
    // Service ID (32 bits) - I-SID identifier
    iSid_t   i_sid;
}

// I-SID 服务类型常量
const iSid_t I_SID_DATA_PLANE    = 32w0x000001;   // 数据平面服务
const iSid_t I_SID_CONTROL_PLANE = 32w0x000002;  // 控制平面服务
const iSid_t I_SID_MCAST_VIDEO   = 32w0x000100;  // 组播视频服务


// 关键特性说明：
//     1. 多路径转发：基于 IS-IS 的 ECMP（等价多路径）支持
//     2. 服务实例标识：通过 24 位 I-SID 实现 L2 服务隔离
//     3. 快速收敛：继承 IS-IS 的亚秒级拓扑收敛能力
//     4. 向后兼容：可与传统 STP/RSTP 网络互通


// 典型工作流程：
//     1. 邻居发现：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action send_spb_hello() {
    spb.setValid();
    spb.topology_change = 1w0;
    spb.root_path_cost = 32w0;
    spb.bridge_priority = 16w0x8000;  // 默认优先级
}
*/
//     2. 拓扑计算：
//         - 使用 IS-IS LSDB 构建最短路径树
//         - 基于链路度量计算多路径转发
//     3. 服务注册：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action register_i_sid() {
    spb_isis_tlv.i_sid = 32w0x0000FF;  // 自定义服务ID
    spb_isis_tlv.link_metric = 24w10;  // 路径开销
}
*/
//     4. 拓扑计算：
//         - 根据 I-SID 进行服务实例映射
//         - 基于 VLAN + MAC + I-SID 三元组转发表
