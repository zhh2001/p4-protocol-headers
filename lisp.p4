typedef bit<8>   packetType_t;
typedef bit<32>  ip4Addr_t;
typedef bit<128> ip6Addr_t;

// Locator/ID Separation Protocol  实现网络虚拟化和多宿主连接的下一代互联网架构协议
header lisp_t {
    // 控制位 (8 bits) - 报文类型标志
    // Flags (8 bits) - Packet type indicators
    bit<1>   nonce_present;  // 随机数存在标志
    bit<1>   lsb_present;    // 本地状态位存在
    bit<1>   map_version_present; // 映射版本存在
    bit<5>   reserved_flags; // 保留标志位

    // 报文类型 (8 bits) - 定义LISP消息类型
    // Type (8 bits) - LISP message type
    packetType_t   packet_type;

    // 随机数 (32 bits) - 防重放攻击
    // Nonce (32 bits) - Anti-replay protection
    bit<32>  nonce;

    // 映射版本 (32 bits) - EID-RLOC映射版本号
    // Map Version (32 bits) - EID-RLOC mapping version
    bit<32>  map_version;

    // 源/目的 EID (各128 bits) - 终端标识符
    // Source/Destination EID (128 bits each)
    bit<128> source_eid;
    bit<128> dest_eid;

    // 控制消息负载 (可变长度)
    // Control message payload (variable)
    varbit<1024> payload;
}

// LISP报文类型常量 (RFC 6830)
const packetType_t LISP_MAP_REQUEST  = 8w0x01;  // 映射请求
const packetType_t LISP_MAP_REPLY    = 8w0x02;  // 映射响应
const packetType_t LISP_MAP_REGISTER = 8w0x03;  // 映射注册
const packetType_t LISP_MAP_NOTIFY   = 8w0x04;  // 映射通知
const packetType_t LISP_ENCAPSULATED = 8w0x08;  // 数据封装包

// LISP 数据封装头部
header lisp_encap_t {
    // 外部头部的 RLOC 地址 (各 32/128 bits)
    // RLOC addresses in outer header
    ip4Addr_t source_rloc_ipv4;
    ip4Addr_t dest_rloc_ipv4;
    // 或使用 IPv6 RLOC:
    // ip6Addr_t source_rloc_ipv6;
    // ip6Addr_t dest_rloc_ipv6;

    // 实例 ID (32 bits) - 多租户隔离标识
    // Instance ID (32 bits) - Multi-tenancy
    bit<32> instance_id;

    // 内部头部的 EID 地址 (各 32/128 bits)
    // EID addresses in inner header
    ip4Addr_t inner_source_eid_ipv4;
    ip4Addr_t inner_dest_eid_ipv4;
    // 或使用 IPv6 EID:
    // ip6Addr_t inner_source_eid_ipv6;
    // ip6Addr_t inner_dest_eid_ipv6;
}


// 关键组件说明：
//     1. EID-RLOC 分离：
//         - EID（Endpoint ID）标识终端设备
//         - RLOC（Routing Locator）标识网络位置
//     2. 映射系统：( ↓ Example ↓ )
header lisp_map_record_t {
    bit<32>  record_ttl;     // 记录有效期(分钟)
    bit<8>   locator_count;  // RLOC 地址数量
    bit<16>  eid_mask_len;   // EID 前缀长度
    bit<128> eid_prefix;     // EID 前缀
    // rloc_entry_t[16] rlocs;  // RLOC 地址列表  // (removed: nested header reference)
}
//     3. 流量工程支持：( ↓ Example ↓ )
header rloc_entry_t {
    bit<8>   priority;      // 路由优先级
    bit<8>   weight;        // 负载均衡权重
    bit<32>  mtu;           // 路径 MTU 值
    bit<128> rloc_address;  // RLOC 地址
}


// 典型工作流程：
//     1. 初始通信：
//         - ITR（Ingress Tunnel Router）发送 Map-Request
//         - ETR（Egress Tunnel Router）返回 Map-Reply
//     2. 数据封装：( ↓ Example ↓ )
/*
action lisp_encapsulate() {
    lisp_encap.setValid();
    lisp_encap.instance_id = 32w0x12345678;
    lisp_encap.source_rloc_ipv4 = 32w0x0A010101;  // ITR RLOC
    lisp_encap.dest_rloc_ipv4 = 32w0x0B020202;    // ETR RLOC
}
*/
//     3. 移动性处理：
//         - 当终端移动时更新 EID-RLOC 映射
//         - 通过 Map-Notify 同步映射变更
