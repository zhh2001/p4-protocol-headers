typedef bit<8> protocol_t;

// Network Service Header  服务功能链(SFC)的核心封装协议，支持动态服务路径编排
header nsh_t {
    // 基础头部 (32 bits) - RFC 8300
    // Base header (32 bits)
    bit<2>     version;         // 版本号（固定为 0）
    bit<1>     o_bit;           // 开销计数器存在标志
    bit<1>     c_bit;           // 关键元数据标志
    bit<6>     reserved_flags;  // 保留标志位
    bit<6>     length;          // 头部总长度（单位 4 字节）
    bit<8>     md_type;         // 元数据类型：0x1=基础 0x2=扩展
    protocol_t next_protocol;   // 下层协议：0x1=IPv4 0x2=IPv6 0x3=Ethernet

    // 服务路径头部 (32 bits)
    // Service path header
    bit<32>  service_path;   // 服务路径标识符（高 24 位）+ 路径索引（低 8 位）

    // 上下文头部 (4×32 bits) - 关键元数据
    // Context headers
    bit<32>  context_1;      // 网络平台标识符
    bit<32>  context_2;      // 服务节点标识符  
    bit<32>  context_3;      // 流量分类标识
    bit<32>  context_4;      // 策略执行结果

    // 可变元数据 (可选)
    // Variable metadata
    varbit<512> metadata;
}

// 协议类型常量 (RFC 8300)
const protocol_t NSH_NEXT_IPV4  = 8w0x01;  // IPv4 协议
const protocol_t NSH_NEXT_IPV6  = 8w0x02;  // IPv6 协议
const protocol_t NSH_NEXT_ETHER = 8w0x03;  // 以太网帧
const protocol_t NSH_NEXT_NSH   = 8w0x04;  // 嵌套 NSH


// Example: 服务功能链动作 (Pseudocode)
/*
action add_service_chain() {
    nsh_t.setValid();
    nsh_t.service_path = 32w0x00ABCD01; // 路径 ID + 起始索引
    nsh_t.context_1 = 32w0x0A010101;  // 入口交换机 IP
    nsh_t.next_protocol = NSH_NEXT_IPV4;
}
*/

// Example: 元数据处理示例 (Pseudocode)
/*
action process_metadata() {
    if (nsh_t.md_type == 8w0x2) {  // 扩展元数据
        nsh_t.metadata = {qos_tag, tenant_id, flow_hash};
    }
}
*/


// 关键特性说明：
//     1. 动态路径控制：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
table service_forwarding {
    key = {
        nsh.service_path: exact;
    }
    actions = {
        forward_to_vfw;
        forward_to_ids;
        skip_next_hop;
    }
    size = 1024;
}
*/
//     2. 服务链编排：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action decrement_si() {
    nsh_t.service_path = nsh_t.service_path & 32w0xFFFFFF00 | (nsh_t.service_path & 32w0xFF) - 32w1;  // 索引减 1
}
*/
//     3. 多平台支持：( ↓↓↓ Example, Pseudocode ↓↓↓ )
const bit<32> PLATFORM_OPENSTACK  = 0x0A000001;
const bit<32> PLATFORM_KUBERNETES = 0x0A000002;


// 典型工作流程：
//     1. 分类器注入：
/*
action classify_traffic() {
    nsh_t.context_3 = ipv4.srcAddr & 32w0xFFFF0000;  // 基于源 IP 分类
}
*/
//     2. 服务跳转：
//         - 每经过一个服务节点，路径索引自动递减
//         - 根据当前索引值选择下一跳服务
//     3. 策略执行：
/*
action log_violation() {
    nsh_t.context_4 = 32w0x0000FF01;  // 标记安全违规
}
*/
//     4. 终结处理：
//         - 当路径索引为 0 时剥离 NSH 头部
//         - 恢复原始报文转发
