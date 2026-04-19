// GTP-U (GPRS Tunneling Protocol User Plane)  4G/5G移动网络中的核心用户面封装协议
header gtp_u_t {
    // 基础头部 - 3GPP TS 29.281
    // Base header
    bit<1>   pn_bit;         // N-PDU 编号存在标志
    bit<1>   s_bit;          // 序列号存在标志
    bit<1>   e_bit;          // 扩展头部标志
    bit<1>   spare;          // 保留位
    bit<4>   message_type;   // 消息类型（固定为 0xFF）
    bit<16>  length;         // 载荷长度（不含头部）
    bit<32>  teid;           // 隧道端点标识符

    // 可选字段 (0-64 bits)
    bit<16>  seq_number;     // 序列号（当 s_bit=1 时存在）
    bit<8>   n_pdu_number;   // N-PDU 编号（当 pn_bit=1 时存在）
    bit<8>   next_ext_type;  // 下一扩展类型（当 e_bit=1 时存在）

    // 扩展头部 (可变长度)
    varbit<512> extensions;
}

// 扩展头部类型常量
const bit<8> GTP_EXT_PDU_SESSION = 0x85;  // 5G PDU 会话容器
const bit<8> GTP_EXT_QOS_FLOW    = 0x86;  // QoS 流标识符
const bit<8> GTP_EXT_UP_MARKER   = 0x87;  // 用户面标记

// 5G 专用字段
header gtp_u_5gc_t {
    bit<8>   pdu_type;       // 0x1=IPv4 0x2=IPv6 0x3=Ethernet
    bit<8>   qfi;            // QoS 流标识符（6 bits）
    bit<16>  rqi;            // 反射 QoS 标识
    bit<32>  ul_teid;        // 上行 TEID
}


// Example: 移动性管理 (Pseudocode)
/*
action set_teid() {
    gtp_u_t.teid = (ue_id << 16) | bearer_id;
    gtp_u_t.s_bit = 1w1;  // 启用序列号
}
*/

// Example: 5G 集成 (Pseudocode)
/*
action add_5gc_extension() {
    gtp_u_t.e_bit = 1w1;
    gtp_u_5gc_t.qfi = (dscp >> 2) & 0x3F;  // 转换 DSCP 到 QFI
}
*/

// Example: 负载均衡 (Pseudocode)
/*
table gtp_load_balancing {
    key = {
        gtp_u.teid: exact;
    }
    actions = {
        forward_to_upf1;
        forward_to_upf2;
    }
    size = 65536;
}
*/


// 典型工作流程：
//     1. 隧道建立：
//         - SMF 分配 TEID 并通过 N4 接口下发
//         - UPF 编程 P4 转发表项
//     2. 数据转发：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action encapsulate_gtp() {
    gtp_u_t.setValid();
    gtp_u_t.message_type = 0xFF;
    gtp_u_t.length = inner_ipv4.totalLen;
}
*/
//     3. QoS 执行：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
meter qos_meter {
    type = packets;
    result = gtp_u_5gc_t.qfi;
    size = 64;
}
*/
//     4. 路径切换：
//         - 通过扩展头携带 N3/N9 隧道信息
//         - 支持 End Marker 标记包
