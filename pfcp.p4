typedef bit<16> ie_type_t;

// Packet Forwarding Control Protocol  5G核心网(5GC)中控制面与用户面分离(SBA)的核心协议
header pfcp_t {
    // 基础头部 (16 bits) - 3GPP TS 29.244
    // Base header (16 bits)
    bit<1>   s_bit;           // SEID 存在标志
    bit<1>   mp_bit;          // 消息优先级标志
    bit<6>   message_type;    // 消息类型：
                              //     1=Heartbeat
                              //     2=PFD Management
                              //     3=Association Setup
    bit<8>   message_length;  // 消息长度（不含头部）
    bit<64>  seid;            // 会话端点标识符（当 s_bit=1 时存在）

    // 序列号 (24 bits)
    bit<24>  seq_number;     // 事务标识符
    bit<8>   spare;          // 保留字段

    // 信息元素列表 (可变长度)
    // Information Elements
    varbit<4096> ies;
}

// 关键信息元素类型
header pfcp_ie_t {
    ie_type_t    ie_type;    // IE 类型代码
    bit<16>      ie_length;  // IE 值长度
    varbit<2048> ie_value;   // IE 实际值
}

// 常用 IE 类型常量
const ie_type_t PFCP_IE_NODE_ID  = 16w0x003C;  // 节点 ID
const ie_type_t PFCP_IE_F_SEID   = 16w0x0039;  // 远端 SEID
const ie_type_t PFCP_IE_PDR      = 16w0x0001;  // 包检测规则
const ie_type_t PFCP_IE_FAR      = 16w0x0002;  // 转发动作规则
const ie_type_t PFCP_IE_URR      = 16w0x0003;  // 用量报告规则


// Example: 会话管理 (Pseudocode)
/*
action create_session() {
    pfcp_t.message_type = 6w4;  // Session Establishment
    pfcp_t.s_bit = 1w1;
    pfcp_ie_t.ie_type = PFCP_IE_PDR;
}
*/

// Example: 规则编程 (Pseudocode)
header pfcp_pdr_t {
    bit<16>      pdr_id;      // 规则唯一标识
    bit<8>       precedence;  // 规则优先级
    bit<8>       pdi_count;   // 包检测信息数量
    varbit<1024> pdi;         // 检测字段（TEID/IP/端口等）
}

// Example: 5G QoS 映射 (Pseudocode)
header pfcp_qos_ie_t {
    bit<8>  qfi;           // QoS 流标识符
    bit<32> mbr_ul;        // 上行最大比特率
    bit<32> mbr_dl;        // 下行最大比特率
    bit<8>  arp_priority;  // 分配保留优先级
}


// 典型工作流程：
//     1. 节点发现：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action send_heartbeat() {
    pfcp_t.message_type = 6w1;
    pfcp_ie_t.ie_type = PFCP_IE_NODE_ID;
    pfcp_ie_t.ie_value = ipv4.src;
}
*/
//     2. 会话建立：
//         - SMF 发送 Session Establishment Request
//         - UPF 分配 SEID 并回复 Response
//     3. 规则下发：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
table apply_pdr {
    key = {
        pfcp_pdr_t.pdi: ternary;
    }
    actions = {
        forward_to_n6;
        buffer_packet;
    }
    size = 65536;
}
*/
//     4. 用量报告：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
meter usage_meter {
    type = bytes;
    result = pfcp_ie_t.ie_value;
    size = 1024;
}
*/
