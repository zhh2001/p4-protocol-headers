typedef bit<16> object_class_t;
typedef bit<32> ipv4_addr_t;

// Path Computation Element Protocol  SDN/光网络中用于集中式路径计算的关键协议
header pcep_t {
    // 版本标志 (8 bits) - 协议版本信息
    // Version flags (8 bits) - Protocol version
    bit<3> version;         // 当前版本 1
    bit<1> stateful;        // 状态化计算标志
    bit<1> trigger;         // 触发式更新标志  
    bit<1> lsp_update;      // LSP 更新能力标志
    bit<2> reserved_flags;

    // 消息类型 (8 bits) - 定义 PCEP 消息类型
    // Message type (8 bits) - PCEP message types
    bit<8> msg_type;  // 1=Open  2=Keepalive
                      // 3=PCReq 4=PCRep
                      // 5=PCErr 6=PCNtf
                      // 7=PCRpt 8=PCUpd

    // 消息长度 (16 bits) - 包含头部的总长度
    // Message length (16 bits) - Total length
    bit<16> msg_length;

    // 会话 ID (32 bits) - PCEP 会话标识符
    // Session ID (32 bits) - Session identifier
    bit<32> session_id;

    // 对象列表 (可变长度) - TLV 编码对象
    // Object list (variable) - TLV-encoded objects
    varbit<4096> objects;
}

// 常用对象类型 (RFC 5440)
header pcep_object_t {
    object_class_t object_class;     // 对象类别
    bit<4>         object_type;      // 对象类型
    bit<1>         processing_rule;  // 处理规则
    bit<1>         ignore;           // 忽略未知对象
    bit<10>        reserved;
    bit<16>        object_length;    // 对象长度
    varbit<2048>   object_value;
}

// 关键对象类型常量
const object_class_t PCEP_OPEN_OBJ      = 16w1;   // 会话参数
const object_class_t PCEP_RP_OBJ        = 16w2;   // 请求参数
const object_class_t PCEP_LSPA_OBJ      = 16w9;   // LSP 属性
const object_class_t PCEP_SVEC_OBJ      = 16w10;  // 同步向量
const object_class_t PCEP_BANDWIDTH_OBJ = 16w5;   // 带宽约束

// 状态化PCEP扩展 (RFC 8231)
header pcep_lsp_object_t {
    bit<32>  lsp_id;            // 网络范围内的 LSP ID
    bit<8>   operational;       // 操作状态
    bit<128> symbolic_name;     // LSP 符号名
    bit<32>  setup_priority;    // 建立优先级
    bit<32>  holding_priority;  // 保持优先级
}


// 关键特性说明：
//     1. 多模式支持：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action handle_stateful() {
    pcep_t.stateful = 1w1;  // 启用状态化模式
    pcep_t.lsp_update = 1w1;  // 允许 LSP 更新
}
*/
//     2. 路径请求处理：( ↓↓↓ Example, Pseudocode ↓↓↓ )
header pcep_req_object_t {
    bit<32>     request_id;    // 请求标识符
    ipv4_addr_t src_ip;        // 源地址
    ipv4_addr_t dst_ip;        // 目的地址
    bit<32>     constraints;   // 约束条件位图
}
//     3. SDN 集成示例：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action send_path_request() {
    pcep_t.msg_type = 8w3;  // PCReq
    pcep_req_object.constraints = 32w0x01;  // 最小跳数
}
*/


// 典型工作流程：
//     1. 会话建立：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action establish_session() {
    pcep_t.msg_type = 8w1;  // Open
    pcep_object.object_class = PCEP_OPEN_OBJ;
}
*/
//     2. 路径计算请求：
//         - PCC 发送 PCReq 消息携带：
//             - RP 对象（请求参数）
//             - END-POINTS 对象（端点）
//             - BANDWIDTH 对象（带宽需求）
//     3. 路径计算响应：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action send_path_reply() {
    pcep_t.msg_type = 8w4;  // PCRep
    pcep_object.object_class = PCEP_BANDWIDTH_OBJ;
}
*/
//     4. 状态同步：
//         - 使用 PCRpt 消息报告 LSP 状态
//         - 通过 PCUpd 消息下发路径更新
