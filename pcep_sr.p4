// PCEP-SR (Path Computation Element Protocol for Segment Routing)  集中式 SR 路径计算的关键控制协议
header pcep_sr_t {
    // PCEP 公共头部 (RFC 5440)
    bit<3>   version;        // 固定为 1
    bit<1>   stateful;       // 状态化标志
    bit<1>   sr_capable;     // SR 能力标志
    bit<3>   reserved_flags;
    bit<8>   msg_type;       // 消息类型扩展：
                             //     10 = SR Path Computation Request
                             //     11 = SR Path Computation Reply
    bit<16>  msg_length;     // 包含 SRP/PCECP 的扩展长度

    // SR 特定对象 (RFC 8664)
    bit<16>  object_class;   // 对象类别：
                             //     36 = SR-ERO (Explicit Route Object)
                             //     37 = SR-RRO (Record Route Object)
    bit<8>   object_type;    // 对象类型：
                             //     1 = SR-IPv6
                             //     2 = SR-MPLS
    bit<16>  object_length;  // 对象总长度

    // SR 路径段列表 (可变长度)
    bit<8>   sid_type;       // SID 类型：
                             //     1 = IPv6 SID
                             //     2 = MPLS Label SID
                             //     3 = Adjacency SID
    bit<24>  flags;          // 路径属性标志
    varbit<2048> sid_list;   // SID 序列
}

// SR 策略 TLV 定义
header pcep_sr_policy_t {
    bit<16>      tlv_type;       // 策略 TLV 类型：
                                 //     1 = 候选路径
                                 //     2 = 偏好值
                                 //     3 = 策略名称
    bit<16>      tlv_length;
    varbit<1024> tlv_value;      // 策略参数
}

// 关键常量定义
const bit<8> SR_SID_IPV6     = 8w0x01;  // IPv6 SID
const bit<8> SR_SID_MPLS     = 8w0x02;  // MPLS 标签 SID
const bit<8> SR_BEHAVIOR_END = 8w0x01;  // 端点行为
const bit<8> SR_BEHAVIOR_X   = 8w0x02;  // 跨连接行为


// Example: 多域路径计算 (Pseudocode)
/*
action add_inter_domain_sid() {
    pcep_sr_t.sid_type = SR_SID_IPV6;
    pcep_sr_t.sid_list = {domain1_border_sid, domain2_entry_sid};
}
*/

// Example: 策略下发 (Pseudocode)
/*
action create_sr_policy() {
    pcep_sr_policy_t.tlv_type = 16w1;  // 候选路径
    pcep_sr_policy_t.tlv_value = {primary_path, backup_path};
}
*/

// Example: 实时优化 (Pseudocode)
header pcep_sr_metric_t {
    bit<8>   metric_type;    // 1=时延 2=带宽 3=跳数
    bit<24>  threshold;      // 优化阈值
    bit<32>  current_value;  // 当前度量值
}


// 与 BGP-LS 的集成：(Pseudocode)
/*
action import_bgpls_topology() {
    pcep_sr_t.sid_list = bgpls_sid;
    pcep_sr_t.flags |= 24w0x01;  // 标记为 BGP-LS 学习路径
}
*/


/* ====== 典型工作流程 ====== */

// 1. 路径请求：(Pseudocode)
/*
action send_sr_request() {
    pcep_sr_t.msg_type = 8w10;
    pcep_sr_t.object_class = 16w36;  // SR-ERO
    pcep_sr_t.sid_type = SR_SID_MPLS;
}
*/

// 2. 路径计算：
//     - PCE 根据拓扑数据库计算 SR 路径
//     - 考虑 TE 约束（带宽/时延/亲和力）

// 3. 路径响应：(Pseudocode)
/*
action encode_sr_path() {
    pcep_sr_t.sid_list = {16001, 16005, 16009};
    pcep_sr_policy_t.tlv_type = 16w2;  // 偏好值
    pcep_sr_policy_t.tlv_value = 100;
}
*/

// 4. 状态同步：(Pseudocode)
/*
action report_sr_state() {
    pcep_sr_t.msg_type = 8w7;  // PCRpt
    pcep_sr_t.object_class = 16w37;  // SR-RRO
}
*/
