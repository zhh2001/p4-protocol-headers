typedef bit<24> segment_flag_t;

// BGP-SR (BGP Segment Routing Extensions)  实现跨域 SR 策略分发的关键协议
header bgp_sr_t {
    // BGP 路径属性头部 (RFC 4271)
    bit<2>   flags;            // 可选/传递/部分标志
    bit<1>   extended_length;  // 扩展长度标志
    bit<5>   type_code;        // 属性类型 = 40 (SR Policy)

    // SR 策略属性 (RFC 9252)
    bit<16>  policy_type;    // 策略类型：
                             //     1 = 候选路径
                             //     2 = 偏好策略
    bit<32>  distinguisher;  // 策略标识符
    bit<32>  color;          // 策略颜色（应用标识）
    bit<128> endpoint;       // 策略终点地址

    // 段列表 (可变长度)
    bit<8>         segment_type;   // 段类型：
                                   //     1 = 节点 SID
                                   //     2 = 邻接 SID
                                   //     3 = 绑定 SID
    segment_flag_t segment_flags;  // 段属性标志
    varbit<1024>   segments;       // 段标识列表

    // 策略 TLV (可选)
    varbit<2048> tlvs;
}

// 策略 TLV 类型
const bit<16> BGP_SR_PREFERENCE = 16w0x01;  // 路径偏好
const bit<16> BGP_SR_PRIORITY   = 16w0x02;  // 路径优先级
const bit<16> BGP_SR_BFD        = 16w0x03;  // BFD 检测参数

// 段标志位定义
const segment_flag_t SR_SEG_WEIGHTED  = 24w0x000001;  // 加权负载均衡
const segment_flag_t SR_SEG_PROTECTED = 24w0x000002;  // 保护路径


// Example: 跨域策略分发 (Pseudocode)
/*
action advertise_sr_policy() {
    bgp_sr_t.policy_type = 16w1;  // 候选路径
    bgp_sr_t.segment_type = 8w1;  // 节点 SID
    bgp_sr_t.segments = {16001, 16005};
}
*/

// Example: 业务链编程 (Pseudocode)
header bgp_sr_service_t {
    bit<16>  app_id;       // 应用标识
    bit<32>  sla_profile;  // SLA 模板 ID
    bit<128> service_sid;  // 服务链 SID
}

// Example: 路径优化 (Pseudocode)
/*
table sr_policy_selection {
    key = {
        bgp_sr_t.color: exact;
        ipv4.dst: ternary;
    }
    actions = {
        use_primary_path;
        use_backup_path;
    }
    size = 100000;
}
*/


// 与 PCEP-SR 的协同：(Pseudocode)
/*
action import_pcep_path() {
    bgp_sr_t.segments = pcep_sr_t.sid_list;
    bgp_sr_t.policy_type = 16w2;  // 标记为 PCEP 计算路径
}
*/
