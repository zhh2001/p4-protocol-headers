typedef bit<20> label_t;

// Segment Routing MPLS (SR-MPLS)  基于 MPLS 数据平面的分段路由实现
header srmpls_t {
    // MPLS 标签栈头部 (32 bits per label)
    // MPLS label stack entries
    label_t  label;            // 标签值（SRGB 偏移量）
    bit<3>   traffic_class;    // TC 字段（QoS 优先级）
    bit<1>   bottom_of_stack;  // 栈底标志
    bit<8>   ttl;              // 生存时间

    // SR-MPLS 扩展信息 (可选)
    bit<32>  sid;            // 段标识符（当 label=特殊值时）
    bit<8>   flags;          // 行为标志位：0x01=持久性 0x02=备份路径
    bit<24>  flow_tag;       // 流分类标记
}

// 特殊标签常量
const label_t SRGB_BASE     = 20w16000;    // 全局段基础值
const label_t EXPLICIT_NULL = 20w0;        // 显式空标签
const label_t IMPLICIT_NULL = 20w3;        // 隐式空标签

// SID 操作类型
const bit<8> SR_OP_CONTINUE = 0x1;  // 继续处理
const bit<8> SR_OP_INSERT   = 0x2;  // 插入新标签
const bit<8> SR_OP_REPLACE  = 0x3;  // 替换当前标签


// Example: 标签栈操作 (Pseudocode)
/*
action push_srmpls_label() {
    srmpls_t.label = SRGB_BASE + segment_id;
    srmpls_t.ttl = 8w64;
    srmpls_t.bottom_of_stack = (remaining_segments == 0);
}
*/

// Example: 路径编程 (Pseudocode)
/*
table srmpls_transit {
    key = {
        srmpls_t.label: exact;
    }
    actions = {
        swap_label; 
        php_action;
        drop;
    }
    size = 100000;
}
*/

// Example: 流量工程支持 (Pseudocode)
header srmpls_te_t {
    bit<32>  latency;      // 时延约束(μs)
    bit<32>  jitter;       // 抖动约束
    bit<8>   affinity;     // 链路亲和属性
}


// 与 SRv6 的互操作 (Pseudocode)
/*
action srmpls_to_srv6() {
    srv6_t.dst_addr = sid_to_ipv6(srmpls_t.label - SRGB_BASE);
    remove_mpls_header();
}
*/


/* ====== 典型工作流程 ====== */

// 1. 入口节点封装：(Pseudocode)
/*
action encapsulate_srmpls() {
    srmpls_t[0].label = 16001;  // Node SID
    srmpls_t[1].label = 16005;  // Adjacency SID
    srmpls_t[1].bottom_of_stack = 1;
}
*/

// 2. 中转节点处理：(Pseudocode)
/*
action swap_segment() {
    srmpls_t.label = next_label;
    srmpls_t.ttl = srmpls_t.ttl - 8w1;
    if (srmpls_t.label == IMPLICIT_NULL) {
        remove_mpls_header();
    }
}
*/

// 3. 倒数第二跳弹出：(Pseudocode)
/*
action penultimate_hop_pop() {
    if (srmpls_t[0].label == EXPLICIT_NULL) {
        srmpls_t[0].setInvalid();
    }
}
*/

// 4. 显式路径引导：(Pseudocode)
/*
action insert_adjacency_sid() {
    srmpls_t[0].flags |= 8w0x04;  // 显式路径标志
    srmpls_t[0].flow_tag = flow_hash;
}
*/
