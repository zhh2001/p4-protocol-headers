/**********************************************************
 * CBS Header (IEEE 802.1Qav)                            
 * 基于信用的流量整形协议报头 - 实现突发流量控制与带宽保障          
 * Credit-Based Shaper Header                              
 * Manages burst traffic and ensures bandwidth allocation  
 **********************************************************/

header cbs_t {
    // ---- 信用控制字段 (4 字节) ----
    bit<8>  class_type;    // Traffic class (0=Class A,1=Class B)        流量类别 (0=Class A,1=Class B)
    bit<16> credit_value;  // Current credit value (dynamic adjustment)  当前信用值 (动态调整传输窗口)
    bit<8>  idle_slope;    // Idle slope (bandwidth allocation rate)     空闲斜率 (带宽分配速率，单位: Mbps)

    // ---- 队列状态字段 (4 字节) ----
    bit<16> send_slope;  // Send slope (port physical rate limit)  发送斜率 (端口物理速率限制)
    bit<8>  max_credit;  // Maximum credit threshold               最大信用阈值 (防止过度累积)
    bit<8>  reserved;    // Reserved field                         保留字段
}

// 信用动态计算逻辑 (Pseudocode)
/*
action update_credit() {
    // Class A 信用值在空闲时增长，发送时减少
    if (hdr.cbs.class_type == 0) {
        if (queue_empty) {
            hdr.cbs.credit_value += hdr.cbs.idle_slope * time_delta;
        } else {
            hdr.cbs.credit_value -= hdr.cbs.send_slope * frame_size;
        }
        // 信用值限制在 [-max_credit, +max_credit] 区间
        hdr.cbs.credit_value = clamp(hdr.cbs.credit_value, -hdr.cbs.max_credit, hdr.cbs.max_credit);
    }
}
*/

// 双队列调度机制 (Pseudocode)
/*
table class_based_scheduling {
    key = { hdr.vlan.pcp : exact; }
    actions = { assign_class_a, assign_class_b, drop }
    const entries = {
        6 -> assign_class_a;  // 语音控制等高优先级流量
        5 -> assign_class_b;  // 视频流等中等优先级
    }
}
*/
