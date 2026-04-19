/**********************************************************
 * FP Header (IEEE 802.1Qbu)                             
 * 帧抢占协议报头 - 实现高优先级帧中断低优先级帧传输             
 * Frame Preemption Header                                 
 * Enables interruption of low-priority frames for urgent traffic 
 **********************************************************/

header fp_t {
    // ---- 抢占控制字段 (4 字节) ----
    bit<1>  preemptible;  // Preemption eligibility (1=Allow, 0=Deny)     可抢占标识 (1=允许被抢占, 0=不可抢占)
    bit<1>  fragmented;   // Fragmentation status (1=Fragment, 0=Intact)  分片标识 (1=分片帧, 0=完整帧)
    bit<6>  reserved;     // Reserved (must be 0)                         保留字段 (必须为 0)
    bit<24> fragment_id;  // Fragment sequence number for reassembly      分片序列号 (用于重组)

    // ---- 时间同步扩展字段 (8 字节) ----
    bit<64> preempt_time;  // Timestamp of preemption event  抢占发生时的时间戳 (IEEE 1588 格式)
}


// Example: 抢占决策逻辑 (Pseudocode)
/*
action check_preemption() {
    if (hdr.fp.preemptible && urgent_frame_available) {
        // 中断当前低优先级帧，插入高优先级帧
        truncate_current_frame();
        insert_express_frame();
        hdr.fp.fragmented = 1;  // 标记分片状态[3,4](@ref)
    }
}
*/

// Example: 分片重组机制 (Pseudocode)
/*
table fragment_reassembly {
    key = { hdr.fp.fragment_id : exact; }
    actions = { reassemble_frames, discard_fragment }
    const entries = {
        0x0 -> discard_fragment;  // 默认丢弃无效分片
    }
}
*/
