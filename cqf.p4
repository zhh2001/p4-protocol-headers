/**********************************************************
 * CQF Header (IEEE 802.1Qch)                            
 * 周期性排队与转发协议报头 - 实现无冲突的确定性传输             
 * Cyclic Queuing and Forwarding Header                    
 * Enables collision-free deterministic forwarding          
 **********************************************************/

header cqf_t {
    // ---- 基础调度字段 ----
    bit<32> cycle_id;      // Cycle identifier (synchronized network-wide)   周期标识符 (全网同步的周期计数)
    bit<16> ingress_time;  // Ingress timestamp (synchronized clock offset)  入队时间戳 (基于同步时钟的偏移量)
    bit<8>  queue_depth;   // Current queue depth (dynamic buffer control)   当前队列深度 (动态调整缓冲区)

    // ---- 增强型同步字段 ----
    bit<64> sync_epoch;  // Synchronization epoch start (IEEE 1588)  同步周期起点 (IEEE 1588 格式)
    bit<8>  hop_count;   // Hop count limit (anti-looping)           跳数限制 (防止循环转发)
    bit<8>  reserved;    // Reserved field                           保留字段
}
