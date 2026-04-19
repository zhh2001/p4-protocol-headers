/**********************************************************
 * PFC Header (IEEE 802.1Qbb)                             
 * 基于优先级的流量控制报头 - 用于数据中心无损网络             
 * Priority-based Flow Control Header                      
 * Enables lossless transport for DC networks              
 **********************************************************/

header pfc_t {
    // ---- 基本控制字段 (4 字节) ----
    bit<3> priority_enable;  // Priority enable bitmap (per 802.1p priority)  启用的优先级位图 (每个 bit 对应802.1p优先级)
    bit<1> reserved;         // Reserved (must be 0)                          保留字段 (必须为 0)
    bit<4> time_value;       // Pause time units (×512 bit-times)             暂停时间单位 (单位×512比特时间)

    // ---- 每优先级控制字段 (8×2 字节) ----
    bit<128> class_pause;  // Per-class pause duration (0-65535)  各优先级的暂停时间 (0-65535)
    
    // ---- 增强型时间戳字段 (可选扩展) ----
    bit<32> timestamp;    // Precision timestamp (IEEE 1588 format)  精确时间戳 (IEEE 1588 格式)
    bit<8>  sync_domain;  // Clock synchronization domain            时间同步域标识
}
