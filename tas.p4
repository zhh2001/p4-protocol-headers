/**********************************************************
 * TAS Header (IEEE 802.1Qbv)                            
 * 时间感知整形协议报头 - 用于 TSN 网络的时间敏感调度            
 * Time-Aware Shaper Header                                
 * Enables deterministic latency for time-sensitive traffic
 **********************************************************/

header tas_t {
    // ---- 基础控制字段 (4 字节) ----
    bit<1>  gate_state;  // Current gate state (1=Open, 0=Closed)  当前门控状态 (1=开, 0=关)
    bit<7>  time_aware;  // Time awareness flags                   时间感知标志位
    bit<32> cycle_time;  // Cycle time (nanosecond precision)      调度周期 (纳秒级精度)

    // ---- 门控列表条目 (每个 8 字节) ----
    bit<8>  operation;    // Operation type (0x01=Open, 0x02=Close)  操作类型 (0x01=开, 0x02=关)
    bit<32> time_offset;  // Time offset from cycle start            相对于周期开始的时间偏移
    bit<8>  priority;     // Traffic priority (802.1p)               适用的优先级 (802.1p)
    bit<8>  reserved;     // Reserved field                          保留字段

    // ---- 时间同步扩展 (8 字节) ----
    bit<64> sync_time;  // IEEE 1588 precision timestamp  IEEE 1588 精确时间戳
}
