/**********************************************************
 * TimeSync Header (IEEE 802.1AS)                        
 * 时间同步协议报头 - 实现亚微秒级全网时钟对齐               
 * Generalized Precision Time Protocol (gPTP) Header     
 * Enables nanosecond-level network-wide synchronization  
 **********************************************************/

header gptp_t {
    // ---- 基础时间字段 (10 字节) ----
    bit<64> origin_timestamp;  // Origin timestamp (IEEE 1588)        源时钟时间戳（IEEE 1588 格式）
    bit<32> correction_field;  // Cumulative path delay compensation  路径延迟补偿值（皮秒级精度）

    // ---- 同步控制字段 (6 字节) ----
    bit<16> sequence_id;     // Sequence identifier           同步序列号（防重放攻击）
    bit<8>  domain_number;   // Clock domain identifier       时钟域编号（多域隔离）
    bit<8>  sync_interval;   // Synchronization interval      同步间隔（单位：2^ns）
    bit<16> grandmaster_id;  // Grandmaster clock identifier  主时钟节点标识（冗余切换用）
}


// Example: 透明时钟补偿逻辑 (Pseudocode)
/*
action transparent_clock() {
    // 计算本地驻留时间并更新修正字段
    ingress_time = get_current_time();
    residence_time = ingress_time - hdr.gptp.origin_timestamp;
    hdr.gptp.correction_field = hdr.gptp.correction_field + residence_time * clock_rate;
}
*/

// Example: 最佳主时钟算法 (Pseudocode)
/*
table bmc_algorithm {
    key = { hdr.gptp.grandmaster_id : exact; }
    actions = { select_grandmaster, backup_sync }
    const entries = {
        0xAA01 -> select_grandmaster;  // 主时钟优先级最高
    }
}
*/


/**
 * 典型应用场景
 *   1. 车载多域控制器同步: 在智能驾驶系统中，激光雷达点云（100ms 周期）与摄像头图像（33ms 周期）通过 `domain_number` 实现多时钟域隔离，同时通过 `correction_field` 补偿网关转发延迟，保障多传感器数据融合时戳对齐。
 *   2. 5G前传网络: 为满足 CPRI/eCPRI 的 ±65ns 同步要求，基站 AAU 通过 origin_timestamp 字段同步射频信号发射相位，结合 1588v2 透明时钟实现光纤链路不对称补偿。
 *   3. 工业机器人协作: 在 EtherCAT 与 TSN 混合网络中，机械臂关节控制器基于 `sync_interval` 动态调整运动控制周期（1ms→250μs），利用 `grandmaster_id` 实现主控 PLC 故障时的无扰切换。
 *   4. 电力差动保护系统: 智能变电站的合并单元（MU）通过 `sequence_id` 验证同步报文完整性，防范 GPS 欺骗攻击，满足 IEC 61850-9-2 的 1μs 同步精度要求。
 */
