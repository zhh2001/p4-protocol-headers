/**********************************************************
 * FRER Header (IEEE 802.1CB)                            
 * 帧复制消除协议报头 - 实现高可靠性冗余传输                  
 * Frame Replication and Elimination for Reliability      
 * Ensures zero packet loss in mission-critical networks  
 **********************************************************/

header frer_t {
    // ---- 冗余控制字段 (8 字节) ----
    bit<32> stream_id;        // Stream identifier (5-tuple hash)     流唯一标识符（基于五元组哈希）
    bit<16> sequence_num;     // Sequence number for ordering         序列号（防止乱序/重复）
    bit<8>  redundancy_mode;  // Redundancy path configuration        冗余模式（0=单路径, 1=双路径, 2=N路径）
    bit<8>  path_id;          // Path identifier (Primary/Secondary)  路径标识（区分主备路径）

    // ---- 故障检测字段 (4 字节) ----
    bit<24> crc_check;  // Fast CRC for error detection  快速 CRC 校验（用于即时错误检测）
    bit<8>  ttl;        // Time-to-live for redundancy   生存周期（限制冗余传播跳数）

    // ---- 消除决策字段 ----
    bit<1>  elimination_flag;  // Elimination decision flag        消除标记（1=需执行消除操作）
    bit<7>  reserved;          // Reserved for alignment           保留字段（对齐填充）
    bit<32> timestamp;         // Reception timestamp (IEEE 1588)  接收时间戳（用于消除决策）
}


// Example: 多路径复制逻辑 (Pseudocode)
/*
action replicate_frames() {
    if (hdr.frer.redundancy_mode >= 1) {
        // 主路径转发原始帧
        clone_packet(CloneType.I2E, 0);  
        // 冗余路径生成复制帧
        hdr.frer.path_id = 1;  // 标记为冗余路径
        hdr.frer.sequence_num = hdr.frer.sequence_num + 1;
        enqueue_to_secondary_port();
    }
}
*/

// Example: 消除决策机制 (Pseudocode)
/*
table elimination_decision {
    key = { 
        hdr.frer.stream_id : exact;
        hdr.frer.sequence_num : range;
    }
    actions = { keep_primary, keep_secondary, discard_duplicate }
    const entries = {
        0x12345678 && 100..200 -> keep_primary;  // 主路径优先
    }
}
*/

/**
 * 典型应用场景
 *   1. 车载制动系统冗余：通过 `redundancy_mode=2` 配置三重路径复制，ADAS 的紧急制动指令（StreamID=0xA5）在中央网关-左/右域控制器-执行器之间形成冗余三角传输，结合 `timestamp` 字段实现 10μs 内消除重复帧。
 *   2. 智能电网差动保护：在 IEC 61850 GOOSE 跳闸命令中，主路径（光纤）和备路径（电力线载波）的 `path_id` 标识差异，利用 `crc_check` 实现 20ns 级错误检测，保障变电站保护动作成功率>99.9999%。
 *   3. 5G前传网络容错：为 eCPRI 的 IQ 数据流配置N=4路径冗余，通过 `ttl=3` 限制跨基站传播，在 AAU 侧基于 FPGA 实现纳秒级消除决策，满足 3GPP 定义的 1e-9 误码率要求。
 *   4. 航空电子网络：在 AFDX 网络中替代传统双冗余架构，通过 `sequence_num` 字段实现 ARINC 664 Part7 兼容的确定性消除，减少 50% 的交换机缓存需求。
 */
