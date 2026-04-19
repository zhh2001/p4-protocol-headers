/**********************************************************
 * PSFP Header (IEEE 802.1Qci)                           
 * 流过滤与监管协议报头 - 实现粒度化流量控制与安全隔离            
 * Per-Stream Filtering and Policing Header                
 * Enables micro-segmentation and deterministic QoS        
 **********************************************************/

header psfp_t {
    // ---- 流标识字段 ----
    bit<48> stream_id;  // Stream identifier (MAC+VLAN+IP 5-tuple hash)  流唯一标识符 (MAC+VLAN+IP五元组哈希)
    bit<8>  flow_type;  // Flow characteristic type                      流量类型 (0=周期型，1=事件型，2=尽力而为)

    // ---- 监管参数字段 ----
    bit<32> max_burst;   // Maximum burst size (bytes)  最大突发量 (单位: 字节)
    bit<16> interval;    // Policing interval (μs)      监管周期 (单位: 微秒)
    bit<8>  color_mode;  // Color marking mode          标记模式 (0=双色, 1=三色)

    // ---- 安全隔离字段 ----
    bit<24> isolation_group;   // Network slicing group ID    隔离组标识 (用于虚拟化网络切片)
    bit<8>  drop_eligibility;  // Drop eligibility indicator  丢弃优先级 (0=保护级, 1=可丢弃)
}

// Example: 令牌桶监管逻辑 (Pseudocode)
/*
action psfp_policing() {
    // 基于双色标记的令牌桶算法
    if (hdr.psfp.flow_type == 0) {  // 周期型流量
        token_bucket = hdr.psfp.max_burst * elapsed_time / hdr.psfp.interval;
        if (packet_size > token_bucket) {
            hdr.psfp.drop_eligibility = 1;  // 标记为可丢弃
        }
    }
}
*/

// Example: 动态流过滤机制 (Pseudocode)
/*
table dynamic_filtering {
    key = { 
        hdr.eth.src_addr : ternary; 
        hdr.ipv4.dst_addr : range;
    }
    actions = { allow_with_policing, redirect_to_quarantine, drop }
    const entries = {
        0x0/0x0 && 10.0.0.0/24 -> allow_with_policing;        // 放行生产域流量
        0x0/0x0 && 192.168.1.0/28 -> redirect_to_quarantine;  // 隔离可疑流量
    }
}
*/
