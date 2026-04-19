// SRv6 (Segment Routing over IPv6)  新一代 IP 网络的核心可编程协议
header srv6_t {
    // IPv6 基础头部 (40 bytes)
    // IPv6 base header
    bit<4>    version;       // 固定为 6
    bit<8>    traffic_class; // DSCP + ECN
    bit<20>   flow_label;    // 流标签
    bit<16>   payload_len;   // 扩展头后的长度
    bit<8>    next_header;   // 下一个头部类型
    bit<8>    hop_limit;     // 跳数限制
    bit<128>  src_addr;      // 源地址（含 SRv6 SID）
    bit<128>  dst_addr;      // 目的地址（当前段标识）

    // SRv6 扩展头部 (RFC 8986)
    // SRH (Segment Routing Header)
    bit<8>    routing_type;   // 路由类型（固定为 4）
    bit<8>    segments_left;  // 剩余段数
    bit<8>    last_entry;     // 最后有效段索引
    bit<8>    flags;          // 标志位
    bit<16>   tag;            // 分组标记
    bit<1280> segments;   // 段列表（最多 10 段）

    // 可选的 TLV 编码
    varbit<512> tlvs;
}

// SRv6 SID 功能常量
const bit<16> SRV6_END     = 16w0x0001;  // 普通端点
const bit<16> SRV6_END_X   = 16w0x0002;  // 跨层端点
const bit<16> SRV6_END_T   = 16w0x0003;  // 特定流表端点
const bit<16> SRV6_END_DT4 = 16w0x0004;  // IPv4 解封装端点

// 行为标志位
const bit<8> SRV6_FLAG_PSP = 8w0x01;    // 倒数第二跳弹出
const bit<8> SRV6_FLAG_USD = 8w0x02;    // 显式空 SID


// Example: 可编程路径 (Pseudocode)
/*
action add_srv6_segment() {
    srv6_t.segments_left = srv6_t.segments_left + 8w1;
    srv6_t.segments[last_entry+1] = next_sid;
}
*/

// Example: 网络编程 (Pseudocode)
/*
table srv6_endpoint {
    key = {
        srv6_t.dst_addr: exact;
    }
    actions = {
        end_action;
        end_x_action;
        end_t_action;
    }
    size = 65536;
}
*/

// Example: 流量工程 (Pseudocode)
header srv6_te_t {
    bit<32>  latency;      // 时延约束
    bit<32>  bandwidth;    // 带宽需求
    bit<128> backup_sid;   // 备份路径 SID
}


/* ====== 典型工作流程 ====== */

// 1. 源路由封装：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action encapsulate_srv6() {
    srv6_t.next_header = 8w43;  // 路由扩展头类型
    srv6_t.segments[0] = sid_list[0];
    srv6_t.segments_left = sid_list.size() - 8w1;
}
*/

// 2. 逐段转发：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action process_srh() {
    srv6_t.segments_left = srv6_t.segments_left - 1;
    srv6_t.dst_addr = srv6_t.segments[last_entry - segments_left];
    if (srv6_t.flags & SRV6_FLAG_PSP) {
        remove_srh_on_penultimate();
    }
}
*/

// 3. SID 执行：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action end_x_operation() {
    lookup_next_hop(srv6_t.segments[last_entry]);
    apply_vrf_table(ipv6.dst);
}
*/

// 4. 策略验证：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
verify srv6_integrity {
    [srv6_t.segments_left <= srv6_t.last_entry] && [srv6_t.hop_limit > 8w0];
}
*/
