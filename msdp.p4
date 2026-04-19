typedef bit<32> ipv4_addr_t;

// Multicast Source Discovery Protocol  跨域组播的核心协议，用于在 PIM-SM 域间传播组播源信息
header msdp_t {
    // 版本 (4 bits) - 固定为 1
    // Version (4 bits) - Fixed to 1
    bit<4> version;

    // 类型 (4 bits) - MSDP 消息类型：
    // Type (4 bits) - MSDP message types:
    //     1 = Source Active (SA) 
    //     2 = SA Request
    //     3 = SA Response
    //     4 = Keepalive
    //     5 = Notification
    bit<4> msg_type;

    // 保留字段 (8 bits) - 必须置 0
    // Reserved (8 bits) - Must be zero
    bit<8> reserved;

    // 长度 (16 bits) - 报文总长度
    // Length (16 bits) - Total message length
    bit<16> length;

    // 条目计数 (16 bits) - SA 消息中的条目数
    // Entry count (16 bits) - SA entries count
    bit<16> entry_count;

    // 源活跃数据 (可变长度) - SA 条目列表
    // SA data (variable) - List of SA entries
    // msdp_sa_entry_t[16] sa_entries;  // (removed: nested header reference)
}

header msdp_sa_entry_t {
    // 组播组地址 (32 bits) - 组播组 IP
    // Multicast group (32 bits) - Group address
    ipv4_addr_t group;

    // 源地址 (32 bits) - 组播源 IP
    // Source address (32 bits) - Source IP
    ipv4_addr_t source;

    // RP地址 (32 bits) - 通告者的 RP 地址
    // RP address (32 bits) - Originator's RP
    bit<32> rp_address;

    // 生存时间 (16 bits) - SA 条目有效期(秒)
    // TTL (16 bits) - Entry lifetime in seconds
    bit<16> ttl;

    // 封装数据 (可变长度) - 原始组播数据包
    // Encapsulated data (variable) - Original packet
    varbit<1024> payload;
}

// MSDP 状态标志
const bit<8> MSDP_STATE_RPF_FAIL = 8w0x01;  // RPF 检查失败
const bit<8> MSDP_STATE_SA_FILTERED = 8w0x02;  // 被 SA 过滤器拦截


// 关键特性说明：
//     1. 域间源发现：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action create_sa_message() {
    msdp_t.msg_type = 4w1;  // SA 类型
    msdp_sa_entry.ttl = 16w210;  // 默认生存时间
}
*/
//     2. RPF 检查机制：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
table msdp_rpf_check {
    key = {
        rp_address: exact;
    }
    actions = {
        accept_sa;
        drop_sa;
    }
    size = 1024;
}
*/
//     3. Anycast RP 支持：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action handle_anycast_rp() {
    msdp_sa_entry.rp_address = 32w0x0A010101; // Anycast RP 地址
}
*/


// 典型工作流程：
//     1. 源注册：
//         - 第一跳 RP 检测到新组播源
//         - 生成 SA 消息发送给所有 MSDP 对等体
//     2. 域间传播：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action forward_sa() {
    msdp_t.entry_count = msdp_t.entry_count + 16w1;
    msdp_sa_entry.ttl = msdp_sa_entry.ttl - 16w1;  // 递减 TTL
}
*/
//     3. 接收处理：
//         - 接收 RP 检查 SA 有效性
//         - 向源发起 PIM Join 建立 SPT
//     4. 状态维护：
//         - 周期性发送 Keepalive（默认 60 秒）
//         - SA条目默认存活 210 秒
