// Protocol Independent Multicast  IP 组播路由的核心协议，支持多种组播分发模式（SM/SSM/BIDIR）
header pim_t {
    // 版本类型 (4 bits) - 版本号 + 类型
    // VerType (4 bits) - Version + Type
    bit<2>   version;     // 固定为 2
    bit<2>   type;        // 报文类型：
                          //     0 = Hello
                          //     1 = Register
                          //     2 = Register-Stop
                          //     3 = Join/Prune
                          //     4 = Bootstrap
                          //     5 = Assert
                          //     6 = Graft (仅 DM)
                          //     7 = Graft-Ack

    // 标志位 (8 bits) - 类型相关标志
    // Flags (8 bits) - Type-specific flags
    bit<1>   reserved1;
    bit<1>   suppress_rpt;   // Join/Prune 专用
    bit<1>   boundary;       // Bootstrap 边界标志
    bit<1>   no_forward;     // Register 空包标志
    bit<4>   reserved2;

    // 校验和 (16 bits) - 标准 IP 校验和
    // Checksum (16 bits) - Standard IP checksum
    bit<16>  checksum;

    // 类型特定数据 (可变长度)
    // Type-specific data (variable)
    varbit<512> payload;
}

// PIM Hello 选项 TLV
header pim_hello_tlv_t {
    bit<16>  option_type;     // 选项类型
    bit<16>  option_length;   // 选项长度
    varbit<256> option_data;  // 选项数据
}

// PIM Join/Prune 条目
header pim_jp_entry_t {
    bit<8>   entry_type;    // 1=Join 2=Prune
    bit<8>   reserved;
    bit<16>  holdtime;      // 保持时间(秒)
    bit<32>  group_addr;    // 组播组地址
    bit<32>  source_addr;   // 源地址(SSM用)
}

// 常用 Hello 选项常量
const bit<16> PIM_HELLO_HOLDTIME    = 1;  // 保持时间
const bit<16> PIM_HELLO_DR_PRIORITY = 2;  // 指定路由器优先级
const bit<16> PIM_HELLO_GEN_ID      = 3;  // 生成 ID
const bit<16> PIM_HELLO_ADDR_LIST   = 4;  // 接口地址列表


// 关键特性说明：
//     1. 模式支持：
const bit<2> PIM_MODE_DM    = 0;  // 密集模式
const bit<2> PIM_MODE_SM    = 1;  // 稀疏模式
const bit<2> PIM_MODE_SSM   = 2;  // 指定源组播
const bit<2> PIM_MODE_BIDIR = 3;  // 双向组播
//     2. DR 选举：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action elect_dr() {
    pim_hello_tlv.option_type = PIM_HELLO_DR_PRIORITY;
    pim_hello_tlv.option_data = 0x7FFF;  // 最高优先级
}
*/
//     3. RPT/SPT 切换：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action build_shared_tree() {
    pim_jp_entry.entry_type = 8w1;  // Join
    pim_jp_entry.group_addr = 32w0xE0000101;  // 224.0.1.1
    pim_jp_entry.source_addr = 32w0;  // 空源=共享树
}
*/


// 典型工作流程：
//     1. 邻居发现：
//         - 周期性发送 Hello 报文（默认 30 秒）
//         - 通过 DR_PRIORITY 选项选举指定路由器
//     2. 组播树建立：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action send_join_prune() {
    pim.type = 2w3;  // Join/Prune 类型
    pim_jp_entry.holdtime = 16w210;  // 默认保持时间
}
*/
//     3. 源注册：
//         - 第一跳路由器发送 Register 报文
//         - RP 回复 Register-Stop 控制注册流程
//     4. 断言机制：
/*
action send_assert() {
    pim.type = 5;  // Assert类型
    pim.payload = {source_addr, group_addr, metric};
}
*/
