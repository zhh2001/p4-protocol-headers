/**********************************************************
 * STP/RSTP Header (IEEE 802.1D / 802.1w)
 * 生成树协议报头 - 防止二层环路
 * Spanning Tree Protocol Header
 * Prevents L2 loops in bridged networks
 **********************************************************/

header stp_t {
    bit<16> protocol_id;       // Protocol ID (0x0000)          协议标识符 (固定 0x0000)
    bit<8>  version;           // Version (0=STP 2=RSTP 3=MSTP) 版本号
    bit<8>  bpdu_type;         // BPDU type                     BPDU 类型
    bit<8>  flags;             // Flags (TC, TCA, etc.)         标志位
    bit<16> root_priority;     // Root bridge priority           根桥优先级
    bit<48> root_mac;          // Root bridge MAC address        根桥 MAC 地址
    bit<32> root_path_cost;    // Root path cost                 根路径开销
    bit<16> bridge_priority;   // Bridge priority                桥优先级
    bit<48> bridge_mac;        // Bridge MAC address             桥 MAC 地址
    bit<16> port_id;           // Port identifier                端口标识符
    bit<16> message_age;       // Message age (1/256 seconds)    消息年龄
    bit<16> max_age;           // Maximum age                    最大年龄
    bit<16> hello_time;        // Hello timer                    Hello 定时器
    bit<16> forward_delay;     // Forward delay                  转发延迟
}

// RSTP 扩展字段
header rstp_ext_t {
    bit<8>  version1_length;   // Version 1 length (must be 0)  版本1长度
}

// BPDU 类型常量
const bit<8> STP_BPDU_CONFIG = 8w0x00;       // 配置 BPDU
const bit<8> STP_BPDU_TCN    = 8w0x80;       // 拓扑变更通知
const bit<8> RSTP_BPDU       = 8w0x02;       // RSTP BPDU

// STP 标志位常量
const bit<8> STP_FLAG_TC     = 8w0x01;       // 拓扑变更
const bit<8> STP_FLAG_TCA    = 8w0x80;       // 拓扑变更确认
const bit<8> RSTP_FLAG_ROLE_MASK = 8w0x0C;   // 端口角色掩码
