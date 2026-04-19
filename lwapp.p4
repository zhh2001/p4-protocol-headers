typedef bit<8> frame_type_t;

// Lightweight Access Point Protocol  CAPWAP 协议的前身，广泛用于早期无线控制器系统
header lwapp_t {
    // 控制标志 (8 bits) - 协议控制字段
    // Control flags (8 bits) - Protocol control
    bit<1>   c_bit;           // 控制消息标志
    bit<1>   f_bit;           // 分片标志
    bit<1>   m_bit;           // 更多分片标志
    bit<1>   k_bit;           // 密钥更新标志
    bit<4>   reserved_flags;  // 保留标志位

    // 版本 (4 bits) - 协议版本号
    // Version (4 bits) - Protocol version
    bit<4>   version;

    // 帧类型 (8 bits) - 定义消息类型：
    // Frame type (8 bits) - Message types:
    //     1=Discovery    2=Join  
    //     3=Config       4=Data
    //     5=Keepalive    6=Key Update
    frame_type_t frame_type;

    // 序列号 (16 bits) - 报文顺序标识
    // Sequence (16 bits) - Packet ordering
    bit<16>  seq_num;

    // 长度 (16 bits) - 有效载荷长度
    // Length (16 bits) - Payload length
    bit<16>  length;

    // 会话 ID (32 bits) - 会话唯一标识符
    // Session ID (32 bits) - Unique session ID
    bit<32>  session_id;

    // 射频信息 (24 bits) - 无线特定字段
    // Radio info (24 bits) - Wireless specific
    bit<8>    radio_id;      // 射频标识符
    bit<16>   wlan_id;       // WLAN 标识符

    // 控制消息载荷 (可变长度)
    // Control message payload
    varbit<1024> payload;
}

// LWAPP 数据封装头部
header lwapp_data_t {
    bit<16>  data_channel;    // 数据通道号
    bit<32>  timestamp;       // 时间戳(毫秒)
    bit<16>  data_len;        // 数据长度
    bit<8>   flags;           // 数据帧标志位
    varbit<1600> frame_data;  // 原始 802.11 帧
}

// 消息类型常量 (RFC 5412)
const frame_type_t LWAPP_DISCOVERY = 8w0x1;  // AP 发现消息
const frame_type_t LWAPP_JOIN      = 8w0x2;  // AP 加入请求  
const frame_type_t LWAPP_CONFIG    = 8w0x3;  // 配置下发
const frame_type_t LWAPP_DATA      = 8w0x4;  // 数据封装
const frame_type_t LWAPP_KEEPALIVE = 8w0x5;  // 连接保活


// 关键特性说明：
//     1. 轻量级封装：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action encapsulate_80211() {
    lwapp_data_t.flags = 8w0x80;  // 标记为 802.11 帧
    lwapp_data_t.timestamp = now();
}
*/
//     2. AP 自动发现：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action send_discovery() {
    lwapp_t.frame_type = LWAPP_DISCOVERY;
    lwapp_t.c_bit = 1w1;  // 控制消息
}
*/
//     3. 密钥轮换机制：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action update_keys() {
    lwapp_t.frame_type = LWAPP_KEY_UPDATE;
    lwapp_t.k_bit = 1w1;  // 密钥更新标志
}
*/


// 典型工作流程：
//     1. 初始化阶段：
//         - AP 发送广播 Discovery 消息
//         - 控制器回复单播 Join 响应
//     2. 配置阶段：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action push_config() {
    lwapp_t.frame_type = LWAPP_CONFIG;
    lwapp_t.payload = {ssid_config, security_policy};
}
*/
//     3. 数据阶段：
//         - 本地转发模式：直接传输数据
//         - 隧道转发模式：通过 LWAPP Data 封装
//     4. 维护阶段：
//         - 周期性 Keepalive 检测（默认 30 秒）
//         - 动态密钥更新（AES-CCMP 密钥）
