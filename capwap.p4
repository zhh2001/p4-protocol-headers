typedef bit<8> msg_type_t;

// Control And Provisioning of Wireless Access Points  无线控制器与AP间通信的核心协议
header capwap_t {
    // 首部标志 (8 bits) - 控制字段
    // Header flags (8 bits) - Control fields
    bit<1>   wb_bit;         // 无线帧指示位
    bit<1>   dtls_bit;       // DTLS 加密标志
    bit<1>   e_bit;          // 分片结束标志
    bit<1>   t_bit;          // 分片开始标志
    bit<1>   r_bit;          // 保留位
    bit<3>   hlen;           // 首部长度(单位4字节)

    // 版本 (4 bits) - 协议版本号
    // Version (4 bits) - Protocol version
    bit<4>   version;

    // 报文类型 (8 bits) - 定义消息类型：
    // Msg Type (8 bits) - Message types:
    //   0=Discovery     1=Join
    //   2=Config Status 3=Data
    //   4=Data Channel Keepalive
    msg_type_t msg_type;

    // 序列号 (16 bits) - 报文顺序标识
    // Sequence (16 bits) - Packet ordering
    bit<16>  seq_num;

    // 会话 ID (32 bits) - 会话唯一标识符
    // Session ID (32 bits) - Unique session ID
    bit<32>  session_id;

    // 分片信息 (16 bits) - 分片处理字段
    // Fragment info (16 bits) - Fragmentation
    bit<16>  frag_offset;    // 分片偏移量
    bit<16>  frag_id;        // 分片标识符

    // 无线信息 (可变长度) - 802.11 帧头
    // Wireless info (variable) - 802.11 header
    varbit<256> radio_mac;     // 射频 MAC 地址
    bit<8>      radio_id;      // 射频标识符
    bit<16>     wlan_id;       // WLAN 标识符

    // 控制通道载荷 (可变长度)
    // Control channel payload
    varbit<2048> payload;
}

// CAPWAP数据消息扩展
header capwap_data_t {
    bit<16>  data_channel;   // 数据通道号
    bit<32>  timestamp;      // 时间戳(微秒)
    bit<16>  data_len;       // 数据长度
    bit<8>   data_type;      // 0=802.3 1=802.11
    varbit<1600> frame_data; // 原始数据帧
}

// 常用消息类型常量 (RFC 5415)
const msg_type_t CAPWAP_DISCOVERY = 8w0x0;  // AP 发现消息
const msg_type_t CAPWAP_JOIN      = 8w0x1;  // AP 加入请求
const msg_type_t CAPWAP_CONFIG    = 8w0x2;  // 配置更新
const msg_type_t CAPWAP_DATA      = 8w0x3;  // 数据封装
const msg_type_t CAPWAP_KEEPALIVE = 8w0x4;  // 保活检测


// 关键特性说明：
//     1. 双通道架构：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action route_control_packet() {
    capwap_t.dtls_bit = 1w1;  // 控制通道启用 DTLS
    capwap_t.msg_type = CAPWAP_JOIN;
}
*/
//     2. 无线帧封装：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action encapsulate_80211_frame() {
    capwap_data_t.data_type = 8w1;  // 802.11 帧
    capwap_data_t.timestamp = now();
}
*/
//     3. AP管理功能：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
table ap_configuration {
    key = {
        radio_mac: exact;
    }
    actions = {
        set_channel;
        set_power;
        reset_radio;
    }
    size = 1024;
}
*/


// 典型工作流程：
//     1. AP发现阶段：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action send_discovery() {
    capwap_t.msg_type = CAPWAP_DISCOVERY;
    capwap_t.seq_num = random();
}
*/
//     2. DTLS 隧道建立：
//         - 完成双向证书认证
//         - 协商加密参数（AES-CCM 等）
//     3. 配置同步：
/*
action push_config() {
    capwap_t.msg_type = CAPWAP_CONFIG;
    capwap_t.payload = {wlan_config, security_policy};
}
*/
//     4. 数据转发：
//         - 控制器集中转发跨 AP 流量
//         - 本地转发模式可绕过控制器
