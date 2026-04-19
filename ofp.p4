/**
 * OpenFlow Header Definition in P4
 * OpenFlow协议P4定义
 * 
 * Note: This defines the OpenFlow message header format used in 
 *       communication between controllers and switches
 * 注意：这里定义的是控制器和交换机之间通信使用的 OpenFlow 消息头格式
 */

/* OpenFlow Protocol Versions - 枚举定义
 * OpenFlow 协议版本
 */
enum bit<8> ofp_version {
    OFP_1_0 = 0x01,  // OpenFlow 1.0
    OFP_1_1 = 0x02,  // OpenFlow 1.1
    OFP_1_2 = 0x03,  // OpenFlow 1.2
    OFP_1_3 = 0x04,  // OpenFlow 1.3 (most widely used)
    OFP_1_4 = 0x05,  // OpenFlow 1.4
    OFP_1_5 = 0x06   // OpenFlow 1.5
}

/* OpenFlow Message Types - 枚举定义
 * OpenFlow 消息类型
 */
enum bit<8> ofp_type {
    OFPT_HELLO            = 0,   // Hello message
    OFPT_ERROR            = 1,   // Error message
    OFPT_ECHO_REQUEST     = 2,   // Echo request
    OFPT_ECHO_REPLY       = 3,   // Echo reply
    OFPT_FEATURES_REQUEST = 5,   // Switch features request
    OFPT_FEATURES_REPLY   = 6,   // Switch features reply
    OFPT_PACKET_IN        = 10,  // Packet received on data plane
    OFPT_FLOW_MOD         = 14,  // Modify flow table entry
    OFPT_PORT_STATUS      = 12   // Port status change
}

/**
 * OpenFlow Header - 基本消息头
 * 所有 OpenFlow 消息都以这个头开始
 */
header ofp_header {
    /* Version - 8 bits
     * 版本 - 8 位
     * Identifies the OpenFlow protocol version
     * 标识 OpenFlow 协议版本
     */
    bit<8> version;
    
    /* Type - 8 bits
     * 类型 - 8 位
     * Identifies the OpenFlow message type
     * 标识 OpenFlow 消息类型
     */
    bit<8> type;
    
    /* Length - 16 bits
     * 长度 - 16 位
     * Length of the message including this header
     * 包括此头在内的消息总长度
     */
    bit<16> length;
    
    /* Transaction ID - 32 bits
     * 事务 ID - 32 位
     * Used to correlate requests and responses
     * 用于关联请求和响应
     */
    bit<32> xid;
}

/**
 * OpenFlow Port Structure - 端口结构
 * Used in port status messages and features reply
 * 用于端口状态消息和特性回复
 */
header ofp_port {
    /* Port Number - 32 bits
     * 端口号 - 32 位
     * Unique identifier for the port
     * 端口的唯一标识符
     */
    bit<32> port_no;
    
    /* Hardware Address - 48 bits
     * 硬件地址 - 48 位
     * The MAC address of the port
     * 端口的 MAC 地址
     */
    bit<48> hw_addr;
    
    /* Name - 128 bits (16 bytes)
     * 名称 - 128 位(16 字节)
     * Human-readable name for the port
     * 端口的人类可读名称
     */
    bit<128> name;
    
    /* Configuration Flags - 32 bits
     * 配置标志 - 32位
     * Bitmap of OFPPC_* flags
     * OFPPC_*标志的位图
     */
    bit<32> config;
    
    /* State Flags - 32 bits
     * 状态标志 - 32位
     * Bitmap of OFPPS_* flags
     * OFPPS_*标志的位图
     */
    bit<32> state;
}

/**
 * OpenFlow Flow Match Structure - 流匹配结构
 * Used in flow table entries
 * 用于流表条目
 */
header ofp_match {
    /* Match Type - 16 bits
     * 匹配类型 - 16 位
     * Identifies the match structure type
     * 标识匹配结构类型
     */
    bit<16> type;
    
    /* Match Length - 16 bits
     * 匹配长度 - 16 位
     * Length of the match structure
     * 匹配结构的长度
     */
    bit<16> length;
    
    /* Match Fields - variable
     * 匹配字段 - 可变
     * Actual match criteria (e.g., Ethernet, IP, TCP/UDP fields)
     * 实际的匹配标准(例如以太网、IP、TCP/UDP 字段)
     */
    varbit<1024> fields; // Typically includes in_port, eth_src, eth_dst, etc.
                        // 通常包括in_port、eth_src、eth_dst等
}

/**
 * OpenFlow Flow Mod Message - 流修改消息
 * Used to add/modify/delete flow table entries
 * 用于添加/修改/删除流表条目
 */
header ofp_flow_mod {
    /* Cookie - 64 bits
     * Cookie - 64 位
     * Opaque controller-issued identifier
     * 控制器发布的不透明标识符
     */
    bit<64> cookie;
    
    /* Command - 8 bits
     * 命令 - 8 位
     * Flow modification command (add/modify/delete)
     * 流修改命令(添加/修改/删除)
     */
    bit<8> command;
    
    /* Idle Timeout - 16 bits
     * 空闲超时 - 16位
     * Seconds before flow is expired by idle time
     * 流因空闲而过期前的秒数
     */
    bit<16> idle_timeout;
    
    /* Hard Timeout - 16 bits
     * 硬超时 - 16 位
     * Seconds before flow is expired regardless of activity
     * 无论活动如何，流过期前的秒数
     */
    bit<16> hard_timeout;
    
    /* Priority - 16 bits
     * 优先级 - 16 位
     * Priority level of the flow entry
     * 流条目的优先级
     */
    bit<16> priority;
    
    /* Buffer ID - 32 bits
     * 缓冲区ID - 32 位
     * Buffered packet to apply to (or OFP_NO_BUFFER)
     * 要应用的缓冲数据包(或OFP_NO_BUFFER)
     */
    bit<32> buffer_id;
    
    /* Match Structure - variable
     * 匹配结构 - 可变
     * Describes the fields to match
     * 描述要匹配的字段
     */
    // ofp_match match;  // (removed: nested header reference)
    
    /* Instructions - variable
     * 指令 - 可变
     * Actions to apply to matching packets
     * 应用于匹配数据包的操作
     */
    varbit<2048> instructions;  // Includes apply_actions, write_actions, etc.
                                // 包括apply_actions、write_actions 等
}
