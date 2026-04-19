/**
 * NETCONF Header Definition in P4
 * NETCONF协议P4定义
 * 
 * Note: NETCONF is an IETF standard for network configuration
 *       网络配置协议标准定义
 */

/* NETCONF Message Types */
enum bit<8> netconf_message_type {
    HELLO        = 0,  // 会话初始化
    RPC          = 1,  // 远程调用请求
    RPC_REPLY    = 2,  // 远程调用响应
    NOTIFICATION = 3   // 通知消息
}

/**
 * NETCONF Message Header
 * NETCONF 消息头
 */
header netconf_header {
    /* Version - 16 bits
     * 版本 - 16位
     * NETCONF protocol version (1.0 or 1.1)
     * NETCONF 协议版本 (1.0 或 1.1)
     */
    bit<16> version;
    
    /* Message Type - 8 bits
     * 消息类型 - 8位
     * Identifies the NETCONF message type
     * 标识 NETCONF 消息类型
     */
    netconf_message_type msg_type;
    
    /* Message ID - 32 bits
     * 消息ID - 32位
     * Unique identifier for the message
     * 消息的唯一标识符
     */
    bit<32> message_id;
    
    /* Session ID - 32 bits
     * 会话ID - 32位
     * NETCONF session identifier
     * NETCONF会话标识符
     */
    bit<32> session_id;
    
    /* Payload Length - 32 bits
     * 负载长度 - 32位
     * Length of the message payload
     * 消息负载的长度
     */
    bit<32> payload_length;
}

/**
 * NETCONF Hello Capabilities
 * NETCONF Hello能力集
 */
header netconf_hello_capabilities {
    /* Capability Count - 16 bits
     * 能力数量 - 16位
     * Number of capabilities advertised
     * 通告的能力数量
     */
    bit<16> capability_count;
    
    /* Session ID - 32 bits
     * 会话ID - 32位
     * Proposed session identifier
     * 提议的会话标识符
     */
    bit<32> proposed_session_id;
}

/**
 * NETCONF RPC Operation
 * NETCONF RPC 操作
 */
header netconf_rpc_operation {
    /* Operation Type - 16 bits
     * 操作类型 - 16位
     * 1 = get-config, 2 = edit-config, etc.
     * 1 = 获取配置, 2 = 编辑配置等
     */
    bit<16> operation;
    
    /* Operation Target - 16 bits
     * 操作目标 - 16位
     * 1 = running, 2 = candidate, 3 = startup
     * 1 = 运行中, 2 = 候选, 3 = 启动
     */
    bit<16> target;
    
    /* Error Option - 8 bits
     * 错误选项 - 8位
     * 1 = stop-on-error, 2 = continue-on-error
     * 1 = 出错停止, 2 = 出错继续
     */
    bit<8> error_option;
    
    /* Test Option - 8 bits
     * 测试选项 - 8位
     * 1 = test-then-set, 2 = set
     * 1 = 先测试后设置, 2 = 直接设置
     */
    bit<8> test_option;
    
    /* Default Operation - 8 bits
     * 默认操作 - 8位
     * 1 = merge, 2 = replace, 3 = none
     * 1 = 合并, 2 = 替换, 3 = 无
     */
    bit<8> default_operation;
}

/**
 * NETCONF Filter
 * NETCONF过滤器
 */
header netconf_filter {
    /* Filter Type - 8 bits
     * 过滤器类型 - 8位
     * 0 = subtree, 1 = xpath
     */
    bit<8> type;
    
    /* Selector Length - 16 bits
     * 选择器长度 - 16位
     * Length of the filter selector
     * 过滤器选择器的长度
     */
    bit<16> selector_length;
}

/**
 * NETCONF Notification
 * NETCONF通知
 */
header netconf_notification {
    /* Event Time - 64 bits
     * 事件时间 - 64位
     * Timestamp in milliseconds since epoch
     * 自纪元起的毫秒时间戳
     */
    bit<64> event_time;
    
    /* Notification Type - 16 bits
     * 通知类型 - 16位
     * Identifies the notification type
     * 标识通知类型
     */
    bit<16> notification_type;
    
    /* Sequence Number - 32 bits
     * 序列号 - 32位
     * Notification sequence number
     * 通知序列号
     */
    bit<32> sequence_number;
}

/**
 * NETCONF Error
 * NETCONF错误
 */
header netconf_error {
    /* Error Type - 16 bits
     * 错误类型 - 16位
     * 1 = transport, 2 = rpc, etc.
     */
    bit<16> error_type;
    
    /* Error Tag - 16 bits
     * 错误标签 - 16位
     * Identifies the error condition
     * 标识错误条件
     */
    bit<16> error_tag;
    
    /* Error Severity - 8 bits
     * 错误严重性 - 8位
     * 0 = warning, 1 = error
     * 0=警告,1=错误
     */
    bit<8> error_severity;
    
    /* Error Path Length - 16 bits
     * 错误路径长度 - 16位
     * Length of error path if any
     * 错误路径的长度(如果有)
     */
    bit<16> error_path_length;
    
    /* Error Message Length - 16 bits
     * 错误消息长度 - 16位
     * Length of error message
     * 错误消息的长度
     */
    bit<16> error_message_length;
}

/**
 * NETCONF Transport Header (over SSH)
 * NETCONF传输头(基于SSH)
 */
header netconf_transport_header {
    /* Channel Number - 32 bits
     * 通道号 - 32位
     * SSH channel identifier
     * SSH通道标识符
     */
    bit<32> channel_number;
    
    /* Packet Length - 32 bits
     * 包长度 - 32位
     * Length of the SSH packet
     * SSH包的长度
     */
    bit<32> packet_length;
    
    /* Padding Length - 8 bits
     * 填充长度 - 8位
     * Length of random padding
     * 随机填充的长度
     */
    bit<8> padding_length;
    
    /* Payload Length - 24 bits
     * 负载长度 - 24位
     * Length of the payload
     * 负载的长度
     */
    bit<24> payload_length;
}
