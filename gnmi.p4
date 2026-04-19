/**
 * gNMI Header Definition in P4
 * gNMI 协议 P4 定义
 * 
 * Note: gNMI is the gRPC Network Management Interface protocol
 *       基于 gRPC 的网络管理接口协议定义
 */

/* gNMI Service Types */
enum bit<8> gnmi_service_type {
    CAPABILITIES = 0,   // 获取设备能力
    GET          = 1,   // 获取配置或状态数据
    SET          = 2,   // 修改配置数据
    SUBSCRIBE    = 3    // 订阅数据更新
}

/**
 * gNMI Message Header
 * gNMI 消息头
 */
header gnmi_header {
    /* Version - 32 bits
     * 版本 - 32 位
     * Protocol version (major << 16 | minor)
     * 协议版本(主版本号<<16 | 次版本号)
     */
    bit<32> version;
    
    /* Service Type - 32 bits
     * 服务类型 - 32 位
     * Identifies the gNMI service
     * 标识gNMI服务类型
     */
    gnmi_service_type service_type;
    
    /* Encoding Type - 32 bits
     * 编码类型 - 32 位
     * 0 = JSON, 1 = BYTES, 2 = PROTO, 3 = ASCII
     * 0=JSON, 1=字节, 2=ProtoBuf, 3=ASCII
     */
    bit<32> encoding;
    
    /* Message Length - 32 bits
     * 消息长度 - 32 位
     * Length of the message payload
     * 消息负载的长度
     */
    bit<32> message_length;
}

/**
 * gNMI Path Element
 * gNMI 路径元素
 */
header gnmi_path_element {
    /* Name Length - 16 bits
     * 名称长度 - 16 位
     * Length of the path element name
     * 路径元素名称的长度
     */
    bit<16> name_length;
    
    /* Key Count - 16 bits
     * 键值对数量 - 16 位
     * Number of key-value pairs
     * 键值对的数量
     */
    bit<16> key_count;
}

/**
 * gNMI Path Key
 * gNMI 路径键
 */
header gnmi_path_key {
    /* Key Length - 16 bits
     * 键长度 - 16 位
     * Length of the key name
     * 键名的长度
     */
    bit<16> key_length;
    
    /* Value Length - 16 bits
     * 值长度 - 16 位
     * Length of the key value
     * 键值的长度
     */
    bit<16> value_length;
}

/**
 * gNMI Subscription
 * gNMI 订阅
 */
header gnmi_subscription {
    /* Subscription Mode - 8 bits
     * 订阅模式 - 8 位
     * 0 = TARGET_DEFINED, 1 = ON_CHANGE, 2 = SAMPLE
     * 0=目标定义,1=变更时,2=采样
     */
    bit<8> mode;
    
    /* Sample Interval - 32 bits
     * 采样间隔 - 32 位
     * Nanoseconds between samples
     * 采样间隔纳秒数
     */
    bit<32> sample_interval;
    
    /* Suppress Redundant - 8 bits
     * 抑制冗余 - 8 位
     * 0 = false, 1 = true
     * 0=否,1=是
     */
    bit<8> suppress_redundant;
    
    /* Heartbeat Interval - 32 bits
     * 心跳间隔 - 32 位
     * Nanoseconds between heartbeat updates
     * 心跳更新间隔纳秒数
     */
    bit<32> heartbeat_interval;
}

/**
 * gNMI Update
 * gNMI 更新
 */
header gnmi_update {
    /* Path Length - 16 bits
     * 路径长度 - 16 位
     * Length of the path specification
     * 路径规范的长度
     */
    bit<16> path_length;
    
    /* Value Length - 32 bits
     * 值长度 - 32 位
     * Length of the updated value
     * 更新值的长度
     */
    bit<32> value_length;
    
    /* Timestamp - 64 bits
     * 时间戳 - 64 位
     * Nanoseconds since epoch
     * 自纪元起的纳秒数
     */
    bit<64> timestamp;
}

/**
 * gNMI Notification
 * gNMI 通知
 */
header gnmi_notification {
    /* Timestamp - 64 bits
     * 时间戳 - 64 位
     * Nanoseconds since epoch
     * 自纪元起的纳秒数
     */
    bit<64> timestamp;
    
    /* Update Count - 32 bits
     * 更新数量 - 32 位
     * Number of updates in this notification
     * 此通知中的更新数量
     */
    bit<32> update_count;
    
    /* Delete Count - 32 bits
     * 删除数量 - 32 位
     * Number of deletes in this notification
     * 此通知中的删除数量
     */
    bit<32> delete_count;
}

/**
 * gNMI Error
 * gNMI 错误
 */
header gnmi_error {
    /* Code - 32 bits
     * 错误码 - 32 位
     * gNMI error code
     * gNMI错误码
     */
    bit<32> code;
    
    /* Message Length - 16 bits
     * 消息长度 - 16 位
     * Length of the error message
     * 错误消息的长度
     */
    bit<16> message_length;
    
    /* Data Length - 16 bits
     * 数据长度 - 16 位
     * Length of additional error data
     * 附加错误数据的长度
     */
    bit<16> data_length;
}

/**
 * gNMI Transport Header (over gRPC)
 * gNMI 传输头(基于 gRPC)
 */
header gnmi_transport_header {
    /* Compression Flag - 8 bits
     * 压缩标志 - 8位
     * 0 = none, 1 = gzip
     * 0=无压缩, 1=gzip压缩
     */
    bit<8> compression;
    
    /* Message Length - 24 bits
     * 消息长度 - 24 位
     * Length of the gRPC message
     * gRPC 消息的长度
     */
    bit<24> message_length;
    
    /* Stream ID - 32 bits
     * 流 ID - 32 位
     * Identifies the gRPC stream
     * 标识 gRPC 流
     */
    bit<32> stream_id;
}

/**
 * gNMI Capability Response
 * gNMI能力响应
 */
header gnmi_capability_response {
    /* Supported Model Count - 32 bits
     * 支持的模型数量 - 32 位
     * Number of supported models
     * 支持的模型数量
     */
    bit<32> model_count;
    
    /* Supported Encoding Count - 32 bits
     * 支持的编码数量 - 32 位
     * Number of supported encodings
     * 支持的编码数量
     */
    bit<32> encoding_count;
    
    /* gNMI Version Length - 16 bits
     * gNMI 版本长度 - 16 位
     * Length of the version string
     * 版本字符串的长度
     */
    bit<16> version_length;
}
