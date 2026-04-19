/**
 * Model-Driven Telemetry Header Definition in P4
 * 模型驱动遥测协议P4定义
 * 
 * Note: 用于高效采集和传输网络设备实时运行数据
 *       支持多种传输模式和编码格式
 */

/* 遥测数据编码类型 */
enum bit<8> telemetry_encoding {
    ENCODING_JSON   = 0,    // JSON 格式
    ENCODING_GPB    = 1,    // Protocol Buffers 格式
    ENCODING_XML    = 2,    // XML 格式
    ENCODING_CUSTOM = 3     // 自定义编码格式
}

/* 遥测采集模式 */
enum bit<8> collection_mode {
    STREAM   = 0,          // 持续流式采集
    ONCE     = 1,          // 单次采集
    PERIODIC = 2,          // 周期性采集
    EVENT    = 3           // 事件触发采集
}

/**
 * 遥测消息头 (12字节)
 */
header telemetry_header {
    /* 协议版本 - 4位
     * 当前版本为1
     */
    bit<4> version;
    
    /* 保留位 - 4位
     * 必须设为0
     */
    bit<4> reserved;
    
    /* 消息标志 - 8位
     * [0]: 数据压缩标志
     * [1]: 数据加密标志
     * [2-7]: 保留
     */
    bit<8> flags;
    
    /* 消息类型 - 8位
     * 0=数据消息, 1=控制消息, 2=确认消息
     */
    bit<8> message_type;
    
    /* 编码类型 - 8位
     * 指定数据负载的编码格式
     */
    telemetry_encoding encoding;
    
    /* 采集模式 - 8位
     * 指定数据采集模式
     */
    collection_mode mode;
    
    /* 消息序列号 - 32位
     * 单调递增的消息序号
     */
    bit<32> sequence_number;
    
    /* 采集时间戳 - 64位
     * 数据采集的UTC时间(纳秒精度)
     */
    bit<64> timestamp;
    
    /* 数据路径标识 - 32位
     * 标识数据来源路径
     */
    bit<32> path_id;
    
    /* 负载长度 - 32位
     * 数据负载的字节长度
     */
    bit<32> payload_length;
}

/**
 * 传感器路径头
 */
header sensor_path {
    /* 模型名称长度 - 8位 */
    bit<8> model_name_len;
    
    /* 路径深度 - 8位
     * YANG路径的层级深度
     */
    bit<8> path_depth;
    
    /* 过滤条件长度 - 16位 */
    bit<16> filter_len;
}

/**
 * 数据样本头
 */
header data_sample {
    /* 样本间隔 - 32位
     * 与前一个样本的时间间隔(微秒)
     */
    bit<32> interval;
    
    /* 字段计数 - 16位
     * 样本中包含的字段数量
     */
    bit<16> field_count;
    
    /* 错误码 - 16位
     * 0=正常 非零表示采集错误
     */
    bit<16> error_code;
}

/**
 * 控制消息头
 */
header control_message {
    /* 命令类型 - 8位
     * 0=订阅 1=取消订阅 2=心跳
     */
    bit<8> command;
    
    /* 订阅ID - 64位
     * 唯一标识一个订阅会话
     */
    bit<64> subscription_id;
    
    /* 采样间隔 - 32位
     * 请求的采样间隔(毫秒)
     */
    bit<32> sample_interval;
    
    /* 抑制冗余 - 8位
     * 是否抑制重复数据
     */
    bit<8> suppress_redundant;
    
    /* 心跳间隔 - 32位
     * 心跳消息间隔(秒)
     */
    bit<32> heartbeat_interval;
}

/**
 * 确认消息头
 */
header ack_message {
    /* 响应码 - 16位
     * 类似HTTP状态码
     */
    bit<16> response_code;
    
    /* 错误消息长度 - 16位 */
    bit<16> error_msg_len;
    
    /* 已处理序列号 - 32位
     * 确认已处理的消息序号
     */
    bit<32> processed_sequence;
}

/**
 * 遥测传输头 (基于UDP)
 */
header telemetry_transport {
    /* 源端口 - 16位 */
    bit<16> src_port;
    
    /* 目的端口 - 16位
     * 默认50051
     */
    bit<16> dst_port;
    
    /* 数据报长度 - 16位 */
    bit<16> length;
    
    /* 校验和 - 16位 */
    bit<16> checksum;
    
    /* 数据流ID - 32位
     * 标识数据流
     */
    bit<32> stream_id;
}

/**
 * 遥测扩展头 (可选)
 */
header telemetry_extension {
    /* 扩展类型 - 8位 */
    bit<8> ext_type;
    
    /* 扩展长度 - 16位 */
    bit<16> ext_len;
    
    /* 扩展标志 - 8位 */
    bit<8> ext_flags;
}

/**
 * 数据字段描述头
 */
header data_field {
    /* 字段ID - 16位 */
    bit<16> field_id;
    
    /* 字段类型 - 8位
     * 0=整型, 1=浮点, 2=字符串, 3=布尔
     */
    bit<8> field_type;
    
    /* 字段长度 - 16位
     * 字段值的字节长度
     */
    bit<16> field_len;
}

/**
 * 事件触发条件头
 */
header trigger_condition {
    /* 条件类型 - 8位
     * 0 = 阈值, 1 = 正则, 2 = 存在
     */
    bit<8> cond_type;
    
    /* 条件ID - 16位 */
    bit<16> cond_id;
    
    /* 条件参数长度 - 16位 */
    bit<16> param_len;
}
