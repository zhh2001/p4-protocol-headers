/**
 * OpenConfig Header Definition in P4
 * OpenConfig协议P4定义
 * 
 * Note: OpenConfig provides vendor-neutral models for network configuration
 *       提供厂商中立的网络配置模型定义
 */

/* OpenConfig Model Types */
enum bit<8> oc_model_type {
    INTERFACE_MODEL = 0,    // 接口模型
    BGP_MODEL       = 1,    // BGP模型
    ACL_MODEL       = 2,    // ACL模型
    PLATFORM_MODEL  = 3,    // 平台模型
    TELEMETRY_MODEL = 4     // 遥测模型
}

/**
 * OpenConfig Message Header
 * OpenConfig消息头
 */
header oc_header {
    /* Version - 16 bits
     * 版本 - 16位
     * OpenConfig model version (major << 8 | minor)
     * OpenConfig模型版本(主版本<<8 | 次版本)
     */
    bit<16> version;
    
    /* Model Type - 8 bits
     * 模型类型 - 8位
     * Identifies the OpenConfig model
     * 标识OpenConfig模型类型
     */
    oc_model_type model_type;
    
    /* Encoding Type - 8 bits
     * 编码类型 - 8位
     * 0 = JSON, 1 = XML, 2 = PROTOBUF
     * 0=JSON,1=XML,2=Protocol Buffers
     */
    bit<8> encoding;
    
    /* Message Flags - 16 bits
     * 消息标志 - 16位
     * Bit flags for message options
     * 消息选项的位标志
     */
    bit<16> flags;
    
    /* Path Depth - 16 bits
     * 路径深度 - 16位
     * Depth of the YANG path
     * YANG路径的深度
     */
    bit<16> path_depth;
    
    /* Payload Length - 32 bits
     * 负载长度 - 32位
     * Length of the message payload
     * 消息负载的长度
     */
    bit<32> payload_length;
}

/**
 * OpenConfig Path Element
 * OpenConfig路径元素
 */
header oc_path_element {
    /* Name Length - 16 bits
     * 名称长度 - 16位
     * Length of the path element name
     * 路径元素名称的长度
     */
    bit<16> name_length;
    
    /* Key Count - 16 bits
     * 键值对数量 - 16位
     * Number of key-value pairs
     * 键值对的数量
     */
    bit<16> key_count;
}

/**
 * OpenConfig Path Key
 * OpenConfig路径键
 */
header oc_path_key {
    /* Key Length - 16 bits
     * 键长度 - 16位
     * Length of the key name
     * 键名的长度
     */
    bit<16> key_length;
    
    /* Value Length - 16 bits
     * 值长度 - 16位
     * Length of the key value
     * 键值的长度
     */
    bit<16> value_length;
}

/**
 * OpenConfig Interface Model
 * OpenConfig接口模型
 */
header oc_interface {
    /* Interface Index - 32 bits
     * 接口索引 - 32位
     * System assigned interface index
     * 系统分配的接口索引
     */
    bit<32> ifindex;
    
    /* Admin Status - 8 bits
     * 管理状态 - 8位
     * 0 = DOWN, 1 = UP, 2 = TESTING
     * 0=关闭,1=开启,2=测试中
     */
    bit<8> admin_status;
    
    /* Oper Status - 8 bits
     * 操作状态 - 8位
     * 0 = DOWN, 1 = UP, 2 = TESTING
     * 0=关闭,1=开启,2=测试中
     */
    bit<8> oper_status;
    
    /* MTU - 16 bits
     * MTU - 16位
     * Maximum transmission unit
     * 最大传输单元
     */
    bit<16> mtu;
    
    /* Speed - 64 bits
     * 速度 - 64位
     * Interface speed in bits per second
     * 接口速度(比特每秒)
     */
    bit<64> speed;
    
    /* Counters - 64 bits each
     * 计数器 - 每个64位
     * Interface statistics counters
     * 接口统计计数器
     */
    bit<64> in_octets;
    bit<64> out_octets;
    bit<64> in_pkts;
    bit<64> out_pkts;
    bit<64> in_errors;
    bit<64> out_errors;
}

/**
 * OpenConfig BGP Model
 * OpenConfig BGP模型
 */
header oc_bgp {
    /* AS Number - 32 bits
     * AS号 - 32位
     * Local autonomous system number
     * 本地自治系统号
     */
    bit<32> local_as;
    
    /* Router ID - 32 bits
     * 路由器ID - 32位
     * BGP router identifier
     * BGP路由器标识符
     */
    bit<32> router_id;
    
    /* Peer AS - 32 bits
     * 对等体AS号 - 32位
     * Peer autonomous system number
     * 对等体自治系统号
     */
    bit<32> peer_as;
    
    /* Peer IP - 32 bits
     * 对等体IP - 32位
     * Peer IPv4 address
     * 对等体IPv4地址
     */
    bit<32> peer_ip;
    
    /* Session State - 8 bits
     * 会话状态 - 8位
     * 0 = IDLE, 1 = CONNECT, 2 = ACTIVE, 3 = OPEN SENT, etc.
     */
    bit<8> session_state;
    
    /* Prefix Count - 32 bits
     * 前缀计数 - 32位
     * Number of prefixes received
     * 接收的前缀数量
     */
    bit<32> prefix_count;
    
    /* Up/Down Time - 64 bits
     * 运行时间 - 64位
     * Session uptime in nanoseconds
     * 会话运行时间(纳秒)
     */
    bit<64> uptime;
}

/**
 * OpenConfig Telemetry Model
 * OpenConfig遥测模型
 */
header oc_telemetry {
    /* Sensor Path Length - 16 bits
     * 传感器路径长度 - 16位
     * Length of the sensor path
     * 传感器路径的长度
     */
    bit<16> sensor_path_length;
    
    /* Collection Interval - 32 bits
     * 采集间隔 - 32位
     * Nanoseconds between samples
     * 采样间隔(纳秒)
     */
    bit<32> interval;
    
    /* Sample Count - 32 bits
     * 样本计数 - 32位
     * Number of samples in message
     * 消息中的样本数量
     */
    bit<32> sample_count;
    
    /* Encoding - 8 bits
     * 编码 - 8位
     * 0 = JSON, 1 = PROTOBUF, 2 = XML
     */
    bit<8> encoding;
    
    /* Data Length - 32 bits
     * 数据长度 - 32位
     * Length of telemetry data
     * 遥测数据的长度
     */
    bit<32> data_length;
}

/**
 * OpenConfig Transport Header (over gRPC)
 * OpenConfig传输头(基于gRPC)
 */
header oc_transport_header {
    /* Frame Type - 8 bits
     * 帧类型 - 8位
     * 0 = DATA, 1 = HEADERS, etc.
     */
    bit<8> frame_type;
    
    /* Flags - 8 bits
     * 标志位 - 8位
     * gRPC frame flags
     * gRPC帧标志
     */
    bit<8> flags;
    
    /* Length - 24 bits
     * 长度 - 24位
     * Length of the frame payload
     * 帧负载的长度
     */
    bit<24> length;
    
    /* Stream ID - 32 bits
     * 流ID - 32位
     * Identifies the gRPC stream
     * 标识gRPC流
     */
    bit<32> stream_id;
}
