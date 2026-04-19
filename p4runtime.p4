/**
 * P4Runtime Header Definition in P4
 * P4Runtime 协议 P4 定义
 * 
 * Note: P4Runtime is the control plane protocol for P4 programs
 *       用于 P4 程序的控制平面协议定义
 */

/* P4Runtime Service Types */
enum bit<8> p4_service_type {
    P4RUNTIME   = 0,       // Main P4Runtime service
    CONFIG_MGMT = 1,       // Configuration management
    DEVICE_MGMT = 2,       // Device management
    PACKET_IO   = 3        // Packet in/out service
}

/**
 * P4Runtime Message Header
 * P4Runtime消息头
 */
header p4runtime_header {
    /* Magic Number - 32 bits
     * 魔数 - 32 位
     * Always 0xFEEDFACE for P4Runtime
     * P4Runtime 固定使用 32w0xFEEDFACE
     */
    bit<32> magic;
    
    /* Version - 32 bits
     * 版本 - 32 位
     * Protocol version (major << 16 | minor)
     * 协议版本(主版本号<<16 | 次版本号)
     */
    bit<32> version;
    
    /* Service Type - 32 bits
     * 服务类型 - 32 位
     * Identifies the P4Runtime service
     * 标识 P4Runtime 服务类型
     */
    p4_service_type service_type;
    
    /* Message Type - 32 bits
     * 消息类型 - 32 位
     * Service-specific message type
     * 服务特定的消息类型
     */
    bit<32> message_type;
    
    /* Payload Length - 32 bits
     * 负载长度 - 32 位
     * Length of the message payload
     * 消息负载的长度
     */
    bit<32> payload_length;
    
    /* Device ID - 64 bits
     * 设备 ID - 64 位
     * Identifies the target device
     * 标识目标设备
     */
    bit<64> device_id;
    
    /* Election ID - 128 bits
     * 选举 ID - 128 位
     * Used for master arbitration
     * 用于主控制器选举
     */
    bit<128> election_id;
}

/**
 * P4Runtime Write Request
 * P4Runtime写请求
 */
header p4runtime_write_request {
    /* Atomicity - 32 bits
     * 原子性 - 32 位
     * 0 = CONTINUE_ON_ERROR, 1 = ROLLBACK_ON_ERROR
     * 0=出错继续, 1=出错回滚
     */
    bit<32> atomicity;
    
    /* Update Count - 32 bits
     * 更新数量 - 32 位
     * Number of updates in this request
     * 此请求中的更新数量
     */
    bit<32> update_count;
}

/**
 * P4Runtime Table Update
 * P4Runtime 表更新
 */
header p4runtime_table_update {
    /* Operation - 32 bits
     * 操作 - 32 位
     * 0 = UNSPECIFIED, 1 = INSERT, 2 = MODIFY, 3 = DELETE
     * 0=未指定, 1=插入, 2=修改, 3=删除
     */
    bit<32> operation;
    
    /* Table ID - 32 bits
     * 表ID - 32 位
     * Identifies the P4 table
     * 标识P4表
     */
    bit<32> table_id;
    
    /* Priority - 32 bits
     * 优先级 - 32 位
     * Table entry priority
     * 表项优先级
     */
    bit<32> priority;
    
    /* Match Key Length - 32 bits
     * 匹配键长度 - 32 位
     * Length of the match key in bytes
     * 匹配键的字节长度
     */
    bit<32> match_key_length;
    
    /* Action Data Length - 32 bits
     * 动作数据长度 - 32 位
     * Length of the action data in bytes
     * 动作数据的字节长度
     */
    bit<32> action_data_length;
}

/**
 * P4Runtime Packet Metadata
 * P4Runtime数据包元数据
 */
header p4runtime_packet_metadata {
    /* Metadata ID - 32 bits
     * 元数据ID - 32 位
     * Identifies the metadata field
     * 标识元数据字段
     */
    bit<32> metadata_id;
    
    /* Metadata Value Length - 32 bits
     * 元数据值长度 - 32 位
     * Length of the metadata value in bytes
     * 元数据值的字节长度
     */
    bit<32> value_length;
}

/**
 * P4Runtime Packet-In Header
 * P4Runtime 数据包输入头
 */
header p4runtime_packet_in {
    /* Payload Length - 32 bits
     * 负载长度 - 32 位
     * Length of the packet payload
     * 数据包负载的长度
     */
    bit<32> payload_length;
    
    /* Metadata Count - 32 bits
     * 元数据数量 - 32 位
     * Number of metadata fields
     * 元数据字段数量
     */
    bit<32> metadata_count;
}

/**
 * P4Runtime Packet-Out Header
 * P4Runtime 数据包输出头
 */
header p4runtime_packet_out {
    /* Payload Length - 32 bits
     * 负载长度 - 32 位
     * Length of the packet payload
     * 数据包负载的长度
     */
    bit<32> payload_length;
    
    /* Metadata Count - 32 bits
     * 元数据数量 - 32 位
     * Number of metadata fields
     * 元数据字段数量
     */
    bit<32> metadata_count;
}

/**
 * P4Runtime Stream Message
 * P4Runtime 流式消息
 */
header p4runtime_stream_message {
    /* Message Type - 32 bits
     * 消息类型 - 32 位
     * 0 = ARBITRATION, 1 = PACKET, 2 = DIGEST
     * 0=仲裁, 1=数据包, 2=摘要
     */
    bit<32> message_type;
    
    /* Payload Length - 32 bits
     * 负载长度 - 32 位
     * Length of the message payload
     * 消息负载的长度
     */
    bit<32> payload_length;
}

/**
 * P4Runtime Transport Header (over gRPC)
 * P4Runtime 传输头(基于 gRPC)
 */
header p4runtime_transport_header {
    /* Frame Type - 8 bits
     * 帧类型 - 8 位
     * 0 = DATA, 1 = HEADERS, etc.
     * 0=数据, 1=头等
     */
    bit<8> frame_type;
    
    /* Flags - 8 bits
     * 标志位 - 8 位
     * gRPC frame flags
     * gRPC 帧标志
     */
    bit<8> flags;
    
    /* Length - 24 bits
     * 长度 - 24 位
     * Length of the frame payload
     * 帧负载的长度
     */
    bit<24> length;
    
    /* Stream ID - 32 bits
     * 流 ID - 32 位
     * Identifies the gRPC stream
     * 标识 gRPC 流
     */
    bit<32> stream_id;
}
