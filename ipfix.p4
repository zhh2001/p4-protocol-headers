/**
 * IPFIX Header Definition in P4
 * IPFIX 协议 P4 定义
 * 
 * Note: IPFIX is the IETF standard protocol for network flow export
 *       基于 IPFIX 的流量导出协议定义
 */

/* IPFIX Message Types */
enum bit<8> ipfix_message_type {
    TEMPLATE_FLOWSET = 0,   // 模板流集合
    DATA_FLOWSET     = 1,   // 数据流集合
    OPTIONS_TEMPLATE = 2,   // 选项模板
    OPTIONS_DATA     = 3    // 选项数据
}

/**
 * IPFIX Message Header (RFC 7011)
 * IPFIX 消息头(16 字节)
 */
header ipfix_header {
    /* Version Number - 16 bits
     * 版本号 - 16 位
     * Value 0x000a for IPFIX (10 in decimal)
     * IPFIX 版本固定为 10(0x000a)
     */
    bit<16> version;
    
    /* Length - 16 bits
     * 长度 - 16 位
     * Total length of the IPFIX message in bytes
     * IPFIX 消息的总字节长度
     */
    bit<16> length;
    
    /* Export Time - 32 bits
     * 导出时间 - 32 位
     * Seconds since UNIX epoch (1970-01-01 00:00:00 UTC)
     * 自 UNIX 纪元以来的秒数
     */
    bit<32> export_time;
    
    /* Sequence Number - 32 bits
     * 序列号 - 32 位
     * Incremented per IPFIX message from this exporter
     * 导出器发送的 IPFIX 消息序列号
     */
    bit<32> sequence_number;
    
    /* Observation Domain ID - 32 bits
     * 观察域 ID - 32 位
     * Identifies the exporter's observation domain
     * 标识导出器的观察域
     */
    bit<32> observation_domain_id;
}

/**
 * IPFIX Set Header (FlowSet Header)
 * IPFIX 集合头(流集合头)
 */
header ipfix_set_header {
    /* Set ID - 16 bits
     * 集合 ID - 16 位
     * Identifies the type of the set:
     *   - 2 for Template Sets
     *   - 3 for Options Template Sets
     *   - 256-65535 for Data Sets
     * 标识集合类型:
     *   - 2 表示模板集合
     *   - 3 表示选项模板集合
     *   - 256-65535 表示数据集合
     */
    bit<16> set_id;
    
    /* Length - 16 bits
     * 长度 - 16 位
     * Total length of the set in bytes
     * 集合的总字节长度
     */
    bit<16> length;
}

/**
 * IPFIX Template Record Header
 * IPFIX 模板记录头
 */
header ipfix_template_header {
    /* Template ID - 16 bits
     * 模板 ID - 16 位
     * Identifies this template (>= 256 for data templates)
     * 标识此模板(>=256 表示数据模板)
     */
    bit<16> template_id;
    
    /* Field Count - 16 bits
     * 字段计数 - 16 位
     * Number of fields in this template record
     * 此模板记录中的字段数
     */
    bit<16> field_count;
}

/**
 * IPFIX Template Field Specifier
 * IPFIX 模板字段定义
 */
header ipfix_field_specifier {
    /* Enterprise Bit - 1 bit
     * 企业位 - 1 位
     * 0 = IETF defined field, 1 = vendor defined field
     * 0 表示 IETF 定义字段，1 表示厂商定义字段
     */
    bit<1> enterprise_bit;
    
    /* Field ID - 15 bits
     * 字段 ID - 15 位
     * Identifies the field (IANA assigned)
     * 标识字段(由 IANA 分配)
     */
    bit<15> field_id;
    
    /* Field Length - 16 bits
     * 字段长度 - 16 位
     * Length of the field in bytes (or 0xFFFF for variable length)
     * 字段的字节长度(0xFFFF 表示可变长度)
     */
    bit<16> field_length;
    
    /* Enterprise Number - 32 bits (optional)
     * 企业号 - 32 位(可选)
     * Present if enterprise_bit=1 (vendor defined field)
     * 当 enterprise_bit=1 时存在(厂商定义字段)
     */
    bit<32> enterprise_number; // Conditional field
}

/**
 * IPFIX Data Record
 * IPFIX 数据记录
 */
header ipfix_data_record {
    /* Fields - variable length
     * 字段 - 可变长度
     * Actual flow data as specified by the template
     * 根据模板定义的实际流数据
     */
    varbit<65535> fields;  // Maximum size limited by set length
}

/**
 * Common Flow Fields (Example)
 * 常见流字段定义(示例)
 */
header ipfix_common_flow_fields {
    /* Source IPv4 Address - 32 bits
     * 源 IPv4 地址 - 32 位
     * Field ID 8 in IANA registry
     * IANA 注册表中的字段 ID 8
     */
    bit<32> source_ipv4_address;
    
    /* Destination IPv4 Address - 32 bits
     * 目的 IPv4 地址 - 32 位
     * Field ID 12 in IANA registry
     * IANA 注册表中的字段 ID 12
     */
    bit<32> destination_ipv4_address;
    
    /* Source Transport Port - 16 bits
     * 源传输端口 - 16 位
     * Field ID 7 in IANA registry
     * IANA 注册表中的字段 ID 7
     */
    bit<16> source_transport_port;
    
    /* Destination Transport Port - 16 bits
     * 目的传输端口 - 16 位
     * Field ID 11 in IANA registry
     * IANA 注册表中的字段 ID 11
     */
    bit<16> destination_transport_port;
    
    /* Protocol Identifier - 8 bits
     * 协议标识符 - 8 位
     * Field ID 4 in IANA registry
     * IANA 注册表中的字段 ID 4
     */
    bit<8> protocol_identifier;
    
    /* Packet Delta Count - 64 bits
     * 数据包增量计数 - 64 位
     * Field ID 2 in IANA registry
     * IANA 注册表中的字段 ID 2
     */
    bit<64> packet_delta_count;
    
    /* Octet Delta Count - 64 bits
     * 字节增量计数 - 64 位
     * Field ID 1 in IANA registry
     * IANA 注册表中的字段 ID 1
     */
    bit<64> octet_delta_count;
}

/**
 * IPFIX Transport Header (typically over UDP or SCTP)
 * IPFIX 传输头(通常基于 UDP 或 SCTP)
 */
header ipfix_transport_header {
    /* Source Port - 16 bits
     * 源端口 - 16 位
     * Typically 4739 for IPFIX
     * IPFIX 通常使用 4739 端口
     */
    bit<16> source_port;
    
    /* Destination Port - 16 bits
     * 目的端口 - 16 位
     * Typically 4739 for IPFIX
     * IPFIX 通常使用 4739 端口
     */
    bit<16> destination_port;
    
    /* Length - 16 bits
     * 长度 - 16 位
     * Length of UDP payload
     * UDP 负载长度
     */
    bit<16> length;
    
    /* Checksum - 16 bits
     * 校验和 - 16 位
     * UDP checksum (optional for IPv4)
     * UDP 校验和(IPv4 下可选)
     */
    bit<16> checksum;
}
