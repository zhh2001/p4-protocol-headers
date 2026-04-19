/**
 * INT Header Definition in P4
 * 带内网络遥测(INT)协议P4定义
 * 
 * Note: INT provides real-time network state collection
 *       带内网络遥测协议定义，用于实时网络状态采集
 */

/* INT Instruction Types */
enum bit<8> int_instruction_type {
    INT_INSTR_0 = 0,    // 保留指令
    INT_INSTR_1 = 1,    // 交换级元数据采集
    INT_INSTR_2 = 2,    // 流量级元数据采集
    INT_INSTR_3 = 3     // 自定义元数据采集
}

/**
 * INT Shim Header (4 bytes)
 * INT Shim头(4字节)
 */
header int_shim_header {
    /* Type - 4 bits
     * 类型 - 4位
     * 0x1 for INT
     * INT固定为0x1
     */
    bit<4> type;
    
    /* Reserved - 2 bits
     * 保留位 - 2位
     * Must be zero
     * 必须为零
     */
    bit<2> reserved;
    
    /* Length - 5 bits
     * 长度 - 5位
     * Number of 4-byte words in INT header
     * INT头中的4字节字数
     */
    bit<5> length;
    
    /* DSCP - 6 bits
     * 差分服务代码点 - 6位
     * Copy from outer header
     * 从外层头复制
     */
    bit<6> dscp;
    
    /* Reserved - 8 bits
     * 保留位 - 8位
     * Must be zero
     * 必须为零
     */
    bit<8> reserved2;
    
    /* Next Protocol - 8 bits
     * 下一协议 - 8位
     * Protocol type of next header
     * 下一头的协议类型
     */
    bit<8> next_protocol;
}

/**
 * INT Metadata Header (8 bytes)
 * INT元数据头(8字节)
 */
header int_metadata_header {
    /* Instruction Bitmap - 16 bits
     * 指令位图 - 16位
     * Specifies which metadata to collect
     * 指定要收集的元数据类型
     */
    bit<16> instruction_bitmap;
    
    /* Hop Count - 8 bits
     * 跳数 - 8位
     * Number of INT capable switches traversed
     * 经过的INT能力交换机数量
     */
    bit<8> hop_count;
    
    /* Remaining Hop Count - 8 bits
     * 剩余跳数 - 8位
     * Number of INT switches remaining
     * 剩余的INT交换机数量
     */
    bit<8> remaining_hop_count;
    
    /* Sequence Number - 16 bits
     * 序列号 - 16位
     * Packet sequence number
     * 数据包序列号
     */
    bit<16> sequence_number;
    
    /* Domain ID - 16 bits
     * 域ID - 16位
     * Administrative domain identifier
     * 管理域标识符
     */
    bit<16> domain_id;
}

/**
 * INT Switch Metadata (8 bytes per hop)
 * INT交换机元数据(每跳8字节)
 */
header int_switch_metadata {
    /* Switch ID - 32 bits
     * 交换机ID - 32位
     * Unique identifier for the switch
     * 交换机的唯一标识符
     */
    bit<32> switch_id;
    
    /* Ingress Port - 16 bits
     * 入口端口 - 16位
     * Ingress port identifier
     * 入口端口标识符
     */
    bit<16> ingress_port;
    
    /* Egress Port - 16 bits
     * 出口端口 - 16位
     * Egress port identifier
     * 出口端口标识符
     */
    bit<16> egress_port;
    
    /* Timestamp - 48 bits
     * 时间戳 - 48位
     * Nanoseconds since epoch (truncated)
     * 自纪元起的纳秒数(截断)
     */
    bit<48> timestamp;
    
    /* Queue Occupancy - 24 bits
     * 队列占用率 - 24位
     * Current queue depth in bytes
     * 当前队列深度(字节)
     */
    bit<24> queue_occupancy;
    
    /* Ingress Port Utilization - 16 bits
     * 入口端口利用率 - 16位
     * Percentage of port bandwidth used
     * 端口带宽使用百分比
     */
    bit<16> ingress_util;
    
    /* Egress Port Utilization - 16 bits
     * 出口端口利用率 - 16位
     * Percentage of port bandwidth used
     * 端口带宽使用百分比
     */
    bit<16> egress_util;
    
    /* Queue Congestion - 8 bits
     * 队列拥塞 - 8位
     * Percentage of queue buffer used
     * 队列缓冲区使用百分比
     */
    bit<8> queue_congestion;
    
    /* Reserved - 8 bits
     * 保留位 - 8位
     * Must be zero
     * 必须为零
     */
    bit<8> reserved;
}

/**
 * INT Flow Metadata (16 bytes)
 * INT流元数据(16字节)
 */
header int_flow_metadata {
    /* Source IP - 32 bits
     * 源IP - 32位
     * IPv4 source address
     * IPv4源地址
     */
    bit<32> src_ip;
    
    /* Destination IP - 32 bits
     * 目的IP - 32位
     * IPv4 destination address
     * IPv4目的地址
     */
    bit<32> dst_ip;
    
    /* Source Port - 16 bits
     * 源端口 - 16位
     * Transport layer source port
     * 传输层源端口
     */
    bit<16> src_port;
    
    /* Destination Port - 16 bits
     * 目的端口 - 16位
     * Transport layer destination port
     * 传输层目的端口
     */
    bit<16> dst_port;
    
    /* Protocol - 8 bits
     * 协议 - 8位
     * IP protocol number
     * IP协议号
     */
    bit<8> protocol;
    
    /* DSCP - 6 bits
     * 差分服务代码点 - 6位
     * Differentiated Services Code Point
     * 差分服务代码点
     */
    bit<6> dscp;
    
    /* ECN - 2 bits
     * 显式拥塞通知 - 2位
     * Explicit Congestion Notification
     * 显式拥塞通知
     */
    bit<2> ecn;
    
    /* VLAN ID - 12 bits
     * VLAN ID - 12位
     * VLAN identifier
     * VLAN标识符
     */
    bit<12> vlan_id;
    
    /* VLAN Priority - 3 bits
     * VLAN优先级 - 3位
     * VLAN priority code point
     * VLAN优先级代码点
     */
    bit<3> vlan_priority;
    
    /* Reserved - 1 bit
     * 保留位 - 1位
     * Must be zero
     * 必须为零
     */
    bit<1> reserved;
}

/**
 * INT Report Header (20 bytes)
 * INT报告头(20字节)
 */
header int_report_header {
    /* Version - 4 bits
     * 版本 - 4位
     * INT report version (0x1)
     * INT报告版本(0x1)
     */
    bit<4> version;
    
    /* Reserved - 4 bits
     * 保留位 - 4位
     * Must be zero
     * 必须为零
     */
    bit<4> reserved;
    
    /* Report Length - 16 bits
     * 报告长度 - 16位
     * Length of report in bytes
     * 报告的字节长度
     */
    bit<16> length;
    
    /* Sequence Number - 32 bits
     * 序列号 - 32位
     * Report sequence number
     * 报告序列号
     */
    bit<32> sequence_number;
    
    /* Domain ID - 16 bits
     * 域ID - 16位
     * Administrative domain identifier
     * 管理域标识符
     */
    bit<16> domain_id;
    
    /* Collector IP - 32 bits
     * 收集器IP - 32位
     * IPv4 address of INT collector
     * INT收集器的IPv4地址
     */
    bit<32> collector_ip;
    
    /* Collector Port - 16 bits
     * 收集器端口 - 16位
     * UDP port of INT collector
     * INT收集器的UDP端口
     */
    bit<16> collector_port;
    
    /* Reserved - 16 bits
     * 保留位 - 16位
     * Must be zero
     * 必须为零
     */
    bit<16> reserved2;
}

/**
 * INT Transport Header (UDP)
 * INT传输头(UDP)
 */
header int_transport_header {
    /* Source Port - 16 bits
     * 源端口 - 16位
     * Random high port number
     * 随机高端口号
     */
    bit<16> source_port;
    
    /* Destination Port - 16 bits
     * 目的端口 - 16位
     * Typically 32766 for INT reports
     * INT报告通常使用32766端口
     */
    bit<16> destination_port;
    
    /* Length - 16 bits
     * 长度 - 16位
     * Length of UDP payload
     * UDP负载长度
     */
    bit<16> length;
    
    /* Checksum - 16 bits
     * 校验和 - 16位
     * UDP checksum (optional for IPv4)
     * UDP校验和(IPv4下可选)
     */
    bit<16> checksum;
}
