/**
 * sFlow Header Definition in P4
 * sFlow 协议 P4 定义
 * 
 * Note: sFlow is a sampling technology for high-speed networks
 *       高速网络流量采样技术定义
 */

/* sFlow Version */
enum bit<8> sflow_version {
    V5 = 5  // Current version is 5
}

/**
 * sFlow Datagram Header (20 bytes)
 * sFlow 数据报头(20 字节)
 */
header sflow_datagram_header {
    /* Version - 32 bits
     * 版本 - 32 位
     * sFlow version number (current is 5)
     * sFlow 版本号(当前为 5)
     */
    bit<32> version;
    
    /* Agent Address - 32 bits
     * 代理地址 - 32 位
     * IPv4 address of sampling agent
     * 采样代理的 IPv4 地址
     */
    bit<32> agent_address;
    
    /* Sub Agent ID - 32 bits
     * 子代理 ID - 32 位
     * Used when multiple agents share same IP
     * 当多个代理共享相同 IP 时使用
     */
    bit<32> sub_agent_id;
    
    /* Sequence Number - 32 bits
     * 序列号 - 32 位
     * Incremented with each sample datagram
     * 每个采样数据报递增
     */
    bit<32> sequence_number;
    
    /* System Uptime - 32 bits
     * 系统运行时间 - 32 位
     * Milliseconds since agent startup
     * 代理启动后的毫秒数
     */
    bit<32> uptime;
    
    /* Number of Samples - 32 bits
     * 样本数量 - 32 位
     * Number of samples in this datagram
     * 此数据报中的样本数量
     */
    bit<32> sample_count;
}

/**
 * sFlow Sample Header (8 bytes)
 * sFlow 样本头(8 字节)
 */
header sflow_sample_header {
    /* Sample Type - 32 bits
     * 样本类型 - 32 位
     * 1 = Flow sample, 2 = Counter sample
     * 1 = 流样本, 2 = 计数器样本
     */
    bit<32> sample_type;
    
    /* Sample Length - 32 bits
     * 样本长度 - 32 位
     * Length of sample data in bytes
     * 样本数据的字节长度
     */
    bit<32> sample_length;
}

/**
 * sFlow Flow Sample Record (variable length)
 * sFlow 流样本记录(可变长度)
 */
header sflow_flow_sample {
    /* Sequence Number - 32 bits
     * 序列号 - 32 位
     * Incremented with each flow sample
     * 每个流样本递增
     */
    bit<32> sequence_number;
    
    /* Source ID Type - 32 bits
     * 源 ID 类型 - 32 位
     * 0 = ifIndex, 1 = smonVlanDataSource
     * 0 = 接口索引, 1 = VLAN数据源
     */
    bit<32> source_id_type;
    
    /* Source ID Index - 32 bits
     * 源 ID 索引 - 32 位
     * Interface index where sample was taken
     * 采样接口的索引
     */
    bit<32> source_id_index;
    
    /* Sampling Rate - 32 bits
     * 采样率 - 32 位
     * 1 in N packets are sampled
     * 每 N 个数据包采样 1 个
     */
    bit<32> sampling_rate;
    
    /* Sample Pool - 32 bits
     * 样本池 - 32 位
     * Total packets seen since last sample
     * 自上次采样后看到的总数据包数
     */
    bit<32> sample_pool;
    
    /* Dropped Packets - 32 bits
     * 丢弃的数据包 - 32 位
     * Packets dropped due to lack of resources
     * 由于资源不足而丢弃的数据包
     */
    bit<32> dropped_packets;
    
    /* Input Interface - 32 bits
     * 输入接口 - 32 位
     * ifIndex of input interface
     * 输入接口的 ifIndex
     */
    bit<32> input_interface;
    
    /* Output Interface - 32 bits
     * 输出接口 - 32 位
     * ifIndex of output interface (0=unknown)
     * 输出接口的ifIndex(0=未知)
     */
    bit<32> output_interface;
    
    /* Record Count - 32 bits
     * 记录数 - 32 位
     * Number of flow records in this sample
     * 此样本中的流记录数
     */
    bit<32> record_count;
}

/**
 * sFlow Flow Record (variable length)
 * sFlow 流记录(可变长度)
 */
header sflow_flow_record {
    /* Data Format - 32 bits
     * 数据格式 - 32 位
     * Type of flow data (1=raw packet, 2=Ethernet, etc.)
     * 流数据类型(1=原始数据包, 2=以太网等)
     */
    bit<32> data_format;
    
    /* Flow Data Length - 32 bits
     * 流数据长度 - 32 位
     * Length of flow data in bytes
     * 流数据的字节长度
     */
    bit<32> flow_data_length;
}

/**
 * sFlow Raw Packet Header (variable length)
 * sFlow 原始数据包头(可变长度)
 */
header sflow_raw_packet_header {
    /* Protocol - 32 bits
     * 协议 - 32 位
     * 1 = Ethernet, 11 = 802.2, etc.
     * 1 = 以太网, 11 = 802.2 等
     */
    bit<32> protocol;
    
    /* Frame Length - 32 bits
     * 帧长度 - 32 位
     * Original length of packet
     * 数据包的原始长度
     */
    bit<32> frame_length;
    
    /* Stripped Bytes - 32 bits
     * 剥离字节数 - 32 位
     * Bytes removed before sampling
     * 采样前移除的字节数
     */
    bit<32> stripped_bytes;
    
    /* Header Length - 32 bits
     * 头长度 - 32 位
     * Length of sampled header
     * 采样头的长度
     */
    bit<32> header_length;
    
    /* Header Bytes - variable
     * 头字节 - 可变
     * Actual header bytes (typically 128 bytes)
     * 实际头字节(通常 128 字节)
     */
    varbit<1024> header_bytes;
}

/**
 * sFlow Counter Sample Record (variable length)
 * sFlow 计数器样本记录(可变长度)
 */
header sflow_counter_sample {
    /* Sequence Number - 32 bits
     * 序列号 - 32 位
     * Incremented with each counter sample
     * 每个计数器样本递增
     */
    bit<32> sequence_number;
    
    /* Source ID Type - 32 bits
     * 源 ID 类型 - 32 位
     * Same as flow sample
     * 与流样本相同
     */
    bit<32> source_id_type;
    
    /* Source ID Index - 32 bits
     * 源 ID 索引 - 32 位
     * Interface/VLAN being counted
     * 被计数的接口/VLAN
     */
    bit<32> source_id_index;
    
    /* Record Count - 32 bits
     * 记录数 - 32 位
     * Number of counter records
     * 计数器记录数
     */
    bit<32> record_count;
}

/**
 * sFlow Counter Record (variable length)
 * sFlow 计数器记录(可变长度)
 */
header sflow_counter_record {
    /* Counter Format - 32 bits
     * 计数器格式 - 32 位
     * Type of counter (1=ifCounters, 2=Ethernet, etc.)
     * 计数器类型(1=接口计数器,2=以太网等)
     */
    bit<32> counter_format;
    
    /* Counter Data Length - 32 bits
     * 计数器数据长度 - 32 位
     * Length of counter data in bytes
     * 计数器数据的字节长度
     */
    bit<32> counter_data_length;
}

/**
 * sFlow Interface Counters (36 bytes)
 * sFlow 接口计数器(36 字节)
 */
header sflow_if_counters {
    /* ifIndex - 32 bits
     * 接口索引 - 32 位
     * Interface index
     * 接口索引
     */
    bit<32> if_index;
    
    /* ifType - 32 bits
     * 接口类型 - 32 位
     * Interface type (IANA ifType)
     * 接口类型(IANA ifType)
     */
    bit<32> if_type;
    
    /* ifSpeed - 64 bits
     * 接口速度 - 64 位
     * Bits per second
     * 每秒比特数
     */
    bit<64> if_speed;
    
    /* ifDirection - 32 bits
     * 接口方向 - 32 位
     * 0=unknown, 1=full-duplex, etc.
     * 0=未知, 1=全双工等
     */
    bit<32> if_direction;
    
    /* ifStatus - 32 bits
     * 接口状态 - 32 位
     * Bitmap of interface status flags
     * 接口状态标志位图
     */
    bit<32> if_status;
    
    /* ifInOctets - 64 bits
     * 输入字节数 - 64 位
     * Octets received
     * 接收的字节数
     */
    bit<64> if_in_octets;
    
    /* ifInPackets - 32 bits
     * 输入数据包数 - 32 位
     * Packets received
     * 接收的数据包数
     */
    bit<32> if_in_packets;
    
    /* ifInErrors - 32 bits
     * 输入错误数 - 32 位
     * Receive errors
     * 接收错误数
     */
    bit<32> if_in_errors;
    
    /* ifOutOctets - 64 bits
     * 输出字节数 - 64 位
     * Octets transmitted
     * 发送的字节数
     */
    bit<64> if_out_octets;
    
    /* ifOutPackets - 32 bits
     * 输出数据包数 - 32 位
     * Packets transmitted
     * 发送的数据包数
     */
    bit<32> if_out_packets;
    
    /* ifOutErrors - 32 bits
     * 输出错误数 - 32 位
     * Transmit errors
     * 发送错误数
     */
    bit<32> if_out_errors;
}

/**
 * sFlow Transport Header (typically over UDP)
 * sFlow 传输头(通常基于 UDP)
 */
header sflow_transport_header {
    /* Source Port - 16 bits
     * 源端口 - 16 位
     * Typically random high port
     * 通常为随机高端口
     */
    bit<16> source_port;
    
    /* Destination Port - 16 bits
     * 目的端口 - 16 位
     * Typically 6343 for sFlow
     * sFlow通常使用6343端口
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
