/**
 * RTP Header Definition in P4
 * RTP 报头 P4 定义
 * Real-time Transport Protocol for media streaming
 * 实时传输协议
 */

/* RTP Payload Types */
enum bit<8> rtp_payload {
    PCMU = 0,
    GSM  = 3,
    G722 = 9,
    OPUS = 96,
};

/**
 * RTP Header
 */
header rtp_t {
    /* Version - 2 bits
     * 版本 - 2 位
     * Identifies the RTP version (current is 2)
     * 标识 RTP 版本(当前为 2)
     */
    bit<2> version;
    
    /* Padding - 1 bit
     * 填充 - 1 位
     * Indicates if the packet contains padding octets
     * 表示数据包是否包含填充字节
     */
    bit<1> padding;
    
    /* Extension - 1 bit
     * 扩展 - 1 位
     * Indicates presence of extension header
     * 表示是否存在扩展头
     */
    bit<1> extension;
    
    /* CSRC count - 4 bits
     * CSRC计数 - 4 位
     * Number of CSRC identifiers that follow the header
     * 报头后的 CSRC 标识符数量
     */
    bit<4> csrc_count;
    
    /* Marker - 1 bit
     * 标记 - 1 位
     * Used at application level, e.g. to mark frame boundaries
     * 在应用层使用，例如标记帧边界
     */
    bit<1> marker;
    
    /* Payload type - 7 bits
     * 负载类型 - 7 位
     * Identifies the format of the payload
     * 标识负载的格式
     */
    bit<7> payload_type;
    
    /* Sequence number - 16 bits
     * 序列号 - 16 位
     * Increments by one for each RTP packet
     * 每个 RTP 数据包递增 1
     */
    bit<16> sequence_number;
    
    /* Timestamp - 32 bits
     * 时间戳 - 32 位
     * Sampling instant of first octet in payload
     * 负载中第一个字节的采样时刻
     */
    bit<32> timestamp;
    
    /* SSRC - 32 bits
     * 同步源标识符 - 32 位
     * Identifies the synchronization source
     * 标识同步源
     */
    bit<32> ssrc;
    
    /* CSRC list - variable length
     * CSRC 列表 - 可变长度
     * Contributing source identifiers
     * 贡献源标识符列表
     */
    bit<32>[15] csrc;  // Maximum of 15 CSRC identifiers
                       // 最多 15 个 CSRC 标识符
}
