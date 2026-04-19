/**
 * TCP Header Definition in P4
 * TCP 报头 P4 定义
 */

typedef bit<16> port_t;

header tcp_t {
    /* Source port - 16 bits
     * 源端口 - 16 位
     * Identifies the sending port
     * 标识发送端口
     */
    port_t  src_port;

    /* Destination port - 16 bits
     * 目的端口 - 16 位
     * Identifies the receiving port
     * 标识接收端口
     */
    port_t  dst_port;

    /* Sequence number - 32 bits
     * 序列号 - 32 位
     * For identifying the first data octet in this segment
     * 用于标识此段中第一个数据字节
     */
    bit<32> seq_no;

    /* Acknowledgment number - 32 bits
     * 确认号 - 32 位
     * If ACK is set, contains the next sequence number expected
     * 如果设置了 ACK，包含期望的下一个序列号
     */
    bit<32> ack_no;

    /* Data offset - 4 bits
     * 数据偏移 - 4 位
     * Specifies the size of the TCP header in 32-bit words
     * 指定 TCP 报头大小(以 32 位字为单位)
     */
    bit<4>  data_offset;

    /* Reserved - 3 bits
     * 保留位 - 3 位
     * For future use, must be zero
     * 保留供将来使用，必须为零
     */
    bit<3>  res;

    /* Flags - 9 bits
     * 标志位 - 9 位
     * Contains 9 1-bit flags (NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)
     * 包含 9 个 1 位标志(NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)
     */
    bit<1>  ns;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;

    /* Window size - 16 bits
     * 窗口大小 - 16 位
     * The size of the receive window
     * 接收窗口的大小
     */
    bit<16> window;

    /* Checksum - 16 bits
     * 校验和 - 16 位
     * For error-checking of the header and data
     * 用于报头和数据的错误检查
     */
    bit<16> checksum;

    /* Urgent pointer - 16 bits
     * 紧急指针 - 16位
     * If URG flag is set, points to the last urgent data byte
     * 如果设置了 URG 标志，指向最后一个紧急数据字节
     */
    bit<16> urgent_ptr;

    /* Options - variable length
     * 选项 - 可变长度
     * Optional fields, length is determined by data_offset
     * 可选字段，长度由 data_offset 确定
     */
    varbit<320> options;  // Maximum options size is 40 bytes (320 bits)
                          // 最大选项大小为 40 字节(320 位)
}
