/**********************************************************
 * TWAMP Header (RFC 5357)
 * 双向主动测量协议报头 - 网络性能测量
 * Two-Way Active Measurement Protocol Header
 * Measures network performance (latency, jitter, loss)
 **********************************************************/

// TWAMP-Test Sender Packet
header twamp_test_t {
    bit<32> sequence_number;    // Sequence number                  序列号
    bit<32> timestamp_sec;      // Timestamp seconds (NTP format)   时间戳秒 (NTP 格式)
    bit<32> timestamp_frac;     // Timestamp fraction               时间戳小数部分
    bit<16> error_estimate;     // Error estimate                   误差估计
    bit<16> mbz;                // Must be zero                     必须为零
}

// TWAMP-Test Reflector Packet (additional fields)
header twamp_reflect_t {
    bit<32> sequence_number;       // Sequence number               序列号
    bit<32> timestamp_sec;         // Timestamp seconds             时间戳秒
    bit<32> timestamp_frac;        // Timestamp fraction            时间戳小数部分
    bit<16> error_estimate;        // Error estimate                误差估计
    bit<16> mbz1;                  // Must be zero                  必须为零
    bit<32> recv_timestamp_sec;    // Receive timestamp seconds     接收时间戳秒
    bit<32> recv_timestamp_frac;   // Receive timestamp fraction    接收时间戳小数部分
    bit<32> sender_seq;            // Sender sequence number        发送方序列号
    bit<32> sender_timestamp_sec;  // Sender timestamp seconds      发送方时间戳秒
    bit<32> sender_timestamp_frac; // Sender timestamp fraction     发送方时间戳小数部分
    bit<16> sender_error;          // Sender error estimate         发送方误差估计
    bit<16> mbz2;                  // Must be zero                  必须为零
    bit<8>  sender_ttl;            // Sender TTL                    发送方 TTL
}

// TWAMP 默认端口
const bit<16> TWAMP_CONTROL_PORT = 16w862;   // 控制连接端口
const bit<16> TWAMP_TEST_PORT    = 16w863;   // 测试报文端口
