/**********************************************************
 * QUIC Header (RFC 9000)
 * 快速UDP互联网连接协议报头 - 下一代HTTP/3传输层协议
 * Quick UDP Internet Connections Header
 * Next-gen transport protocol for HTTP/3
 **********************************************************/

header quic_t {
    // ---- 公共头部字段 (所有 QUIC 报文通用) ----
    bit<1> header_form;  // Header form (1=long, 0=short)  头部格式 (1=长头部, 0=短头部)

    // 长头部特定字段 (当 header_form=1 时)
    bit<1>        fixed_bit;         // Fixed bit (must be 1)                             固定位 (必须为 1)
    bit<2>        long_packet_type;  // Long packet type (Initial/0-RTT/Handshake/Retry)  长包类型 (初始/0-RTT/握手/重传)
    bit<32>       version;           // QUIC version (e.g., 0x00000001=RFC9000)           QUIC 版本 (如 0x00000001=RFC9000)
    bit<8>        dcil;              // Destination Connection ID Length                  目标连接 ID 长度 (字节数)
    bit<8>        scil;              // Source Connection ID Length                       源连接 ID 长度 (字节数)
    bit<64>       length;            // Packet length (bytes remaining)                   报文长度 (剩余部分的字节数)
    varbit<256> dc_id;             // Destination Connection ID                         目标连接ID (长度由 dcil 决定)
    varbit<256> sc_id;             // Source Connection ID                              源连接ID (长度由 scil 决定)

    // 短头部特定字段 (当 header_form=0 时)
    bit<1>        spin_bit;       // Latency spin bit           延迟测量位 (用于 RTT 计算)
    bit<2>        reserved_bits;  // Reserved bits (must be 0)  保留位 (必须为 0)
    // Note: short header dc_id shares the dc_id field above

    // ---- 加密帧头部 (所有 QUIC 版本通用) ----
    bit<8>  packet_number_length;  // Packet number length (1/2/4 bytes)  包号长度 (1/2/4字节)
    bit<64> packet_number;         // Packet number (anti-replay)         包号 (防重放攻击)
    bit<32> frame_type;            // Frame type (e.g., STREAM=0x08)      帧类型 (如 STREAM=0x08)
}