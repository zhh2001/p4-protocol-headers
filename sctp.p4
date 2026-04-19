/**********************************************************
 * SCTP Header (RFC 4960)
 * 流控制传输协议报头 - 提供可靠的多流消息传输
 * Stream Control Transmission Protocol Header
 * Provides reliable multi-stream message delivery
 **********************************************************/

header sctp_t {
    bit<16> src_port;          // Source port (similar to TCP/UDP ports)    源端口号 (类似 TCP/UDP 端口)
    bit<16> dst_port;          // Destination port                          目标端口号 (类似 TCP/UDP 端口)
    bit<32> verification_tag;  // Verification tag (connection identifier)  验证标签 (连接标识符)
    bit<32> checksum;          // Checksum (covers entire SCTP packet)      校验和 (覆盖整个 SCTP 报文)

    // ---- 数据块通用头部 (每个块单独存在) ----
    bit<8>  chunk_type;    // Chunk type (e.g., DATA=0, INIT=1)  块类型 (如 DATA=0, INIT=1)
    bit<8>  chunk_flags;   // Chunk flags (type-dependent)       块标志位 (类型相关)
    bit<16> chunk_length;  // Chunk length (including header)    块总长度 (包括头部)

    // ---- DATA块特定字段 (当 chunk_type=0 时) ----
    bit<32> tsn;            // Transmission Sequence Number  传输序列号 (可靠性保障)
    bit<16> stream_id;      // Stream identifier             流标识符 (多路复用)
    bit<16> stream_seq;     // Stream sequence number        流内序列号 (有序交付)
    bit<32> payload_proto;  // Payload protocol identifier   载荷协议标识 (如 SCTP PPID)

    // ---- INIT块特定字段 (当 chunk_type=1 时) ----
    bit<32> init_tag;       // Initiate tag                初始验证标签
    bit<32> a_rwnd;         // Advertised receiver window  通告接收窗口大小
    bit<16> n_out_streams;  // Number of outbound streams  输出流数量
    bit<16> n_in_streams;   // Number of inbound streams   输入流数量
    bit<32> initial_tsn;    // Initial TSN                 初始 TSN
}