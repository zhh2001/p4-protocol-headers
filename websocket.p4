/**********************************************************
 * WebSocket Header (RFC 6455)
 * WebSocket协议报头 - 用于实现全双工实时通信
 * WebSocket Protocol Header
 * Enables full-duplex real-time communication
 **********************************************************/

header websocket_t {
    bit<1> fin;          // Final frame flag (1=last frame)                 结束帧标志 (1=最后一帧)
    bit<3> rsv;          // Reserved bits (must be 0 unless negotiated)     保留位 (必须为 0，除非扩展定义)
    bit<4> opcode;       // Opcode (e.g., text=1, binary=2, close=8)        操作码 (如文本帧=1, 二进制帧=2, 关闭帧=8)
    bit<1> mask;         // Mask flag (must be 1 for client-to-server)      掩码标志 (客户端到服务器必须为1)
    bit<7> payload_len;  // Base payload length (<=125 uses this directly)  基础载荷长度 (<=125直接表示)

    // 扩展长度字段 (根据 payload_len 动态出现)
    bit<16> ext_len16;    // Extended length (appears when payload_len==126)  扩展长度 (当 payload_len==126 时出现)
    bit<64> ext_len64;    // Extended length (appears when payload_len==127)  扩展长度 (当 payload_len==127 时出现)
    bit<32> masking_key;  // Masking key (appears when mask=1)                掩码密钥 (当 mask=1 时出现)

    // 实际载荷数据 (通过元数据或后续解析处理)
    varbit<256> payload_data;  // Payload data (length determined by above fields)  载荷数据 (长度由前述字段决定)
}