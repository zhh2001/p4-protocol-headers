/**********************************************************
 * IPSec Header (RFC 4301-4309)
 * IP 安全协议报头 - 提供网络层加密与认证
 * Internet Protocol Security Header
 * Provides network-layer encryption and authentication
 **********************************************************/

header ipsec_t {
    // ---- 通用头部字段 ----
    bit<32> spi;      // Security Parameters Index (identifies SA)  安全参数索引 (标识 SA)
    bit<32> seq_num;  // Sequence number (anti-replay)              序列号 (防重放攻击)
    
    // ---- AH (认证头) 特定字段 ----
    bit<16>       ah_length;    // Authentication data length               认证数据长度
    bit<16>       ah_reserved;  // Reserved (must be 0)                     保留字段 (必须为 0)
    varbit<256> auth_data;    // Authentication data (e.g., HMAC-SHA256)  认证数据 (如 HMAC-SHA256)

    // ---- ESP (封装安全载荷) 特定字段 ----
    varbit<256> iv;           // Initialization Vector (for encryption)  初始化向量 (加密算法需要)
    varbit<256> payload;      // Encrypted payload (actual IP packet)    加密载荷 (实际 IP 数据包)
    varbit<256> padding;      // Padding bytes (block alignment)         填充字节 (满足块加密对齐)
    bit<8>        pad_length;   // Padding length                          填充长度
    bit<8>        next_header;  // Next header protocol (e.g., TCP=6)      下一头部协议 (如 TCP=6)
    varbit<256> esp_auth;     // ESP authentication data (optional)      ESP 认证数据 (可选)

    // ---- IKEv2 (密钥交换) 特定字段 ----
    bit<8>    ike_initiator;  // Initiator SPI (first 8 bytes)      发起方 SPI (前 8 字节)
    bit<8>    ike_responder;  // Responder SPI (last 8 bytes)       响应方 SPI (后 8 字节)
    bit<8>    ike_version;    // IKEv2 version (0x20=2.0)           IKEv2 版本 (0x20=2.0)
    bit<8>    ike_exch_type;  // Exchange type (e.g., SA_INIT=34)   交换类型 (如 SA_INIT=34)
    bit<32>   ike_flags;      // Flags (e.g., response/encryption)  标志位 (如响应/加密)
    bit<32>   ike_msg_id;     // Message ID (anti-replay)           消息 ID (防重放)
}
