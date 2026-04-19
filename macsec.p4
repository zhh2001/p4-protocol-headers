/**********************************************************
 * MACsec Header (IEEE 802.1AE)
 * 媒体访问控制安全协议报头 - 二层加密与完整性保护
 * Media Access Control Security Header
 * Layer 2 encryption and integrity protection
 **********************************************************/

// SecTAG (Security Tag) - 8 or 16 bytes
header macsec_sectag_t {
    bit<16> ether_type;    // EtherType (0x88E5)               以太类型 (0x88E5)
    bit<3>  tci_v;         // Tag Control Info: version         版本号
    bit<1>  tci_es;        // End station flag                  终端站标志
    bit<1>  tci_sc;        // Secure Channel flag               安全通道标志
    bit<1>  tci_scb;       // Single Copy Broadcast flag        单拷贝广播标志
    bit<1>  tci_e;         // Encryption flag                   加密标志
    bit<1>  tci_c;         // Changed text flag                 密文标志
    bit<8>  association_num; // Association number (AN)          关联编号
    bit<8>  short_length;    // Short length                    短长度字段
    bit<32> packet_number;   // Packet number (anti-replay)     包序号 (防重放)
}

// SCI (Secure Channel Identifier) - optional 8 bytes
header macsec_sci_t {
    bit<48> mac_addr;      // Source MAC address                 源 MAC 地址
    bit<16> port_id;       // Port identifier                   端口标识符
}

// ICV (Integrity Check Value) - appended at end
header macsec_icv_t {
    bit<128> icv;          // Integrity check value (AES-GCM-128) 完整性校验值
}

// MACsec 常量
const bit<16> ETHERTYPE_MACSEC = 16w0x88E5;  // MACsec EtherType
