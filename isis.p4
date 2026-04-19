typedef bit<8> isisTlv_t;

// Intermediate System to Intermediate System
header isis_t {
    // 网络层协议标识 (8 bits) - 0x83 表示 IS-IS
    // NLPID (8 bits) - 0x83 indicates IS-IS
    bit<8>   nlpid;

    // 长度标识符 (8 bits) - 头部长度指示符
    // Length indicator (8 bits) - Header length marker
    bit<8>   length_indicator;

    // 协议数据单元类型 (8 bits) - PDU 类型：
    // PDU Type (8 bits) - Packet type:
    //   0x0F=L1 Hello  0x11=L2 Hello
    //   0x12=P2P Hello 0x14=L1 LSP
    //   0x16=L2 LSP    0x18=L1 CSNP
    bit<8>   pdu_type;

    // 版本 (8 bits) - 固定为 0x01
    // Version (8 bits) - Fixed to 0x01
    bit<8>   version;

    // 系统 ID 长度 (8 bits) - 通常为 6 字节
    // System ID length (8 bits) - Typically 6 bytes
    bit<8>   system_id_len;

    // 保留字段 (8 bits) - 必须置 0
    // Reserved (8 bits) - Must be zero
    bit<8>   reserved;

    // 最大区域地址 (8 bits) - 支持的最大区域数
    // Max area addresses (8 bits) - Supported areas count
    bit<8>   max_area_addr;

    // PDU 特定头部 (可变长度) - 根据 PDU 类型变化
    // PDU-specific header (variable) - Depends on PDU type
    varbit<256> pdu_specific;
}

header isis_lsp_t {
    // PDU长度 (16 bits) - 整个 PDU 的字节长度
    // PDU length (16 bits) - Total PDU length
    bit<16>  pdu_length;

    // 剩余生存时间 (16 bits) - LSP 存活时间(秒)
    // Remaining lifetime (16 bits) - LSP TTL in seconds
    bit<16>  remaining_lifetime;

    // 链路状态 ID (可变长度) - 系统 ID + 伪节点 ID
    // LSP ID (variable) - System ID + Pseudonode ID
    varbit<128> lsp_id;

    // 序列号 (32 bits) - LSP 更新序号
    // Sequence number (32 bits) - LSP update counter
    bit<32>  sequence_number;

    // 校验和 (16 bits) - LSP 内容校验和
    // Checksum (16 bits) - LSP content checksum
    bit<16>  checksum;

    // 类型块 (可变长度) - TLV 编码的链路状态信息
    // Type blocks (variable) - TLV-encoded link state info
    varbit<2048> tlvs;
}


// 关键 TLV 类型常量（RFC 1195）
const isisTlv_t ISIS_TLV_AREA_ADDR     = 8w1;    // 区域地址
const isisTlv_t ISIS_TLV_IS_NEIGHBORS  = 8w2;    // IS 邻居
const isisTlv_t ISIS_TLV_ES_NEIGHBORS  = 8w3;    // ES 邻居
const isisTlv_t ISIS_TLV_AUTH          = 8w10;   // 认证信息
const isisTlv_t ISIS_TLV_IP_INTF       = 8w132;  // IPv4 接口地址
const isisTlv_t ISIS_TLV_IP_REACH      = 8w133;  // IPv4 可达性
const isisTlv_t ISIS_TLV_EXTD_IP_REACH = 8w135;  // 扩展 IP 可达性
const isisTlv_t ISIS_TLV_HOSTNAME      = 8w137;  // 设备主机名


/**
 * 典型工作流程
 *     1. 邻居发现：通过 IIH Hello 报文建立邻接关系
 *     2. 链路状态传播：使用 LSP（链路状态 PDU）洪泛拓扑信息
 *     3. 数据库同步：通过 CSNP/PSNP 报文确保 LSDB 一致性
 *     4. SPF 计算：基于 Dijkstra 算法计算最短路径树
 */
