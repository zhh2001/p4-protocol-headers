/**********************************************************
 * EAP / 802.1X Header (RFC 3748 / IEEE 802.1X)
 * 可扩展认证协议报头 - 网络访问控制
 * Extensible Authentication Protocol Header
 * Port-based network access control
 **********************************************************/

// 802.1X Authentication Header
header dot1x_t {
    bit<8>  version;       // Protocol version (1 or 2)     协议版本
    bit<8>  type;          // Packet type                   报文类型
    bit<16> length;        // Body length                   报文体长度
}

// EAP Packet Header
header eap_t {
    bit<8>  code;          // Code (1=Request 2=Response 3=Success 4=Failure) 代码
    bit<8>  identifier;    // Identifier (match req/resp)   标识符 (匹配请求/响应)
    bit<16> length;        // Total EAP packet length       EAP 报文总长度
    bit<8>  type;          // EAP method type               EAP 方法类型
}

// 802.1X 报文类型常量
const bit<8> DOT1X_EAP_PACKET    = 8w0x00;  // EAP 报文
const bit<8> DOT1X_EAPOL_START   = 8w0x01;  // EAPOL 开始
const bit<8> DOT1X_EAPOL_LOGOFF  = 8w0x02;  // EAPOL 注销
const bit<8> DOT1X_EAPOL_KEY     = 8w0x03;  // EAPOL 密钥

// EAP 代码常量
const bit<8> EAP_CODE_REQUEST  = 8w1;  // 请求
const bit<8> EAP_CODE_RESPONSE = 8w2;  // 响应
const bit<8> EAP_CODE_SUCCESS  = 8w3;  // 成功
const bit<8> EAP_CODE_FAILURE  = 8w4;  // 失败

// EAP 方法类型常量
const bit<8> EAP_TYPE_IDENTITY = 8w1;   // 身份识别
const bit<8> EAP_TYPE_NAK      = 8w3;   // 否定应答
const bit<8> EAP_TYPE_MD5      = 8w4;   // MD5 挑战
const bit<8> EAP_TYPE_TLS      = 8w13;  // EAP-TLS
const bit<8> EAP_TYPE_PEAP     = 8w25;  // PEAP
const bit<8> EAP_TYPE_MSCHAPV2 = 8w26;  // MS-CHAPv2

// 802.1X EtherType
const bit<16> ETHERTYPE_DOT1X = 16w0x888E;
