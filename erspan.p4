/**********************************************************
 * ERSPAN Header (RFC 7348 / Cisco)
 * 封装远程端口镜像协议报头 - 跨网络流量镜像
 * Encapsulated Remote Switched Port Analyzer Header
 * Mirrors traffic across L3 networks for monitoring
 **********************************************************/

// ERSPAN Type II Header (8 bytes)
header erspan_type2_t {
    bit<4>  version;    // Version (1 for Type II)       版本号 (Type II 为 1)
    bit<12> vlan_id;    // Original VLAN ID              原始 VLAN 标识符
    bit<3>  cos;        // Class of Service              服务等级
    bit<2>  en;         // Encapsulation type            封装类型
    bit<1>  truncated;  // Truncated flag                截断标志
    bit<10> session_id; // ERSPAN session ID             会话标识符
    bit<12> reserved;   // Reserved                      保留字段
    bit<20> index;      // Port index / timestamp        端口索引/时间戳
}

// ERSPAN Type III Header (12 bytes)
header erspan_type3_t {
    bit<4>  version;      // Version (2 for Type III)    版本号 (Type III 为 2)
    bit<12> vlan_id;      // Original VLAN ID            原始 VLAN 标识符
    bit<3>  cos;          // Class of Service            服务等级
    bit<2>  bso;          // Bad/Short/Oversized         帧状态
    bit<1>  truncated;    // Truncated flag              截断标志
    bit<10> session_id;   // ERSPAN session ID           会话标识符
    bit<32> timestamp;    // Timestamp (100us granularity) 时间戳 (100微秒精度)
    bit<16> sgt;          // Security Group Tag           安全组标签
    bit<1>  pdu;          // PDU flag                     PDU 标志
    bit<5>  frame_type;   // Frame type                   帧类型
    bit<6>  hw_id;        // Hardware ID                  硬件标识符
    bit<1>  direction;    // Direction (0=ingress 1=egress) 方向 (0=入 1=出)
    bit<2>  gra;          // Timestamp granularity        时间戳粒度
    bit<1>  optional;     // Optional subheader present   可选子头部标志
}

// ERSPAN GRE 协议类型常量
const bit<16> GRE_PROTO_ERSPAN_II  = 16w0x88BE;  // ERSPAN Type II
const bit<16> GRE_PROTO_ERSPAN_III = 16w0x22EB;  // ERSPAN Type III
