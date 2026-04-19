typedef bit<8>  stt_flag_t;
typedef bit<16> port_t;

// Stateless Transport Tunneling  一种基于 TCP 伪装的网络虚拟化封装协议
header stt_t {
    // TCP 伪头部 (64 bits) - 用于兼容中间设备
    // TCP-like pseudo header
    port_t  src_port;    // 固定为 7471
    port_t  dest_port;   // 固定为 7471  
    bit<32> seq_number;  // 序列号（用于 ECMP 哈希）

    // STT 控制头部 (64 bits)
    // STT control header
    stt_flag_t flags;      // 控制标志位
    bit<24>    vni;        // 24 位虚拟网络 ID
    bit<16>    l4_offset;  // 内层 L4 头部偏移量
    bit<16>    reserved;   // 保留字段

    // 可选上下文头部 (0-256 bits)
    // Optional context headers
    varbit<2048> context;
}

// 标志位定义
const stt_flag_t STT_FLAG_CSUM   = 8w0x80;  // 需要校验和卸载
const stt_flag_t STT_FLAG_DF     = 8w0x40;  // 禁止分片标志
const stt_flag_t STT_FLAG_MACSEC = 8w0x20;  // MACsec 加密标志

// 上下文类型常量
const bit<16> STT_CTX_VLAN     = 16w0x0001;  // VLAN 标签
const bit<16> STT_CTX_GRO      = 16w0x0002;  // 大接收卸载参数
const bit<16> STT_CTX_SECURITY = 16w0x0003;  // 安全标签


// Example: TCP 伪装机制 (Pseudocode)
/*
action set_tcp_pseudo() {
    stt_t.src_port = 16w0x1D2F;  // 7471
    stt_t.dest_port = 16w0x1D2F;
    stt_t.seq_number = hash(ipv4.src, ipv4.dst);
}
*/

// Example: 硬件卸载支持 (Pseudocode)
/*
action enable_csum_offload() {
    stt_t.flags |= STT_FLAG_CSUM;
    stt_t.l4_offset = 16w64;  // 内层 L4 头部位置
}
*/

// Example: 多租户隔离 (Pseudocode)
/*
action set_vni_context() {
    stt_t.vni = tenant_id << 8 | app_id;
    stt_t.context = {security_tag, qos_profile};
}
*/


// 典型工作流程：
//     1. 封装阶段：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action stt_encapsulate() {
    stt_t.setValid();
    stt_t.flags = STT_FLAG_DF;
    stt_t.vni = lookup_vni(inner_ethernet.dst);
}
*/
//     2. 传输阶段：
//         - 中间设备视为普通 TCP 流量
//         - 支持 ECMP 哈希（基于伪序列号）
//     3. 解封装阶段：
/*
parser stt_inner_parser {
    extract(stt_t);
    move(stt_t.l4_offset);  // 跳转到内层报文
    extract(inner_packet);
}
*/
//     4. 异常处理：
/*
action handle_malformed() {
    stt_t.setInvalid();
    send_to_controller(inner_packet);
}
*/
