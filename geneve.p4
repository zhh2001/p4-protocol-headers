/**********************************************************
 * GENEVE Header (RFC 8926)                               
 * 通用网络虚拟化封装报头 - 新一代数据中心 overlay 协议        
 * Generic Network Virtualization Encapsulation Header     
 * Next-gen overlay protocol for data centers              
 **********************************************************/

typedef bit<16> protocol_t;
typedef bit<16> opt_class_t;
typedef bit<8>  opt_type_t;

header geneve_t {
    // 基础头部 (64 bits)
    // Base header (64 bits)
    bit<2>     version;        // 版本号（固定为 0）
    bit<6>     opt_len;        // 选项长度（单位 4 字节）
    bit<1>     oam_pkt;        // OAM 报文标志
    bit<1>     critical_opt;   // 关键选项存在标志
    bit<24>    vni;            // 虚拟网络标识符
    bit<8>     reserved;       // 保留字段
    protocol_t protocol;       // 内层协议类型： 0x6558=以太网 0x0800=IPv4

    // 可变长选项头 (0-512 bits)
    // Variable options (RFC 8926)
    // geneve_option_t[16] options;  // (removed: nested header reference)
}

// Geneve 选项结构
header geneve_option_t {
    opt_class_t opt_class;      // 选项类别
    opt_type_t  opt_type;       // 选项类型
    bit<1>      critical;       // 关键选项标志
    bit<7>      reserved;       // 保留位
    bit<8>      opt_length;     // 选项长度（不含头部）
    varbit<512> opt_data;       // 选项值
}

// 常用选项常量
const opt_class_t GENEVE_CLASS_NVO3 = 0x0102;  // 网络虚拟化选项
const opt_class_t GENEVE_CLASS_NSH  = 0x0103;  // 服务链集成
const opt_type_t  GENEVE_TYPE_TTL   = 0x01;    // TTL 控制选项
const opt_type_t  GENEVE_TYPE_ECMP  = 0x02;    // 负载均衡哈希

// 协议类型扩展
const protocol_t GENEVE_PROTO_NSH   = 0x894F;  // NSH 封装
const protocol_t GENEVE_PROTO_MPLS  = 0x8847;  // MPLS 封装


/* ====== 关键特性说明 Start ====== */

// Example 1: 多租户隔离 (Pseudocode)
/*
action set_vni() {
    geneve_t.vni = tenant_id << 8 | vlan_id;  // 24 位虚拟网络 ID
}
*/

// Example 2: 动态选项处理 (Pseudocode)
/*
action add_ecmp_option() {
    geneve_option_t.opt_class = GENEVE_CLASS_NVO3;
    geneve_option_t.opt_type = GENEVE_TYPE_ECMP;
    geneve_option_t.opt_data = hash(ipv4.src, ipv4.dst);
}
*/

// Example 3: 服务链集成 (Pseudocode)
/*
action encapsulate_nsh() {
    geneve_t.protocol = GENEVE_PROTO_NSH;
    geneve_t.options[0].opt_class = GENEVE_CLASS_NSH;
}
*/

/* ====== 关键特性说明 End ====== */


// 典型工作流程：
//     1. 虚拟网络封装：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
table vxlan_to_geneve {
    key = {
        vxlan.vni: exact;
    }
    actions = {
        geneve_encap;
        drop;
    }
    size = 4096;
}
*/
//     2. 选项处理流水线：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
parser geneve_option_parser {
    extract(geneve_t.options);
    while (options_left > 0) {
        extract(current_option);
        process_option(current_option);
    }
}
*/
//     3. 跨域传输：
//         - 基于 VNI 的虚拟网络路由
//         - 使用选项携带 QoS 策略信息
//     4. 终端解封装：( ↓↓↓ Example, Pseudocode ↓↓↓ )
/*
action terminate_geneve() {
    geneve_t.setInvalid();
    inner_ethernet.setValid();
}
*/
