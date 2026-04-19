/**********************************************************
 * VRRP Header (RFC 5798)
 * 虚拟路由器冗余协议报头 - 网关高可用
 * Virtual Router Redundancy Protocol Header
 * First-hop router redundancy for gateway failover
 **********************************************************/

header vrrp_t {
    bit<4>  version;       // Version (3 for VRRPv3)       版本号 (VRRPv3 为 3)
    bit<4>  type;          // Packet type (1=Advertisement) 报文类型 (1=通告)
    bit<8>  vrid;          // Virtual router ID             虚拟路由器标识符
    bit<8>  priority;      // Priority (0-255, 255=owner)   优先级 (0-255, 255=地址拥有者)
    bit<8>  count_ipaddr;  // Number of IP addresses        IP 地址数量
    bit<4>  rsvd;          // Reserved                      保留字段
    bit<12> max_adver_int; // Advertisement interval (cs)   通告间隔 (厘秒)
    bit<16> checksum;      // Checksum                      校验和
}

// VRRPv3 IPv4 地址条目
header vrrp_ipv4_addr_t {
    bit<32> addr;          // Virtual IPv4 address           虚拟 IPv4 地址
}

// VRRPv3 IPv6 地址条目
header vrrp_ipv6_addr_t {
    bit<128> addr;         // Virtual IPv6 address           虚拟 IPv6 地址
}

// VRRP 常量
const bit<4> VRRP_TYPE_ADVERTISEMENT = 1;    // 通告报文
const bit<8> VRRP_PRIORITY_OWNER     = 8w255; // 地址拥有者优先级
const bit<8> VRRP_PRIORITY_DEFAULT   = 8w100; // 默认优先级
const bit<8> VRRP_PRIORITY_STOP      = 8w0;   // 停止参与选举
const bit<8> VRRP_IP_PROTO           = 8w112; // IP 协议号
