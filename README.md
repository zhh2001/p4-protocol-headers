# P4 Protocol Headers Library

### Welcome!

This repository provides ready-to-use **P4_16** header definitions for common network protocols (L2-L7). All files pass `p4c` compilation. Use freely for research, prototyping, or production.

### Features

- **72 protocols** covering L2 to L4+ (data-plane parseable)
- All files compile cleanly with `p4c --std p4-16`
- Bilingual comments (English + Chinese)
- Includes typedefs, constants, and enum definitions
- Only protocols with fixed binary headers that P4 can actually parse

### Quick Start

Include a header file in your P4 program:

```p4
#include "ethernet.p4"
#include "ipv4.p4"
#include "tcp.p4"
```

### Need Help?

Open an Issue if you:
- Find incorrect header definitions
- Want to request a new protocol
- Need usage examples

### Want to Contribute?

PRs are welcome!

---

# P4 协议报头库

### 欢迎使用！

本仓库提供开箱即用的 **P4_16** 协议报头定义（L2-L7），所有文件均可通过 `p4c` 编译。支持科研、原型开发或生产环境。

### 特性

- **72 个协议**，覆盖 L2 到 L4+（数据面可解析）
- 所有文件均可通过 `p4c --std p4-16` 编译
- 中英双语注释
- 包含 typedef、常量和 enum 定义
- 仅收录 P4 可解析的固定二进制报头协议

### 快速上手

在 P4 程序中引用头文件：

```p4
#include "ethernet.p4"
#include "ipv4.p4"
#include "tcp.p4"
```

### 遇到问题？

欢迎提交 Issue：

- 发现报头定义错误
- 需要新增协议支持
- 需要使用案例

### 参与贡献

接受 PR 贡献！

---

### Protocol List / 协议列表

| Filename | Abbr | Full Name | 中文名称 |
| --- | --- | --- | --- |
| `arp.p4` | ARP | Address Resolution Protocol | 地址解析协议 |
| `bfd.p4` | BFD | Bidirectional Forwarding Detection | 双向转发检测协议 |
| `bgp.p4` | BGP | Border Gateway Protocol | 边界网关协议 |
| `bgp_ls.p4` | BGP-LS | BGP Link-State | BGP 链路状态扩展 |
| `bgp_sr.p4` | BGP-SR | BGP Segment Routing Extensions | BGP 段路由扩展 |
| `bier.p4` | BIER | Bit Index Explicit Replication | 位索引显式复制协议 |
| `capwap.p4` | CAPWAP | Control And Provisioning of Wireless Access Points | 无线接入点控制与配置协议 |
| `cbs.p4` | CBS | Credit-Based Shaper (IEEE 802.1Qav) | 基于信用的流量整形协议 |
| `cqf.p4` | CQF | Cyclic Queuing and Forwarding | 周期性排队与转发协议 |
| `dhcp.p4` | DHCP | Dynamic Host Configuration Protocol | 动态主机配置协议 |
| `dhcpv6.p4` | DHCPv6 | Dynamic Host Configuration Protocol for IPv6 | DHCPv6 动态主机配置协议 |
| `dns.p4` | DNS | Domain Name System | 域名系统协议 |
| `eap.p4` | EAP/802.1X | Extensible Authentication Protocol | 可扩展认证协议 |
| `erspan.p4` | ERSPAN | Encapsulated Remote Switched Port Analyzer | 封装远程端口镜像协议 |
| `ethernet.p4` | Ethernet | Ethernet II (IEEE 802.3) | 以太网协议 |
| `fp.p4` | FP | Frame Preemption (IEEE 802.1Qbu) | 帧抢占协议 |
| `frer.p4` | FRER | Frame Replication and Elimination for Reliability | 帧复制消除协议 |
| `geneve.p4` | GENEVE | Generic Network Virtualization Encapsulation | 通用网络虚拟化封装 |
| `gptp.p4` | gPTP | Generalized Precision Time Protocol | 广义精确时间协议 |
| `gre.p4` | GRE | Generic Routing Encapsulation | 通用路由封装协议 |
| `gtp_u.p4` | GTP-U | GPRS Tunneling Protocol User Plane | GPRS 隧道协议用户面 |
| `icmp.p4` | ICMP | Internet Control Message Protocol | 互联网控制报文协议 |
| `icmpv6.p4` | ICMPv6 | Internet Control Message Protocol for IPv6 | ICMPv6 控制报文协议 |
| `igmp.p4` | IGMP | Internet Group Management Protocol | 互联网组管理协议 |
| `int.p4` | INT | In-band Network Telemetry | 带内网络遥测 |
| `ipfix.p4` | IPFIX | IP Flow Information Export | IP 数据流信息输出 |
| `ipsec.p4` | IPSec | Internet Protocol Security | IP 安全协议 |
| `ipv4.p4` | IPv4 | Internet Protocol version 4 | 互联网协议第 4 版 |
| `ipv6.p4` | IPv6 | Internet Protocol version 6 | 互联网协议第 6 版 |
| `isis.p4` | IS-IS | Intermediate System to Intermediate System | 中间系统到中间系统路由协议 |
| `lacp.p4` | LACP | Link Aggregation Control Protocol | 链路汇聚控制协议 |
| `lisp.p4` | LISP | Locator/Identifier Separation Protocol | 定位/标识分离协议 |
| `lldp.p4` | LLDP | Link Layer Discovery Protocol | 链路层发现协议 |
| `lwapp.p4` | LWAPP | Lightweight Access Point Protocol | 轻量级无线接入点协议 |
| `macsec.p4` | MACsec | Media Access Control Security (IEEE 802.1AE) | 媒体访问控制安全协议 |
| `modbus.p4` | Modbus | Modbus Protocol | Modbus 通讯协议 |
| `mpls.p4` | MPLS | Multi-Protocol Label Switching | 多协议标签交换 |
| `msdp.p4` | MSDP | Multicast Source Discovery Protocol | 组播源发现协议 |
| `nsh.p4` | NSH | Network Service Header | 网络服务头部 |
| `ntp.p4` | NTP | Network Time Protocol | 网络时间协议 |
| `nts.p4` | NTS | Network Time Security | 网络时间安全协议 |
| `nvgre.p4` | NVGRE | Network Virtualization using GRE | 基于 GRE 的网络虚拟化 |
| `ofp.p4` | OpenFlow | OpenFlow Protocol | OpenFlow 协议 |
| `ospf.p4` | OSPF | Open Shortest Path First | 开放式最短路径优先路由协议 |
| `pcep.p4` | PCEP | Path Computation Element Protocol | 路径计算元素协议 |
| `pcep_sr.p4` | PCEP-SR | PCEP for Segment Routing | PCEP 段路由扩展 |
| `pfc.p4` | PFC | Priority-based Flow Control | 基于优先级的流量控制 |
| `pfcp.p4` | PFCP | Packet Forwarding Control Protocol | 报文转发控制协议 |
| `pim.p4` | PIM | Protocol Independent Multicast | 协议无关组播 |
| `pppoe.p4` | PPPoE | Point-to-Point Protocol Over Ethernet | 以太网上的点对点协议 |
| `psfp.p4` | PSFP | Per-Stream Filtering and Policing | 流过滤与监管协议 |
| `ptp.p4` | PTP | Precision Time Protocol (IEEE 1588) | 高精度授时协议 |
| `quic.p4` | QUIC | Quick UDP Internet Connections | 快速 UDP 网络连接 |
| `radius.p4` | RADIUS | Remote Authentication Dial-In User Service | 远程认证拨号用户服务 |
| `rip.p4` | RIP | Routing Information Protocol | 路由信息协议 |
| `rtp.p4` | RTP | Real-time Transport Protocol | 实时传输协议 |
| `sctp.p4` | SCTP | Stream Control Transmission Protocol | 流控制传输协议 |
| `sflow.p4` | sFlow | sFlow Sampling Protocol | sFlow 采样协议 |
| `spb.p4` | SPB | Shortest Path Bridging (IEEE 802.1aq) | 最短路径桥接 |
| `srmpls.p4` | SR-MPLS | Segment Routing MPLS | 基于 MPLS 的段路由 |
| `srv6.p4` | SRv6 | Segment Routing over IPv6 | 基于 IPv6 的段路由 |
| `stp.p4` | STP/RSTP | Spanning Tree Protocol (IEEE 802.1D/w) | 生成树协议 |
| `stt.p4` | STT | Stateless Transport Tunneling | 无状态传输隧道 |
| `tas.p4` | TAS | Time-Aware Shaper (IEEE 802.1Qbv) | 时间感知整形协议 |
| `tcp.p4` | TCP | Transmission Control Protocol | 传输控制协议 |
| `trill.p4` | TRILL | Transparent Interconnection of Lots of Links | 多链路透明互联协议 |
| `twamp.p4` | TWAMP | Two-Way Active Measurement Protocol | 双向主动测量协议 |
| `udp.p4` | UDP | User Datagram Protocol | 用户数据报协议 |
| `vlan.p4` | VLAN | Virtual Local Area Network (IEEE 802.1Q) | 虚拟局域网 |
| `vrrp.p4` | VRRP | Virtual Router Redundancy Protocol | 虚拟路由器冗余协议 |
| `vxlan.p4` | VXLAN | Virtual Extensible Local Area Network | 虚拟可扩展局域网 |
| `vxlan_gpe.p4` | VXLAN-GPE | VXLAN Generic Protocol Extension | VXLAN 通用协议扩展 |
