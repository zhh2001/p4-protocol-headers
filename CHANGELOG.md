# Changelog / 版本变更记录

## v3.0.0

Changes since `v2.0.0` / 相比 `v2.0.0` 的主要变化。

### Definitions

- Update protocol header layouts, field widths, constants and TLVs using the standards and drafts cited in each file.
- Add include guards and share common definitions across files. In `vlan.p4`, rename `dot1q_header` to `vlan_header` and remove the duplicate Ethernet header. Remove duplicate IP headers from `udp.p4` and reuse PTP definitions in `gptp.p4`.
- Define TAS, CBS, CQF and PSFP configuration and metadata as local types.

### Examples and checks

- Update commented parser and control examples for bounded messages, optional fields and TLVs. DNS parsing extracts the fixed header. STT examples separate segment handling from frame parsing after reassembly.
- Update VLAN tag operations and IPv4/IPv6 forwarding examples, including TTL, Hop Limit and IPv4 checksum handling.
- Add [header checks](scripts/check_headers.py) for the catalogue, includes and references in commented examples, plus single-file and joint compilation with `p4test` and `p4c-bm2-ss`.
- Add [checker regression tests](tests/test_check_headers.py) using simulated compilers and [example compilation tests](tests/test_protocol_examples.py) using both real compilers. Seven combinations cover Ethernet/VLAN, IPv4/IPv6 forwarding, ARP, DNS over UDP/TCP, GRE and NTP.
- Add [GitHub Actions checks](.github/workflows/check-headers.yml) with a p4c image pinned by version and digest. Document usage, dependencies and test commands in the README.

### 报头与类型

- 依据各文件引用的标准和草案，调整协议报头布局、字段位宽、常量和 TLV 定义。
- 增加包含保护，复用公共定义。`vlan.p4` 中的 `dot1q_header` 更名为 `vlan_header`，移除重复的以太网报头。`udp.p4` 移除重复的 IP 报头，`gptp.p4` 复用 PTP 定义。
- 使用本地类型定义 TAS、CBS、CQF 和 PSFP 的配置与元数据。

### 示例与检查

- 更新注释中的解析器和控制流程示例，处理消息边界、可选字段和 TLV。DNS 示例提取固定报头，STT 示例分别处理报文段和重组后的完整帧。
- 更新 VLAN 标签操作和 IPv4/IPv6 转发示例，包含 TTL、Hop Limit 和 IPv4 校验和处理。
- 增加[报头检查脚本](scripts/check_headers.py)，检查目录、引用关系和注释示例中的引用，并使用 `p4test` 和 `p4c-bm2-ss` 进行单文件及联合编译。
- 增加使用模拟编译器的[检查脚本回归测试](tests/test_check_headers.py)，以及使用两个真实编译器的[示例编译测试](tests/test_protocol_examples.py)。七组组合覆盖 Ethernet/VLAN、IPv4/IPv6 转发、ARP、基于 UDP/TCP 的 DNS、GRE 和 NTP。
- 增加 [GitHub Actions 检查](.github/workflows/check-headers.yml)，固定 p4c 镜像版本和摘要。在 README 中说明用法、依赖和测试命令。
