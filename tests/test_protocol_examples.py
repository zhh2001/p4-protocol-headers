"""Compile selected commented examples with p4test and p4c-bm2-ss."""

from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
from textwrap import dedent
import unittest


REPOSITORY = Path(__file__).resolve().parents[1]
COMPILERS = ("p4test", "p4c-bm2-ss")


def example(sources, protocol, kind=None):
    blocks = []
    for block in re.findall(r"/\*(.*?)\*/", sources[protocol + ".p4"], re.DOTALL):
        declaration = kind or "(?:parser|control)"
        if re.search(r"^\s*" + declaration + r"\s+\w+", block, re.MULTILINE):
            blocks.append(block)
    if not blocks:
        raise ValueError(f"{protocol}.p4: no {kind or 'parser/control'} example")
    return "\n".join(blocks)


def payload_states(parser, names):
    position = parser.rindex("}")
    states = "\n".join(
        f"    state {name} {{ transition accept; }}" for name in names)
    return parser[:position] + states + "\n" + parser[position:]


def program(includes, headers, metadata, examples, parser, ingress, emit,
            verify="apply {}", compute="apply {}"):
    source = "#include <core.p4>\n#include <v1model.p4>\n"
    source += "".join(f'#include "{name}.p4"\n' for name in includes)
    source += f"struct headers {{ {headers} }}\n"
    source += f"struct metadata {{ {metadata} }}\n"
    source += "\n".join(examples)
    source += f"""
parser ExampleParser(packet_in pkt, out headers hdr, inout metadata meta,
                     inout standard_metadata_t sm) {{
{dedent(parser)}
}}
control ExampleVerify(inout headers hdr, inout metadata meta) {{
{dedent(verify)}
}}
control ExampleIngress(inout headers hdr, inout metadata meta,
                       inout standard_metadata_t sm) {{
{dedent(ingress)}
}}
control ExampleEgress(inout headers hdr, inout metadata meta,
                      inout standard_metadata_t sm) {{ apply {{}} }}
control ExampleCompute(inout headers hdr, inout metadata meta) {{
{dedent(compute)}
}}
control ExampleDeparser(packet_out pkt, in headers hdr) {{
    apply {{ {" ".join(f"pkt.emit(hdr.{name});" for name in emit)} }}
}}
V1Switch(ExampleParser(), ExampleVerify(), ExampleIngress(), ExampleEgress(),
         ExampleCompute(), ExampleDeparser()) main;
"""
    return source


IP_PARSERS = """
    ipv4_parser() ip4;
    ipv6_parser() ip6;
    state start {
        meta.more_fragments = false;
        // Protocol initialization.
        pkt.extract(hdr.ethernet_header);
        transition select(hdr.ethernet_header.ether_type) {
            ether_type.IPv4: parse_ipv4;
            ether_type.IPv6: parse_ipv6;
            default: accept;
        }
    }
    state parse_ipv4 {
        ip4.apply(pkt, hdr.ipv4_header, meta.ipv4, sm.packet_length - 14);
        verify(hdr.ipv4_header.protocol == UPPER_PROTOCOL
               && hdr.ipv4_header.fragment_offset == 0
               && hdr.ipv4_header.mf == 0, error.NoMatch);
        meta.payload_bytes = meta.ipv4.payload_bytes;
        meta.more_fragments = hdr.ipv4_header.mf == 1;
        transition parse_payload;
    }
    state parse_ipv6 {
        ip6.apply(pkt, hdr.ipv6_header, meta.ipv6, sm.packet_length - 14);
        verify(hdr.ipv6_header.next_header == UPPER_PROTOCOL
               && meta.ipv6.length_known, error.NoMatch);
        meta.payload_bytes = meta.ipv6.payload_bytes;
        transition parse_payload;
    }
"""

IP_HEADERS = """
    ethernet_header ethernet_header;
    ipv4_header ipv4_header;
    ipv6_header ipv6_header;
"""

IP_METADATA = """
    ipv4_metadata_t ipv4;
    ipv6_metadata_t ipv6;
    bit<32> payload_bytes;
    bool more_fragments;
"""


class ProtocolExampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compilers = {name: shutil.which(name) for name in COMPILERS}
        missing = [name for name, path in cls.compilers.items() if path is None]
        if missing:
            raise unittest.SkipTest("Missing P4 compiler(s): " + ", ".join(missing))
        cls.sources = {path.name: path.read_text(encoding="utf-8")
                       for path in REPOSITORY.glob("*.p4")}

    def compile_program(self, source):
        with tempfile.TemporaryDirectory(prefix="p4-example-tests-") as directory:
            work = Path(directory)
            include = work / "include"
            include.mkdir()
            for name, contents in self.sources.items():
                (include / name).write_text(contents, encoding="utf-8")
            (work / "example.p4").write_text(source, encoding="utf-8")
            for name, executable in self.compilers.items():
                with self.subTest(compiler=name):
                    command = [executable, "--std", "p4-16", "--Wdisable=unused",
                               "--Werror", "-I", "include", "example.p4"]
                    if name == "p4c-bm2-ss":
                        command.extend(["-o", "example.json"])
                    result = subprocess.run(command, cwd=work, capture_output=True,
                                            encoding="utf-8", errors="replace",
                                            timeout=60)
                    self.assertEqual(result.returncode, 0,
                                     shlex.join(command) + "\n"
                                     + result.stdout + result.stderr)

    def test_ethernet(self):
        parser = payload_states(example(self.sources, "ethernet", "parser"),
                                ("parse_ipv4", "parse_ipv6", "parse_arp"))
        self.compile_program(program(
            includes=("ethernet",),
            headers="ethernet_header ethernet_header; dot1q_header[2] vlan;",
            metadata="bit<1> unused;",
            examples=(parser, example(self.sources, "ethernet", "control")),
            parser="""
                ethernet_parser() ethernet;
                state start { ethernet.apply(pkt, hdr); transition accept; }
            """,
            ingress="""
                ethernet_control() ethernet;
                apply { ethernet.apply(hdr, sm); }
            """,
            emit=("ethernet_header", "vlan")))

    def test_vlan_before_ethernet_forwarding(self):
        self.compile_program(program(
            includes=("ethernet", "vlan"),
            headers="ethernet_header ethernet_header; vlan_header[2] vlan;",
            metadata="bit<1> unused;",
            examples=(example(self.sources, "vlan"),
                      example(self.sources, "ethernet", "control")),
            parser="""
                vlan_parser() vlan;
                state start {
                    pkt.extract(hdr.ethernet_header);
                    vlan.apply(pkt, hdr.ethernet_header.ether_type, hdr.vlan);
                    transition accept;
                }
            """,
            ingress="""
                vlan_control() vlan;
                ethernet_control() ethernet;
                apply { vlan.apply(hdr, sm); ethernet.apply(hdr, sm); }
            """,
            emit=("ethernet_header", "vlan")))

    def test_ipv4_and_ipv6_forwarding(self):
        self.compile_program(program(
            includes=("ethernet", "ipv4", "ipv6"),
            headers=IP_HEADERS,
            metadata="ipv4_metadata_t ipv4; ipv6_metadata_t ipv6;",
            examples=(example(self.sources, "ipv4"), example(self.sources, "ipv6")),
            parser="""
                ipv4_parser() ip4;
                ipv6_parser() ip6;
                state start {
                    pkt.extract(hdr.ethernet_header);
                    transition select(hdr.ethernet_header.ether_type) {
                        ether_type.IPv4: parse_ipv4;
                        ether_type.IPv6: parse_ipv6;
                        default: accept;
                    }
                }
                state parse_ipv4 {
                    ip4.apply(pkt, hdr.ipv4_header, meta.ipv4, sm.packet_length - 14);
                    transition accept;
                }
                state parse_ipv6 {
                    ip6.apply(pkt, hdr.ipv6_header, meta.ipv6, sm.packet_length - 14);
                    transition accept;
                }
            """,
            ingress="""
                ipv4_control() ip4;
                ipv6_control() ip6;
                apply {
                    if (hdr.ipv4_header.isValid()) {
                        ip4.apply(hdr, meta, sm, (bit<9>)3);
                    } else if (hdr.ipv6_header.isValid()) {
                        ip6.apply(hdr, meta, sm, (bit<9>)3);
                    } else { mark_to_drop(sm); }
                }
            """,
            verify="""
                ipv4_verify_checksum() checksum;
                apply { checksum.apply(hdr, meta); }
            """,
            compute="""
                ipv4_compute_checksum() checksum;
                apply { checksum.apply(hdr, meta); }
            """,
            emit=("ethernet_header", "ipv4_header", "ipv6_header")))

    def test_arp_after_ethernet(self):
        self.compile_program(program(
            includes=("arp",),
            headers="""
                ethernet_header ethernet_header;
                arp_prefix arp;
                arp_ethernet_ipv4_addresses arp_ipv4;
                arp_addresses arp_addresses;
            """,
            metadata="arp_metadata_t arp;",
            examples=(example(self.sources, "arp"),),
            parser="""
                arp_parser() arp;
                state start {
                    pkt.extract(hdr.ethernet_header);
                    arp.apply(pkt, hdr.arp, hdr.arp_ipv4, hdr.arp_addresses, meta.arp,
                              hdr.ethernet_header.ether_type, sm.packet_length - 14);
                    transition accept;
                }
            """,
            ingress="""
                arp_control() arp;
                apply { arp.apply(hdr, meta, sm, (bit<9>)3); }
            """,
            emit=("ethernet_header", "arp", "arp_ipv4", "arp_addresses")))

    def test_dns_after_udp_or_tcp(self):
        self.compile_program(program(
            includes=("ethernet", "ipv4", "udp", "tcp", "dns"),
            headers="""
                ethernet_header ethernet_header;
                ipv4_header ipv4_header;
                udp_header udp_header;
                tcp_headers_t tcp;
                dns_tcp_length dns_length;
                dns_header dns_header;
            """,
            metadata="ipv4_metadata_t ipv4; udp_metadata_t udp; tcp_metadata_t tcp;",
            examples=(example(self.sources, "ipv4", "parser"),
                      example(self.sources, "udp", "parser"),
                      example(self.sources, "tcp", "parser"),
                      example(self.sources, "dns")),
            parser="""
                ipv4_parser() ip;
                udp_parser() udp;
                tcp_parser() tcp;
                dns_parser() dns;
                state start {
                    pkt.extract(hdr.ethernet_header);
                    ip.apply(pkt, hdr.ipv4_header, meta.ipv4, sm.packet_length - 14);
                    verify(hdr.ipv4_header.fragment_offset == 0
                           && hdr.ipv4_header.mf == 0, error.NoMatch);
                    transition select(hdr.ipv4_header.protocol) {
                        ip_protocol.UDP: parse_udp;
                        ip_protocol.TCP: parse_tcp;
                        default: accept;
                    }
                }
                state parse_udp {
                    udp.apply(pkt, hdr.udp_header, meta.udp, meta.ipv4.payload_bytes,
                              hdr.ipv4_header.mf == 1);
                    verify(hdr.udp_header.src_port == 53 || hdr.udp_header.dst_port == 53,
                           error.NoMatch);
                    verify(meta.udp.payload_bytes >= 12, error.HeaderTooShort);
                    dns.apply(pkt, hdr.dns_header);
                    transition accept;
                }
                state parse_tcp {
                    tcp.apply(pkt, hdr.tcp, meta.tcp, meta.ipv4.payload_bytes);
                    verify(hdr.tcp.base.src_port == 53 || hdr.tcp.base.dst_port == 53,
                           error.NoMatch);
                    verify(meta.tcp.payload_bytes >= 2, error.HeaderTooShort);
                    pkt.extract(hdr.dns_length);
                    verify(hdr.dns_length.length >= 12, error.HeaderTooShort);
                    verify((bit<32>)hdr.dns_length.length <= meta.tcp.payload_bytes - 2,
                           error.PacketTooShort);
                    dns.apply(pkt, hdr.dns_header);
                    transition accept;
                }
            """,
            ingress="""
                dns_control() dns;
                apply {
                    if (sm.parser_error != error.NoError) { mark_to_drop(sm); }
                    else { dns.apply(hdr, sm); }
                }
            """,
            emit=("ethernet_header", "ipv4_header", "udp_header", "tcp.base",
                  "tcp.parsed_options", "tcp.padding", "dns_length", "dns_header")))

    def test_gre_after_ipv4_or_ipv6(self):
        gre = payload_states(example(self.sources, "gre", "parser"),
                             ("parse_inner_ip", "parse_inner_ipv6", "parse_mpls",
                              "parse_inner_ethernet", "parse_erspan"))
        self.compile_program(program(
            includes=("ethernet", "ipv4", "ipv6", "gre"),
            headers=IP_HEADERS + """
                gre_header gre_header;
                gre_checksum_header gre_checksum;
                gre_key_header gre_key;
                gre_sequence_header gre_sequence;
            """,
            metadata=IP_METADATA,
            examples=(example(self.sources, "ipv4", "parser"),
                      example(self.sources, "ipv6", "parser"), gre,
                      example(self.sources, "gre", "control")),
            parser="gre_parser() gre;\n" + IP_PARSERS.replace("UPPER_PROTOCOL", "47") + """
                state parse_payload {
                    bit<16> flags;
                    bit<32> header_bytes;
                    verify(meta.payload_bytes >= 4, error.HeaderTooShort);
                    flags = pkt.lookahead<bit<16>>();
                    header_bytes = 4;
                    if (flags[15:15] == 1) { header_bytes = header_bytes + 4; }
                    if (flags[13:13] == 1) { header_bytes = header_bytes + 4; }
                    if (flags[12:12] == 1) { header_bytes = header_bytes + 4; }
                    verify(header_bytes <= meta.payload_bytes, error.PacketTooShort);
                    gre.apply(pkt, hdr.gre_header, hdr.gre_checksum, hdr.gre_key,
                              hdr.gre_sequence);
                    transition accept;
                }
            """,
            ingress="""
                gre_control() gre;
                apply { gre.apply(hdr, sm); }
            """,
            emit=("ethernet_header", "ipv4_header", "ipv6_header", "gre_header",
                  "gre_checksum", "gre_key", "gre_sequence")))

    def test_ntp_after_udp(self):
        parser = IP_PARSERS.replace("UPPER_PROTOCOL", "17").replace(
            "// Protocol initialization.",
            "meta.ntp.version = 0; meta.ntp.mode = 0; meta.ntp.opaque_length = 0;")
        self.compile_program(program(
            includes=("ethernet", "ipv4", "ipv6", "udp", "ntp"),
            headers=IP_HEADERS + "udp_header udp_header; ntp_header ntp_header;",
            metadata=IP_METADATA + "udp_metadata_t udp; ntp_metadata_t ntp;",
            examples=(example(self.sources, "ipv4", "parser"),
                      example(self.sources, "ipv6", "parser"),
                      example(self.sources, "udp", "parser"),
                      example(self.sources, "ntp")),
            parser="udp_parser() udp;\nntp_parser() ntp;\n" + parser + """
                state parse_payload {
                    udp.apply(pkt, hdr.udp_header, meta.udp, meta.payload_bytes,
                              meta.more_fragments);
                    verify(hdr.udp_header.src_port == NTP_UDP_PORT
                           || hdr.udp_header.dst_port == NTP_UDP_PORT, error.NoMatch);
                    ntp.apply(pkt, hdr.ntp_header, meta.ntp,
                              (bit<16>)meta.udp.payload_bytes);
                    transition accept;
                }
            """,
            ingress="""
                ntp_control() ntp;
                apply { ntp.apply(hdr, meta, sm); }
            """,
            emit=("ethernet_header", "ipv4_header", "ipv6_header", "udp_header",
                  "ntp_header")))


if __name__ == "__main__":
    unittest.main()
