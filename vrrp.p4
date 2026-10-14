#ifndef P4_PROTOCOL_HEADERS_VRRP_P4
#define P4_PROTOCOL_HEADERS_VRRP_P4

/**
 * Virtual Router Redundancy Protocol version 3 (RFC 9568)
 * VRRPv3 固定报头、地址列表和通告接收示例
 * RFC 9568 replaces RFC 5798. Receive checks include verified errata
 * 8298, 8299, 8300 and 8301.
 */

const bit<4> VRRP_VERSION = 3;
const bit<4> VRRP_TYPE_ADVERTISEMENT = 1;
const bit<8> VRRP_PRIORITY_OWNER = 255;
const bit<8> VRRP_PRIORITY_DEFAULT = 100;
const bit<8> VRRP_PRIORITY_STOP = 0;
const bit<8> VRRP_IP_PROTO = 112;
const bit<8> VRRP_HOP_LIMIT = 255;
const bit<12> VRRP_DEFAULT_ADVER_INTERVAL = 100;
const bit<32> VRRP_IPV4_MULTICAST = 0xe0000012; // 224.0.0.18
const bit<128> VRRP_IPV6_MULTICAST = 0xff020000000000000000000000000012;
const bit<40> VRRP_IPV4_MAC_PREFIX = 0x00005e0001;
const bit<40> VRRP_IPV6_MAC_PREFIX = 0x00005e0002;

/* Fixed advertisement header, eight bytes.
 * VRID = 1-255, Count = 1-255. Address width follows the enclosing IP version.
 * Priority = 255 for the address owner, 1-254 for backup routers (default 100).
 * Priority = 0 announces that the Active Router has stopped participating.
 * Reserve is zero on transmission and ignored on reception.
 * Max Advertise Interval is 1-4095 centiseconds, default 100 (one second).
 * The checksum covers this header and every advertised address. IPv4 uses
 * only the VRRP message. IPv6 also uses its pseudo-header with Next Header 112.
 */
header vrrp_t {
    bit<4> version;
    bit<4> type;
    bit<8> vrid;
    bit<8> priority;
    bit<8> count_ipaddr;
    bit<4> rsvd;
    bit<12> max_adver_int;
    bit<16> checksum;
}

header vrrp_ipv4_addr_t {
    bit<32> addr;
}

/* The first advertised IPv6 address is the Virtual Router's link-local
 * address. IPv4 and IPv6 addresses occupy separate VRRP instances.
 */
header vrrp_ipv6_addr_t {
    bit<128> addr;
}

/* Storage for addresses after the first one, in their original order.
 * Count permits at most 254 remaining addresses: 1016 IPv4 bytes or 4064
 * IPv6 bytes. This field is part of the address list, not an extension.
 */
header vrrp_address_tail_t {
    varbit<32512> addresses;
}

struct vrrp_headers_t {
    vrrp_t base;
    vrrp_ipv4_addr_t first_ipv4;
    vrrp_ipv6_addr_t first_ipv6;
    vrrp_address_tail_t address_tail;
};

struct vrrp_metadata_t {
    bool is_ipv6;
    bit<32> message_bytes;
    bit<32> address_bytes;
    bit<16> checksum_residue; // Zero complement after summing the received checksum.
};

/* Validated enclosing IP context. IPv4 addresses occupy the low 32 bits.
 * protocol is the upper-layer protocol after any IPv6 extension headers.
 */
struct vrrp_ip_context_t {
    bit<4> version;
    bit<8> protocol;
    bit<8> hop_limit;
    bit<128> src_addr;
    bit<128> dst_addr;
};

/**
 * Complete advertisement parsing, checksum verification and local delivery
 * example (P4_16, v1model). The cursor points to the VRRP header. outer_bytes
 * is its IP upper-layer length, excluding IP headers, extensions and link
 * padding. The caller validates IP framing and completes IP reassembly.
 * This example requires exactly one fixed header and Count addresses.
 *
 * Instantiate vrrp_verify_checksum in the architecture's VerifyChecksum
 * stage, then vrrp_control in ingress. IPv6 checksum length is the VRRP
 * message length, excluding extension headers. Reserve bits are preserved
 * and included in the checksum. Emit base, first_ipv4, first_ipv6 and
 * address_tail in order, followed by untouched link padding.
 *
 * interface_id identifies the receiving logical interface. The table keys
 * on interface, address family and VRID, with entries for configured local
 * instances. The handler compares configured addresses/intervals and runs
 * the election and timers. Address owners also receive advertisements, as
 * clarified by erratum 8298. Virtual source MACs use the relevant 40-bit
 * prefix above followed by the eight-bit VRID.
 */
/*
parser vrrp_parser(packet_in pkt, out vrrp_headers_t hdr,
                   out vrrp_metadata_t meta, in bit<32> outer_bytes,
                   in vrrp_ip_context_t ip) {
    state start {
        meta.is_ipv6 = ip.version == 6;
        meta.message_bytes = 0;
        meta.address_bytes = 0;
        meta.checksum_residue = 0;
        verify(ip.version == 4 || ip.version == 6, error.NoMatch);
        verify(ip.protocol == VRRP_IP_PROTO
               && ip.hop_limit == VRRP_HOP_LIMIT, error.NoMatch);
        transition select(ip.version) {
            4: check_ipv4;
            default: check_ipv6;
        }
    }

    state check_ipv4 {
        verify(ip.dst_addr == (bit<128>)VRRP_IPV4_MULTICAST, error.NoMatch);
        transition parse_header;
    }

    state check_ipv6 {
        verify(ip.dst_addr == VRRP_IPV6_MULTICAST
               && ip.src_addr[127:118] == 10w0x3fa, error.NoMatch);
        transition parse_header;
    }

    state parse_header {
        verify(outer_bytes >= 8, error.HeaderTooShort);
        pkt.extract(hdr.base);
        verify(hdr.base.version == VRRP_VERSION
               && hdr.base.type == VRRP_TYPE_ADVERTISEMENT, error.NoMatch);
        verify(hdr.base.vrid != 0 && hdr.base.count_ipaddr != 0
               && hdr.base.max_adver_int != 0, error.NoMatch);
        transition select(meta.is_ipv6) {
            true: parse_ipv6_addresses;
            default: parse_ipv4_addresses;
        }
    }

    state parse_ipv4_addresses {
        meta.address_bytes = (bit<32>)hdr.base.count_ipaddr * 4;
        meta.message_bytes = 8 + meta.address_bytes;
        verify(meta.message_bytes == outer_bytes, error.NoMatch);
        pkt.extract(hdr.first_ipv4);
        pkt.extract(hdr.address_tail, (meta.address_bytes - 4) * 8);
        transition accept;
    }

    state parse_ipv6_addresses {
        meta.address_bytes = (bit<32>)hdr.base.count_ipaddr * 16;
        meta.message_bytes = 8 + meta.address_bytes;
        verify(meta.message_bytes == outer_bytes, error.NoMatch);
        pkt.extract(hdr.first_ipv6);
        verify(hdr.first_ipv6.addr[127:118] == 10w0x3fa, error.NoMatch);
        pkt.extract(hdr.address_tail, (meta.address_bytes - 16) * 8);
        transition accept;
    }
}

control vrrp_verify_checksum(in vrrp_headers_t hdr,
                            in vrrp_metadata_t meta,
                            in vrrp_ip_context_t ip) {
    apply {
        verify_checksum(hdr.base.isValid() && hdr.address_tail.isValid()
                        && meta.is_ipv6, {
            ip.src_addr, ip.dst_addr, meta.message_bytes, 24w0,
            VRRP_IP_PROTO, hdr.base.version, hdr.base.type,
            hdr.base.vrid, hdr.base.priority, hdr.base.count_ipaddr,
            hdr.base.rsvd, hdr.base.max_adver_int, hdr.base.checksum,
            hdr.first_ipv6.addr, hdr.address_tail.addresses
        }, meta.checksum_residue, HashAlgorithm.csum16);

        verify_checksum(hdr.base.isValid() && hdr.address_tail.isValid()
                        && !meta.is_ipv6, {
            hdr.base.version, hdr.base.type, hdr.base.vrid,
            hdr.base.priority, hdr.base.count_ipaddr, hdr.base.rsvd,
            hdr.base.max_adver_int, hdr.base.checksum, hdr.first_ipv4.addr,
            hdr.address_tail.addresses
        }, meta.checksum_residue, HashAlgorithm.csum16);
    }
}

control vrrp_control(inout vrrp_headers_t hdr,
                     in vrrp_metadata_t meta,
                     inout standard_metadata_t standard_metadata,
                     in bit<32> interface_id) {
    action deliver_vrrp(bit<9> handler_port) {
        standard_metadata.egress_spec = handler_port;
    }

    action drop_vrrp() {
        mark_to_drop(standard_metadata);
    }

    table vrrp_instances {
        key = {
            interface_id: exact;
            meta.is_ipv6: exact;
            hdr.base.vrid: exact;
        }
        actions = {
            deliver_vrrp;
            drop_vrrp;
        }
        default_action = drop_vrrp();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || standard_metadata.checksum_error != 0
            || !hdr.base.isValid()) {
            mark_to_drop(standard_metadata);
        } else {
            vrrp_instances.apply();
        }
    }
}
*/

#endif
