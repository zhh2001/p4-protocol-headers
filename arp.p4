/**
 * ARP and RARP headers (RFC 826 and RFC 903)
 * 通用地址布局、Ethernet/IPv4 报头和分流示例
 */
#ifndef P4_PROTOCOL_HEADERS_ARP_P4
#define P4_PROTOCOL_HEADERS_ARP_P4

#include "ethernet.p4"

const bit<16> ARP_ETHER_TYPE = 16w0x0806;
const bit<16> RARP_ETHER_TYPE = 16w0x8035;

// Selected IANA operation and hardware assignments. Both fields are 16 bits.
// Other registered values can be retained by the generic RFC 826 layout.
enum bit<16> arp_opcode {
    ARP_REQUEST = 1,
    ARP_REPLY = 2,
    RARP_REQUEST = 3,
    RARP_REPLY = 4
}

enum bit<16> arp_hardware_type {
    ETHERNET = 1,
    IEEE802 = 6,
    ARCNET = 7,
    FRAME_RELAY = 15,
    FIBRE_CHANNEL = 18,
    IEEE1394 = 24,
    INFINIBAND = 32
}

// Protocol Type shares the EtherType number space. IPv4 uses ARP on Ethernet.
// IPv6 address resolution uses Neighbor Discovery, described in icmpv6.p4.
// Keeping an unknown Protocol Type does not imply support for its resolution.
enum bit<16> arp_protocol_type {
    IPV4 = 0x0800
}

// Fixed eight-octet prefix for the RFC 826 four-address layout. All multioctet
// fields use network byte order. Lengths count octets, not bits or words.
header arp_prefix {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8> hw_addr_len;
    bit<8> proto_addr_len;
    bit<16> opcode;
}

// Address block follows arp_prefix in this exact order: sender hardware,
// sender protocol, target hardware, target protocol. There is no alignment
// padding between them. Each hardware address uses hw_addr_len octets and
// each protocol address uses proto_addr_len octets. At lengths 255/255, the
// block is 1020 octets (8160 bits). Interpret the regions using the prefix.
header arp_addresses {
    varbit<8160> data;
}

// Typed twenty-octet address block for hardware 1, protocol 0x0800, HLEN 6
// and PLEN 4. Requests may use an unspecified target hardware address.
header arp_ethernet_ipv4_addresses {
    bit<48> sender_hw_addr;
    bit<32> sender_proto_addr;
    bit<48> target_hw_addr;
    bit<32> target_proto_addr;
}

// Complete 28-octet Ethernet/IPv4 view for callers that extract one header.
// Check the four type/length fields before choosing this view. Emit either
// this complete header or arp_prefix followed by a selected address block.
header arp_header {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8> hw_addr_len;
    bit<8> proto_addr_len;
    bit<16> opcode;
    bit<48> sender_hw_addr;
    bit<32> sender_proto_addr;
    bit<48> target_hw_addr;
    bit<32> target_proto_addr;
}

// Ethernet II includes destination, source and EtherType, for 14 octets.
// With VLAN tags, dispatch on the innermost EtherType after parsing the tags.
typedef ethernet_header arp_transport;

// ARP Probes and Announcements (RFC 5227) use ordinary ARP Requests, without
// appended headers. A Probe has sender IPv4 address zero and a candidate
// target IPv4 address. An Announcement has equal sender and target IPv4
// addresses. Both are broadcast and normally use a zero target hardware
// address. Proxy ARP (RFC 1027) uses ordinary ARP Replies with the proxy's
// hardware address. Recognition and responses require interface/route state.

struct arp_metadata_t {
    bit<16> link_type; // ARP or RARP EtherType supplied by the caller
    bit<1> ethernet_ipv4;
    bit<32> address_bytes;
    bit<32> parsed_bytes;
    bit<32> trailing_bytes; // Link padding or other trailing bytes
}

/**
 * Bounded RFC 826 parser
 * The cursor starts at the hardware type. link_type is the validated
 * innermost EtherType, 0x0806 for ARP or 0x8035 for RARP. payload_length is
 * the physically bounded link payload length after Ethernet and any VLAN
 * tags, including padding but excluding an FCS. ARP has no total-length
 * field. The length octets delimit its four address regions.
 *
 * This example applies to the RFC 826/RFC 903 four-address layout. The
 * caller selects a compatible link profile before applying it. Formats
 * that alter the layout, such as IEEE 1394 ARP (RFC 2734), require their
 * own parser. The hardware enum identifies numbers, not a shared layout
 * for every link profile.
 *
 * headers contains arp_prefix arp, arp_ethernet_ipv4_addresses arp_ipv4
 * and arp_addresses arp_addresses. metadata contains arp_metadata_t arp.
 * The example checks the prefix, address bounds, Ethernet HLEN 6 and IPv4
 * PLEN 4. The Ethernet/IPv4 tuple selects typed addresses. Other compatible
 * tuples retain their address bytes without interpreting them. The
 * application validates supported hardware/protocol types, their address
 * lengths and opcode rules before using the addresses. Generic zero lengths
 * are representable and do not establish a valid resolution protocol.
 *
 * Emit arp followed by the valid arp_ipv4 or arp_addresses header. Trailing
 * bytes remain unparsed and unchanged. ARP has no checksum field. Ethernet
 * FCS handling belongs to the target. ARP cache policy, conflict detection,
 * announcements, proxy routing and RARP server mappings belong to the
 * application. No additional Gratuitous ARP or Proxy ARP header is present.
 */
/*
parser arp_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                   in bit<16> link_type, in bit<32> payload_length) {
    bit<32> address_bytes;

    state start {
        hdr.arp.setInvalid();
        hdr.arp_ipv4.setInvalid();
        hdr.arp_addresses.setInvalid();
        meta.arp.link_type = link_type;
        meta.arp.ethernet_ipv4 = 0;
        meta.arp.address_bytes = 0;
        meta.arp.parsed_bytes = 0;
        meta.arp.trailing_bytes = 0;
        verify(link_type == ARP_ETHER_TYPE || link_type == RARP_ETHER_TYPE,
               error.NoMatch);
        verify(payload_length >= 8, error.HeaderTooShort);
        pkt.extract(hdr.arp);
        verify(hdr.arp.hw_type != 1 || hdr.arp.hw_addr_len == 6,
               error.NoMatch);
        verify(hdr.arp.proto_type != 16w0x0800 || hdr.arp.proto_addr_len == 4,
               error.NoMatch);
        address_bytes = ((bit<32>)hdr.arp.hw_addr_len
            + (bit<32>)hdr.arp.proto_addr_len) * 2;
        verify(address_bytes <= payload_length - 8, error.HeaderTooShort);
        meta.arp.address_bytes = address_bytes;
        meta.arp.parsed_bytes = 8 + address_bytes;
        meta.arp.trailing_bytes = payload_length - 8 - address_bytes;
        transition select(hdr.arp.hw_type, hdr.arp.proto_type) {
            (1, 0x0800): parse_ethernet_ipv4;
            default: parse_generic_addresses;
        }
    }

    state parse_ethernet_ipv4 {
        pkt.extract(hdr.arp_ipv4);
        meta.arp.ethernet_ipv4 = 1;
        transition accept;
    }

    state parse_generic_addresses {
        pkt.extract(hdr.arp_addresses, address_bytes * 8);
        transition accept;
    }
}
*/

/**
 * Application dispatch (v1model)
 * handler_port is the default application destination. The link type in the
 * key distinguishes ARP and RARP even when their other fields coincide.
 * Parser errors drop the packet. Accepted packets are forwarded unchanged
 * for the application to validate and process using its interface state.
 */
/*
control arp_control(inout headers hdr, inout metadata meta,
                    inout standard_metadata_t standard_metadata,
                    in bit<9> handler_port) {
    action send_arp(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action send_default() {
        standard_metadata.egress_spec = handler_port;
    }

    table arp_handlers {
        key = {
            meta.arp.link_type: exact;
            hdr.arp.hw_type: exact;
            hdr.arp.proto_type: exact;
            hdr.arp.opcode: exact;
        }
        actions = {
            send_arp;
            send_default;
        }
        default_action = send_default();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.arp.isValid()) {
            mark_to_drop(standard_metadata);
        } else {
            arp_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_ARP_P4
