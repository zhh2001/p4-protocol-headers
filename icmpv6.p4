/**
 * ICMPv6 and Neighbor Discovery options (RFC 4443 and RFC 4861)
 * 复用 ICMPv6 固定报头，按八字节单位解析邻居发现选项
 */
#ifndef P4_PROTOCOL_HEADERS_ICMPV6_P4
#define P4_PROTOCOL_HEADERS_ICMPV6_P4

#include "icmp.p4"

// The common header is four octets. The selected fixed body and remaining
// data follow separately. Echo uses identifier and sequence from icmp.p4.
// Message and echo data lengths come from the enclosing IPv6 packet.
typedef icmpv6_header icmpv6_t;
typedef icmpv6_echo icmpv6_echo_t;

const bit<8> ICMPV6_ND_OPT_SOURCE_LL = 1;
const bit<8> ICMPV6_ND_OPT_TARGET_LL = 2;
const bit<8> ICMPV6_ND_OPT_PREFIX_INFO = 3;
const bit<8> ICMPV6_ND_OPT_REDIRECTED_HEADER = 4;
const bit<8> ICMPV6_ND_OPT_MTU = 5;
const bit<8> ICMPV6_ND_PREFIX_FLAG_ON_LINK = 8w0x80;
const bit<8> ICMPV6_ND_PREFIX_FLAG_AUTONOMOUS = 8w0x40;

// Options can follow Router Solicitation, Router Advertisement, Neighbor
// Solicitation, Neighbor Advertisement and Redirect. length includes type
// and length in units of eight octets. Zero is invalid. At length 255, the
// option is 2040 octets and value is 2038 octets (16304 bits).
header icmpv6_nd_option_t {
    bit<8> type;
    bit<8> length;
    varbit<16304> value;
}

// Source/Target Link-layer Address view for Ethernet, Type 1/2, Length 1.
// Other link types use their own address size and alignment padding.
header icmpv6_nd_ethernet_address_t {
    bit<8> type;
    bit<8> length;
    bit<48> link_layer_address;
}

// Prefix Information, Type 3, Length 4 (32 octets).
// Lifetimes are unsigned seconds. 0xffffffff denotes infinity. The high
// flags bits are L and A. Keep the other bits for assigned extensions.
header icmpv6_nd_prefix_information_t {
    bit<8> type;
    bit<8> length;
    bit<8> prefix_length;
    bit<8> flags;
    bit<32> valid_lifetime;
    bit<32> preferred_lifetime;
    bit<32> reserved;
    bit<128> prefix;
}

// Redirected Header, Type 4. The fixed prefix is eight octets, followed by
// (length * 8 - 8) octets of the invoking packet and alignment padding.
// The capacity below follows the length field. Senders truncate the quote
// so that the entire IPv6 Redirect packet fits the minimum IPv6 MTU.
header icmpv6_nd_redirected_header_t {
    bit<8> type;
    bit<8> length;
    bit<48> reserved;
    varbit<16256> invoking_packet;
}

// MTU, Type 5, Length 1 (eight octets).
header icmpv6_nd_mtu_t {
    bit<8> type;
    bit<8> length;
    bit<16> reserved;
    bit<32> mtu;
}

struct icmpv6_metadata_t {
    bit<1> is_nd;
    bit<16> option_count;
    bit<32> option_bytes;
}

/**
 * Bounded ICMPv6 parser
 * Copy icmp_parser from icmp.p4 together with this example. Use its headers
 * and metadata instances, plus icmpv6_nd_option_t[32] icmpv6_nd_options in
 * headers and icmpv6_metadata_t icmpv6 in metadata. The option stack starts
 * empty and this parser is applied once per message.
 *
 * The cursor starts at the ICMPv6 type octet. Pass the enclosing IPv6
 * header's version field as ip_version. The enclosing parser validates
 * final Next Header 58, physical bounds and message_length,
 * excluding IPv6 extension headers and outer padding. Check the ICMPv6
 * checksum with the IPv6 pseudo-header. ND also needs Hop Limit 255 and
 * the RFC 4861 source/destination checks. RFC 6980 requires discarding these
 * five ND types whenever an IPv6 Fragment Header is present, including an
 * atomic fragment. These IP checks belong to the enclosing implementation.
 *
 * This example extracts the common header and selected fixed body, then
 * all ND options within message_length, accepting up to 32 options. This
 * stack limit is an example resource bound and can be adjusted for a target.
 * ND has no PAD or END option. Unknown and repeated types retain their
 * values and order. The application ignores unknown option types and
 * reserved fields on reception. It checks known option lengths, message
 * applicability, prefix lengths, lifetimes, link MTU and quoted packets
 * before acting.
 *
 * Emit the common header, the valid fixed body and the valid option stack
 * in wire order. Echo data, error quotes and unknown message bodies remain
 * unparsed and unchanged. meta.icmp keeps the fixed-body lengths from the
 * base parser. meta.icmpv6.option_bytes counts the additionally parsed ND
 * options. Neighbor state, timers and response generation belong to the
 * enclosing application.
 */
/*
parser icmpv6_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                     in bit<4> ip_version, in bit<32> message_length) {
    icmp_parser() base;
    bit<32> remaining;
    bit<16> option_prefix;
    bit<8> option_length;
    bit<32> option_octets;
    bit<32> value_bits;

    state start {
        meta.icmpv6.is_nd = 0;
        meta.icmpv6.option_count = 0;
        meta.icmpv6.option_bytes = 0;
        verify(ip_version == 6, error.NoMatch);
        base.apply(pkt, hdr, meta, ip_version, message_length);
        transition select(hdr.icmp.type) {
            133: begin_options;
            134: begin_options;
            135: begin_options;
            136: begin_options;
            137: begin_options;
            default: accept;
        }
    }

    state begin_options {
        verify(hdr.icmp.code == 0, error.NoMatch);
        meta.icmpv6.is_nd = 1;
        remaining = meta.icmp.remainder_bytes;
        transition check_options;
    }

    state check_options {
        transition select(remaining) {
            0: accept;
            default: parse_option;
        }
    }

    state parse_option {
        verify(remaining >= 2, error.HeaderTooShort);
        verify(meta.icmpv6.option_count < 32, error.StackOutOfBounds);
        option_prefix = pkt.lookahead<bit<16>>();
        option_length = (bit<8>)option_prefix;
        verify(option_length != 0, error.NoMatch);
        option_octets = (bit<32>)option_length * 8;
        verify(option_octets <= remaining, error.HeaderTooShort);
        value_bits = (option_octets - 2) * 8;
        pkt.extract(hdr.icmpv6_nd_options.next, value_bits);
        meta.icmpv6.option_count = meta.icmpv6.option_count + 1;
        meta.icmpv6.option_bytes = meta.icmpv6.option_bytes + option_octets;
        remaining = remaining - option_octets;
        transition check_options;
    }
}
*/

/**
 * Application dispatch (v1model)
 * Copy icmp_control from icmp.p4 alongside this wrapper. Its icmp_handlers
 * table routes by IP version, type and code, with handler_port as the default.
 * Parser errors, including malformed ND lengths and stack overflow, drop the
 * packet. An enclosing control also drops packets failing the IP or checksum
 * checks described above. Accepted packets are forwarded unchanged.
 */
/*
control icmpv6_control(inout headers hdr, inout metadata meta,
                       inout standard_metadata_t standard_metadata,
                       in bit<9> handler_port) {
    icmp_control() base;

    apply {
        base.apply(hdr, meta, standard_metadata, handler_port);
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_ICMPV6_P4
