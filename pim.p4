/*
 * Protocol Independent Multicast version 2
 * 标准报头、Hello 选项和有界控制消息解析示例
 * RFC 7761, RFC 3973, RFC 5015 and RFC 9436
 */
#ifndef P4_PROTOCOL_HEADERS_PIM_P4
#define P4_PROTOCOL_HEADERS_PIM_P4

const bit<8> PIM_IP_PROTOCOL = 103;
const bit<4> PIM_VERSION = 2;
const bit<8> PIM_AF_IPV4 = 1;
const bit<8> PIM_AF_IPV6 = 2;
const bit<8> PIM_ENCODING_NATIVE = 0;
const bit<32> PIM_ALL_ROUTERS_IPV4 = 32w0xe000000d;
const bit<128> PIM_ALL_ROUTERS_IPV6 = 128w0xff02000000000000000000000000000d;

const bit<4> PIM_HELLO = 0;
const bit<4> PIM_REGISTER = 1;
const bit<4> PIM_REGISTER_STOP = 2;
const bit<4> PIM_JOIN_PRUNE = 3;
const bit<4> PIM_BOOTSTRAP = 4;
const bit<4> PIM_ASSERT = 5;
const bit<4> PIM_GRAFT = 6;
const bit<4> PIM_GRAFT_ACK = 7;
const bit<4> PIM_CANDIDATE_RP = 8;
const bit<4> PIM_STATE_REFRESH = 9;
const bit<4> PIM_DF_ELECTION = 10;
const bit<4> PIM_ECMP_REDIRECT = 11;
const bit<4> PIM_FLOODING = 12;

// Common-header flags have meanings specific to the message type.
const bit<8> PIM_NO_FORWARD = 8w0x80; // Bootstrap/PFM, not Register
const bit<8> PIM_STOP_PACKING_CAPABLE = 8w0x01; // RFC 9465
const bit<8> PIM_ASSERT_PACKED = 8w0x01; // RFC 9466
const bit<8> PIM_ASSERT_AGGREGATED = 8w0x02; // RFC 9466
// Types 13..15 use flags[7:4] as a subtype and flags[3:0] as flags.
// DF Election (10) also uses flags[7:4] as its subtype. 15.15 is reserved.
const bit<4> PIM_PACKED_REGISTER_TYPE = 13;
const bit<4> PIM_PACKED_NULL_REGISTER_SUBTYPE = 0;
const bit<4> PIM_PACKED_REGISTER_STOP_SUBTYPE = 1;

const bit<16> PIM_HELLO_HOLDTIME = 1;
const bit<16> PIM_HELLO_LAN_PRUNE_DELAY = 2;
const bit<16> PIM_HELLO_DR_PRIORITY = 19;
const bit<16> PIM_HELLO_GEN_ID = 20;
const bit<16> PIM_HELLO_STATE_REFRESH = 21;
const bit<16> PIM_HELLO_BIDIR_CAPABLE = 22;
const bit<16> PIM_HELLO_ADDR_LIST = 24;
const bit<16> PIM_HELLO_JOIN_ATTRIBUTE = 26;
const bit<16> PIM_HELLO_PACKED_ASSERT = 40;

// Local configuration choices, not a mode field in a PIM packet.
const bit<2> PIM_MODE_DM = 0;
const bit<2> PIM_MODE_SM = 1;
const bit<2> PIM_MODE_SSM = 2;
const bit<2> PIM_MODE_BIDIR = 3;

// Four-octet common header. RFC 9436 calls the second octet Flag Bits.
// Unassigned flags are zero on transmission and ignored on reception.
// checksum covers the complete message except the encapsulated packet
// in Register. Register normally covers only its first eight octets.
// Its handler also accepts legacy full-message checksums for interoperability.
// IPv6 includes a pseudo-header with Next Header 103 and the covered
// PIM length (eight for Register). Checksum validation needs IP context.
header pim_t {
    bit<4> version;
    bit<4> type;
    bit<8> flags;
    bit<16> checksum;
}

// option_length counts value octets, excluding the four-octet prefix.
// There is no implicit padding. The Hello handler ignores unknown options
// without preventing neighbor discovery.
header pim_hello_tlv_t {
    bit<16> option_type;
    bit<16> option_length;
    varbit<524280> option_data;
}

// Alternative Hello option values, excluding the TLV prefix.
header pim_hello_holdtime_t {
    bit<16> holdtime; // Seconds, 0 expires state, 0xffff never expires
}

header pim_hello_lan_prune_delay_t {
    bit<1> tracking_support;
    bit<15> propagation_delay; // Milliseconds
    bit<16> override_interval; // Milliseconds
}

header pim_hello_dr_priority_t {
    bit<32> priority;
}

header pim_hello_generation_id_t {
    bit<32> generation_id;
}

header pim_hello_state_refresh_t {
    bit<8> version; // State Refresh version 1
    bit<8> interval; // Seconds
    bit<16> reserved;
}

// Bidirectional Capable, Join Attribute and Packed Assert Capability have
// zero-length values. Address List contains encoded unicast addresses
// from one family, with no address count or alignment padding.

// Native encoding uses four IPv4 or sixteen IPv6 address octets.
// Encoding 1 adds Join/Prune attributes (RFC 5384 and RFC 7887). These
// headers represent native encoded addresses, not attribute lists.
header pim_unicast_t {
    bit<8> address_family;
    bit<8> encoding_type;
    varbit<128> address;
}

header pim_group_t {
    bit<8> address_family;
    bit<8> encoding_type;
    bit<1> bidirectional;
    bit<6> reserved;
    bit<1> admin_scope_zone;
    bit<8> mask_length;
    varbit<128> address;
}

header pim_source_t {
    bit<8> address_family;
    bit<8> encoding_type;
    bit<5> reserved;
    bit<1> sparse;
    bit<1> wildcard;
    bit<1> rpt;
    bit<8> mask_length;
    varbit<128> address;
}

// Join/Prune: upstream encoded unicast, this four-octet prefix, then
// num_groups repetitions of encoded group, counts, joined sources,
// pruned sources. There is no Join/Prune entry_type octet on the wire.
// All group/source addresses in one message have the same family.
// Graft and Graft-Ack (RFC 3973) use this layout with types 6/7.
header pim_jp_t {
    bit<8> reserved;
    bit<8> num_groups;
    bit<16> holdtime;
}

header pim_jp_counts_t {
    bit<16> joined_sources;
    bit<16> pruned_sources;
}

// Register body prefix, followed by the original multicast IP packet.
// Border is deprecated in RFC 7761 and ignored on reception.
// null_register probes the RP. It is not a common-header flag.
header pim_register_t {
    bit<1> border;
    bit<1> null_register;
    bit<30> reserved;
}

// Register-Stop: encoded group followed by encoded unicast source.
// Assert: the same two addresses followed by these eight octets.
// RFC 9466 packed Assert bodies require their own record parser.
header pim_assert_t {
    bit<1> rpt;
    bit<31> metric_preference;
    bit<32> metric;
}

// Storage for the example's ordered Join/Prune records. The first four
// octets are shared by encoded group and source addresses. For a group,
// value holds its native address followed by pim_jp_counts_t. For a
// source, value holds only its native address. flags has the group B/Z
// or source S/W/R layout above. Record roles are local metadata, not
// extra bits on the wire. One stack retains the original record order.
header pim_jp_record_t {
    bit<8> address_family;
    bit<8> encoding_type;
    bit<8> flags;
    bit<8> mask_length;
    varbit<160> value;
}

struct pim_metadata_t {
    bit<32> pdu_bytes;
    bit<32> parsed_bytes;
    bit<32> remaining;
    bit<4> subtype;
    bit<8> address_family;
    bit<8> address_bytes;
    bit<8> address_bits;
    bit<8> option_count;
    bit<8> group_count;
    bit<8> record_count;
    bit<16> source_count;
    bit<64> group_records; // Bit i marks a group at stack index i
    bit<8> pending_groups;
    bit<32> pending_sources;
}

/*
 * Single-message parser and local delivery example
 * headers contains pim_t pim, pim_hello_tlv_t[8] pim_options,
 * pim_unicast_t pim_upstream and pim_source, pim_group_t pim_group,
 * pim_jp_t pim_jp, pim_register_t pim_register, pim_assert_t pim_assert,
 * and pim_jp_record_t[64] pim_records. metadata contains pim_metadata_t pim.
 * Instantiate this parser once per packet. All headers start invalid.
 *
 * The enclosing parser handles IPv4/IPv6, options/extension headers and
 * reassembly, verifies protocol/Next Header 103, and supplies physically
 * bounded payload_bytes from the IP length, excluding Ethernet padding.
 * The cursor starts at the PIM version octet. This example handles up to
 * 65535 PIM octets. IPv6 jumbograms require a separate length profile.
 *
 * Hello parses up to eight TLVs, retaining values and unknown options.
 * Native Join/Prune, Graft and Graft-Ack parse at most eight groups and
 * 64 total group/source records. These are local capacities. Every group
 * carries joined/pruned counts, followed by those two lists in order.
 * A source's list membership comes from its position and the counts.
 * Register parses its flags and retains the inner packet. Register-Stop
 * and non-packed Assert parse their native group/source addresses.
 * Packed Assert and other message bodies remain unchanged for their
 * protocol handlers. Extended types retain their subtype for dispatch.
 * Unsupported address families/encodings, excess entries, truncated
 * fields and inconsistent list boundaries produce a parser error.
 *
 * Emit pim, the active prefix/address headers, then pim_options or
 * pim_records in order. Join/Prune emits pim_upstream and pim_jp before
 * pim_records. Register-Stop/Assert emit pim_group and pim_source, then
 * pim_assert if valid. Emit remaining bytes unchanged. parsed_bytes and
 * remaining describe the handled prefix and opaque body within the PDU.
 *
 * The handler checks checksums, IP destinations and hop limits, Hello
 * value formats/duplicates, group/source semantics, S/W/R rules for the
 * configured mode, encapsulated IP framing, and authentication policy.
 * PIM-SM sources have full host masks, and W implies R. A (*,G) Join
 * identifies the RP address
 * with W/R set, not an arbitrary zero source. DR election, timers, RPF,
 * Register processing and multicast tree state need the control plane.
 * Unrecognized/reserved messages are discarded there. This example only
 * delivers packets to a configured local handler and preserves bytes.
 */
/*
parser pim_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                  in bit<32> payload_bytes) {
    bit<32> prefix;
    bit<96> group4;
    bit<192> group6;
    bit<32> record_bytes;

    state start {
        meta.pim.pdu_bytes = payload_bytes;
        meta.pim.parsed_bytes = 0;
        meta.pim.remaining = payload_bytes;
        meta.pim.subtype = 0;
        meta.pim.address_family = 0;
        meta.pim.address_bytes = 0;
        meta.pim.address_bits = 0;
        meta.pim.option_count = 0;
        meta.pim.group_count = 0;
        meta.pim.record_count = 0;
        meta.pim.source_count = 0;
        meta.pim.group_records = 0;
        meta.pim.pending_groups = 0;
        meta.pim.pending_sources = 0;
        verify(payload_bytes >= 4 && payload_bytes <= 65535, error.NoMatch);
        pkt.extract(hdr.pim);
        verify(hdr.pim.version == PIM_VERSION, error.NoMatch);
        meta.pim.remaining = payload_bytes - 4;
        meta.pim.parsed_bytes = 4;
        transition select(hdr.pim.type) {
            PIM_DF_ELECTION: extended_type;
            13: extended_type;
            14: extended_type;
            15: extended_type;
            default: classify;
        }
    }

    state extended_type {
        meta.pim.subtype = hdr.pim.flags[7:4];
        transition accept;
    }

    state classify {
        transition select(hdr.pim.type) {
            PIM_HELLO: next_option;
            PIM_REGISTER: parse_register;
            PIM_REGISTER_STOP: group_address;
            PIM_JOIN_PRUNE: upstream_address;
            PIM_ASSERT: assert_format;
            PIM_GRAFT: upstream_address;
            PIM_GRAFT_ACK: upstream_address;
            default: accept;
        }
    }

    state next_option {
        transition select(meta.pim.remaining, meta.pim.option_count) {
            (0, _): finish;
            (_, 8): invalid_message;
            default: parse_option;
        }
    }

    state parse_option {
        verify(meta.pim.remaining >= 4, error.NoMatch);
        prefix = pkt.lookahead<bit<32>>();
        record_bytes = 4 + (bit<32>)prefix[15:0];
        verify(record_bytes <= meta.pim.remaining, error.NoMatch);
        pkt.extract(hdr.pim_options.next, (bit<32>)prefix[15:0] * 8);
        meta.pim.remaining = meta.pim.remaining - record_bytes;
        meta.pim.parsed_bytes = meta.pim.parsed_bytes + record_bytes;
        meta.pim.option_count = meta.pim.option_count + 1;
        transition next_option;
    }

    state parse_register {
        verify(meta.pim.remaining >= 4, error.NoMatch);
        pkt.extract(hdr.pim_register);
        meta.pim.remaining = meta.pim.remaining - 4;
        meta.pim.parsed_bytes = meta.pim.parsed_bytes + 4;
        transition accept;
    }

    state assert_format {
        transition select(hdr.pim.flags & PIM_ASSERT_PACKED) {
            0: group_address;
            default: accept;
        }
    }

    state upstream_address {
        verify(meta.pim.remaining >= 2, error.NoMatch);
        transition select(pkt.lookahead<bit<16>>()) {
            16w0x0100: upstream4;
            16w0x0200: upstream6;
            default: invalid_message;
        }
    }

    state upstream4 {
        meta.pim.address_family = PIM_AF_IPV4;
        meta.pim.address_bytes = 4;
        meta.pim.address_bits = 32;
        transition parse_upstream;
    }

    state upstream6 {
        meta.pim.address_family = PIM_AF_IPV6;
        meta.pim.address_bytes = 16;
        meta.pim.address_bits = 128;
        transition parse_upstream;
    }

    state group_address {
        verify(meta.pim.remaining >= 4, error.NoMatch);
        prefix = pkt.lookahead<bit<32>>();
        transition select(prefix[31:16]) {
            16w0x0100: group_address4;
            16w0x0200: group_address6;
            default: invalid_message;
        }
    }

    state group_address4 {
        meta.pim.address_family = PIM_AF_IPV4;
        meta.pim.address_bytes = 4;
        meta.pim.address_bits = 32;
        transition parse_group_address;
    }

    state group_address6 {
        meta.pim.address_family = PIM_AF_IPV6;
        meta.pim.address_bytes = 16;
        meta.pim.address_bits = 128;
        transition parse_group_address;
    }

    state parse_upstream {
        record_bytes = 2 + (bit<32>)meta.pim.address_bytes;
        verify(meta.pim.remaining >= record_bytes, error.NoMatch);
        pkt.extract(hdr.pim_upstream, (bit<32>)meta.pim.address_bits);
        meta.pim.remaining = meta.pim.remaining - record_bytes;
        meta.pim.parsed_bytes = meta.pim.parsed_bytes + record_bytes;
        verify(meta.pim.remaining >= 4, error.NoMatch);
        pkt.extract(hdr.pim_jp);
        meta.pim.remaining = meta.pim.remaining - 4;
        meta.pim.parsed_bytes = meta.pim.parsed_bytes + 4;
        meta.pim.pending_groups = hdr.pim_jp.num_groups;
        verify(meta.pim.pending_groups <= 8, error.NoMatch);
        transition next_group;
    }

    state next_group {
        transition select(meta.pim.pending_groups) {
            0: finish;
            default: group_record;
        }
    }

    state group_record {
        verify(meta.pim.record_count < 64, error.NoMatch);
        record_bytes = 8 + (bit<32>)meta.pim.address_bytes;
        verify(meta.pim.remaining >= record_bytes, error.NoMatch);
        transition select(meta.pim.address_family) {
            PIM_AF_IPV4: group_record4;
            PIM_AF_IPV6: group_record6;
            default: invalid_message;
        }
    }

    state group_record4 {
        group4 = pkt.lookahead<bit<96>>();
        meta.pim.pending_sources = (bit<32>)group4[31:16]
                                  + (bit<32>)group4[15:0];
        transition parse_group_record;
    }

    state group_record6 {
        group6 = pkt.lookahead<bit<192>>();
        meta.pim.pending_sources = (bit<32>)group6[31:16]
                                  + (bit<32>)group6[15:0];
        transition parse_group_record;
    }

    state parse_group_record {
        pkt.extract(hdr.pim_records.next,
                    (bit<32>)meta.pim.address_bits + 32);
        verify(hdr.pim_records.last.address_family == meta.pim.address_family
               && hdr.pim_records.last.encoding_type == PIM_ENCODING_NATIVE
               && hdr.pim_records.last.mask_length <= meta.pim.address_bits,
               error.NoMatch);
        meta.pim.group_records = meta.pim.group_records
                                | (64w1 << meta.pim.record_count);
        meta.pim.record_count = meta.pim.record_count + 1;
        meta.pim.group_count = meta.pim.group_count + 1;
        meta.pim.pending_groups = meta.pim.pending_groups - 1;
        meta.pim.remaining = meta.pim.remaining - record_bytes;
        meta.pim.parsed_bytes = meta.pim.parsed_bytes + record_bytes;
        verify(meta.pim.pending_sources <= 64 - (bit<32>)meta.pim.record_count,
               error.NoMatch);
        verify(meta.pim.pending_sources * (4 + (bit<32>)meta.pim.address_bytes)
               <= meta.pim.remaining, error.NoMatch);
        transition next_source;
    }

    state next_source {
        transition select(meta.pim.pending_sources) {
            0: next_group;
            default: source_record;
        }
    }

    state source_record {
        verify(meta.pim.record_count < 64, error.NoMatch);
        record_bytes = 4 + (bit<32>)meta.pim.address_bytes;
        verify(meta.pim.remaining >= record_bytes, error.NoMatch);
        pkt.extract(hdr.pim_records.next, (bit<32>)meta.pim.address_bits);
        verify(hdr.pim_records.last.address_family == meta.pim.address_family
               && hdr.pim_records.last.encoding_type == PIM_ENCODING_NATIVE
               && hdr.pim_records.last.mask_length <= meta.pim.address_bits,
               error.NoMatch);
        meta.pim.record_count = meta.pim.record_count + 1;
        meta.pim.source_count = meta.pim.source_count + 1;
        meta.pim.pending_sources = meta.pim.pending_sources - 1;
        meta.pim.remaining = meta.pim.remaining - record_bytes;
        meta.pim.parsed_bytes = meta.pim.parsed_bytes + record_bytes;
        transition next_source;
    }

    state parse_group_address {
        record_bytes = 4 + (bit<32>)meta.pim.address_bytes;
        verify(meta.pim.remaining >= record_bytes, error.NoMatch);
        pkt.extract(hdr.pim_group, (bit<32>)meta.pim.address_bits);
        verify(hdr.pim_group.mask_length <= meta.pim.address_bits,
               error.NoMatch);
        meta.pim.remaining = meta.pim.remaining - record_bytes;
        meta.pim.parsed_bytes = meta.pim.parsed_bytes + record_bytes;
        record_bytes = 2 + (bit<32>)meta.pim.address_bytes;
        verify(meta.pim.remaining >= record_bytes, error.NoMatch);
        pkt.extract(hdr.pim_source, (bit<32>)meta.pim.address_bits);
        verify(hdr.pim_source.address_family == meta.pim.address_family
               && hdr.pim_source.encoding_type == PIM_ENCODING_NATIVE,
               error.NoMatch);
        meta.pim.remaining = meta.pim.remaining - record_bytes;
        meta.pim.parsed_bytes = meta.pim.parsed_bytes + record_bytes;
        transition select(hdr.pim.type) {
            PIM_ASSERT: parse_assert;
            default: finish;
        }
    }

    state parse_assert {
        verify(meta.pim.remaining >= 8, error.NoMatch);
        pkt.extract(hdr.pim_assert);
        meta.pim.remaining = meta.pim.remaining - 8;
        meta.pim.parsed_bytes = meta.pim.parsed_bytes + 8;
        transition finish;
    }

    state finish {
        verify(meta.pim.remaining == 0, error.NoMatch);
        transition accept;
    }

    state invalid_message {
        verify(false, error.NoMatch);
        transition accept;
    }
}

// v1model example. handler_port and table ports identify local protocol
// processing endpoints. Delivery does not forward PIM traffic to peers.
control pim_control(inout headers hdr, inout metadata meta,
                    inout standard_metadata_t standard_metadata,
                    in bit<9> handler_port) {
    action deliver(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action deliver_default() {
        standard_metadata.egress_spec = handler_port;
    }

    table message_handlers {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.pim.type: exact;
            meta.pim.subtype: exact;
        }
        actions = {
            deliver;
            deliver_default;
        }
        default_action = deliver_default();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.pim.isValid()) {
            mark_to_drop(standard_metadata);
        } else {
            message_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_PIM_P4
