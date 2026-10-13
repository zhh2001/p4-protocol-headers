#ifndef P4_PROTOCOL_HEADERS_TCP_P4
#define P4_PROTOCOL_HEADERS_TCP_P4

/**
 * Transmission Control Protocol definitions (RFC 9293 and RFC 9768)
 * TCP 报头、常用选项和有界选项解析示例
 * RFC 9768 assigns Accurate ECN (AE) to the former NS bit. The nonce-sum
 * experiment is Historic. AE/CWR/ECE form ACE after AccECN negotiation.
 */

typedef bit<16> port_t;
const bit<8> TCP_IP_PROTOCOL = 6;
const bit<6> TCP_MAX_OPTION_BYTES = 40;

enum bit<8> tcp_option_kind {
    EOL = 0,
    NOP = 1,
    MSS = 2,
    WINDOW_SCALE = 3,
    SACK_PERMITTED = 4,
    SACK = 5,
    TIMESTAMPS = 8,
    ACCECN0 = 172,
    ACCECN1 = 174
};

/**
 * TCP header (20-60 bytes). Data Offset counts 32-bit words and is 5-15.
 * This type can retain all options and padding in its raw options field.
 * The parser below instead extracts zero raw option bits, then uses a separate
 * option stack. Choose one representation when parsing and emitting a packet.
 * Sequence Number identifies the first data octet, except a SYN carries the
 * ISN and consumes one sequence number before any data. FIN also consumes one.
 * Unimplemented reserved bits are ignored on receipt and zero on transmit.
 * Flags, including ACE, depend on connection state and negotiated features.
 * Window scaling applies only when negotiated, and never to SYN windows.
 * Urgent Pointer is significant with URG = 1. Its offset from seq_no points
 * to the octet following the urgent data, not the last urgent octet.
 * Checksum covers the IP pseudoheader, TCP header, options, padding and data.
 * It is required for IPv4 and IPv6. A zero field does not disable checking.
 */
header tcp_t {
    port_t src_port;
    port_t dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<3> res;
    bit<1> ae;
    bit<1> cwr;
    bit<1> ece;
    bit<1> urg;
    bit<1> ack;
    bit<1> psh;
    bit<1> rst;
    bit<1> syn;
    bit<1> fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
    varbit<320> options;
};

/* EOL and NOP contain only their kind octet. All other options have a length
 * octet that counts kind, length and data. Options need not be word-aligned.
 * A typed option below replaces a complete generic option, not its value.
 */
header tcp_option_kind_t {
    bit<8> kind;
};

header tcp_option_prefix_t {
    bit<8> kind;
    bit<8> length;
};

/* Complete generic option. For EOL/NOP, extract zero following bits.
 * Otherwise following stores length and data, (length - 1) octets in total.
 * At most 39 following octets fit in the 40-byte TCP option area.
 */
header tcp_option_t {
    bit<8> kind;
    varbit<312> following;
};

/* Header bytes after EOL. Transmit zeros, keep received bytes unchanged. */
header tcp_option_padding_t {
    varbit<312> bytes;
};

/* MSS option (4 bytes, kind 2, length 4). Sent only with SYN. */
header tcp_mss_option_t {
    bit<8> kind;
    bit<8> length;
    bit<16> mss;
};

/* Window Scale (RFC 7323, 3 bytes, kind 3, length 3), negotiated on SYN.
 * Legal shifts are 0-14. A receiver clamps a received larger shift to 14.
 */
header tcp_window_scale_option_t {
    bit<8> kind;
    bit<8> length;
    bit<8> shift;
};

/* SACK Permitted (RFC 2018, 2 bytes, kind 4, length 2), sent only with SYN. */
header tcp_sack_permitted_option_t {
    bit<8> kind;
    bit<8> length;
};

/* SACK prefix (RFC 2018, kind 5), followed by 1-4 eight-byte blocks.
 * Length = 2 + 8 * block count. Block edges are TCP sequence numbers,
 * with the right edge identifying the first octet beyond the block.
 */
header tcp_sack_option_prefix_t {
    bit<8> kind;
    bit<8> length;
};

header tcp_sack_block_t {
    bit<32> left_edge;
    bit<32> right_edge;
};

/* Timestamps (RFC 7323, 10 bytes, kind 8, length 10). Units are sender-defined.
 * Interpretation of TSval/TSecr requires the connection's timestamp state.
 */
header tcp_timestamp_option_t {
    bit<8> kind;
    bit<8> length;
    bit<32> ts_value;
    bit<32> ts_echo;
};

/* AccECN option prefix (RFC 9768). Kind 172 has EE0B, ECEB, EE1B order.
 * Kind 174 has EE1B, ECEB, EE0B order. Each counter is 24 bits, big endian.
 * Normal lengths 2/5/8/11 carry 0/1/2/3 counters. Receivers also accept other
 * lengths, using the complete counters that fit and ignoring the remainder.
 * Negotiation and counter rollover interpretation belong to the endpoint.
 */
header tcp_accecn_option_prefix_t {
    bit<8> kind;
    bit<8> length;
};

header tcp_accecn_counter_t {
    bit<24> bytes;
};

struct tcp_headers_t {
    tcp_t base;
    tcp_option_t[40] parsed_options;
    tcp_option_padding_t padding;
};

struct tcp_metadata_t {
    bit<32> header_bytes;
    bit<32> payload_bytes;
    bit<6> parsed_options;
    bit<6> padding_bytes;
    bool eol_seen;
};

/**
 * Bounded TCP segment parsing and local delivery example (P4_16, v1model).
 * The cursor points to TCP after outer IP protocol 6 classification.
 * tcp_bytes is the validated length of one complete TCP segment, excluding
 * IP headers, IPv6 extensions and link padding. The caller handles IP options,
 * IPv6 extensions and IP reassembly, including any jumbogram length rules.
 * TCP stream messages need separate reassembly and application framing.
 *
 * The example extracts base with an empty raw options field, then each generic
 * option. The stack holds all possible 40 NOPs. EOL ends parsing and the rest
 * of the option area is preserved as header padding. The cursor then points
 * to the unchanged segment payload, which can be empty. Unknown option kinds,
 * unused flag bits and unnegotiated option values remain available to the
 * handler. Only Data Offset, generic option lengths and bounds are checked.
 *
 * The local TCP owner verifies the mandatory TCP checksum and any TCP-AO or
 * other authentication before using the segment. It checks typed option sizes,
 * EOL padding, SYN-only options, duplicates, negotiation, sequence arithmetic
 * and connection state. ACKs, resets, reassembly, windows, timers, urgent data
 * and congestion control also belong there. This parser does not infer those
 * states or interpret the AE/CWR/ECE combination without AccECN negotiation.
 *
 * context_id scopes destination ports to a configured local endpoint and peer
 * policy. The table delivers the intact packet to a local TCP handler and
 * defaults to drop. Emit base, parsed_options and padding, then the payload.
 * To use a single raw tcp_t instead, extract (Data Offset - 5) * 32 option bits
 * after checking the same header bounds and omit the separate option stack.
 */
/*
parser tcp_parser(packet_in pkt, out tcp_headers_t hdr,
                  out tcp_metadata_t meta, in bit<32> tcp_bytes) {
    bit<32> remaining;
    bit<32> option_bytes;

    state start {
        bit<160> fixed_header;
        meta.header_bytes = 0;
        meta.payload_bytes = 0;
        meta.parsed_options = 0;
        meta.padding_bytes = 0;
        meta.eol_seen = false;
        verify(tcp_bytes >= 20, error.HeaderTooShort);
        fixed_header = pkt.lookahead<bit<160>>();
        verify(fixed_header[63:60] >= 5, error.NoMatch);
        meta.header_bytes = (bit<32>)fixed_header[63:60] * 4;
        verify(meta.header_bytes <= tcp_bytes, error.HeaderTooShort);
        pkt.extract(hdr.base, 0);
        remaining = meta.header_bytes - 20;
        meta.payload_bytes = tcp_bytes - meta.header_bytes;
        transition check_option;
    }

    state check_option {
        transition select(remaining) {
            0: accept;
            default: parse_option;
        }
    }

    state parse_option {
        bit<8> kind;
        verify(meta.parsed_options < TCP_MAX_OPTION_BYTES,
               error.StackOutOfBounds);
        kind = pkt.lookahead<bit<8>>();
        transition select(kind) {
            tcp_option_kind.EOL: parse_eol;
            tcp_option_kind.NOP: parse_nop;
            default: parse_length_option;
        }
    }

    state parse_eol {
        pkt.extract(hdr.parsed_options.next, 0);
        meta.parsed_options = meta.parsed_options + 1;
        remaining = remaining - 1;
        meta.eol_seen = true;
        meta.padding_bytes = (bit<6>)remaining;
        pkt.extract(hdr.padding, remaining * 8);
        transition accept;
    }

    state parse_nop {
        pkt.extract(hdr.parsed_options.next, 0);
        meta.parsed_options = meta.parsed_options + 1;
        remaining = remaining - 1;
        transition check_option;
    }

    state parse_length_option {
        bit<16> prefix;
        verify(remaining >= 2, error.HeaderTooShort);
        prefix = pkt.lookahead<bit<16>>();
        option_bytes = (bit<32>)prefix[7:0];
        verify(option_bytes >= 2, error.NoMatch);
        verify(option_bytes <= remaining, error.HeaderTooShort);
        pkt.extract(hdr.parsed_options.next, (option_bytes - 1) * 8);
        meta.parsed_options = meta.parsed_options + 1;
        remaining = remaining - option_bytes;
        transition check_option;
    }
}

control tcp_control(inout tcp_headers_t hdr,
                    inout standard_metadata_t standard_metadata,
                    in bit<32> context_id) {
    action deliver_tcp(bit<9> handler_port) {
        standard_metadata.egress_spec = handler_port;
    }

    action drop_tcp() {
        mark_to_drop(standard_metadata);
    }

    table tcp_handlers {
        key = {
            context_id: exact;
            hdr.base.dst_port: exact;
        }
        actions = {
            deliver_tcp;
            drop_tcp;
        }
        default_action = drop_tcp();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.base.isValid()) {
            mark_to_drop(standard_metadata);
        } else {
            tcp_handlers.apply();
        }
    }
}
*/

#endif
