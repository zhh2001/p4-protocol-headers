#ifndef P4_PROTOCOL_HEADERS_GENEVE_P4
#define P4_PROTOCOL_HEADERS_GENEVE_P4

/**
 * Geneve Header Definition in P4 (RFC 8926)
 * 通用网络虚拟化封装报头
 * Geneve carries an EtherType payload over UDP, normally on port 6081.
 */

typedef bit<16> geneve_protocol_t;
typedef bit<16> geneve_opt_class_t;
typedef bit<7>  geneve_opt_type_t;  // Type value without the critical bit

const bit<16> GENEVE_UDP_PORT = 6081;

/**
 * Geneve Base Header (8 bytes)
 * 基础报头，选项长度以 4 字节为单位，不含基础报头
 */
header geneve_t {
    bit<2>  version;       // Version 0
    bit<6>  opt_len;       // Total options length in 4-byte units (0-63)
    bit<1>  oam_pkt;       // O: control message
    bit<1>  critical_opt;  // C: at least one critical option
    bit<6>  reserved1;     // Transmit zero, ignore on receipt
    geneve_protocol_t protocol;
    bit<24> vni;           // Virtual Network Identifier
    bit<8>  reserved;      // Transmit zero, ignore on receipt
};

/**
 * Geneve Option (4-byte prefix and 0-124 bytes of data)
 * 选项的关键标志属于 Type 字段，长度不含 4 字节选项前缀
 */
header geneve_option_t {
    geneve_opt_class_t opt_class;
    bit<1> critical;             // High bit of the 8-bit Type field
    geneve_opt_type_t opt_type;
    bit<3> reserved;             // Transmit zero, ignore on receipt
    bit<5> opt_length;           // Data length in 4-byte units (0-31)
    varbit<992> opt_data;        // Up to 31 * 4 bytes
};

/* Registered option classes. Each class owner defines its option types. */
const geneve_opt_class_t GENEVE_CLASS_OVN = 0x0102;
const geneve_opt_class_t GENEVE_CLASS_INT = 0x0103;

/* Payload EtherTypes */
const geneve_protocol_t GENEVE_PROTO_ETHERNET = 0x6558;
const geneve_protocol_t GENEVE_PROTO_IPV4     = 0x0800;
const geneve_protocol_t GENEVE_PROTO_IPV6     = 0x86DD;
const geneve_protocol_t GENEVE_PROTO_NSH      = 0x894F;
const geneve_protocol_t GENEVE_PROTO_MPLS     = 0x8847;

/**
 * P4 Parser Logic for Geneve Tunnel Endpoints
 * The packet cursor must point to the Geneve base header.
 * Pass the UDP payload length as geneve_length after validating UDP length.
 * The headers struct contains geneve_t geneve and geneve_option_t[63] options.
 * The option stack must be empty on entry. Each option consumes at least
 * 4 bytes, so 63 entries cover the maximum 252-byte option area.
 *
 * This example checks TLV boundaries and preserves unknown noncritical options.
 * It has no option-specific handlers and rejects packets with critical options.
 * Control messages keep their payload opaque for delivery to a control port.
 * The enclosing pipeline handles parser errors, IP/UDP bounds and checksums.
 * Transit devices need a separate path that does not reject critical options
 * or unknown versions and does not alter Geneve headers or options.
 */
/*
parser geneve_parser(packet_in pkt, inout headers hdr,
                     in bit<16> geneve_length) {
    bit<16> options_left;
    bit<32> option_prefix;
    bit<16> option_bytes;
    bit<32> option_data_bits;

    state start {
        verify(geneve_length >= 8, error.HeaderTooShort);
        pkt.extract(hdr.geneve);
        verify(hdr.geneve.version == 0, error.NoMatch);
        verify(hdr.geneve.critical_opt == 0, error.NoMatch);
        options_left = (bit<16>) hdr.geneve.opt_len * 4;
        verify(options_left + 8 <= geneve_length, error.HeaderTooShort);
        transition check_options;
    }

    state check_options {
        transition select(options_left) {
            0: check_payload;
            default: parse_option;
        }
    }

    state parse_option {
        option_prefix = pkt.lookahead<bit<32>>();
        option_bytes = ((bit<16>) option_prefix[4:0] + 1) * 4;
        verify(option_bytes <= options_left, error.HeaderTooShort);
        verify(option_prefix[15:15] == 0, error.NoMatch);
        option_data_bits = (bit<32>) option_prefix[4:0] * 32;
        pkt.extract(hdr.options.next, option_data_bits);
        options_left = options_left - option_bytes;
        transition check_options;
    }

    state check_payload {
        transition select(hdr.geneve.oam_pkt) {
            1: accept;
            default: parse_payload;
        }
    }

    state parse_payload {
        transition select(hdr.geneve.protocol) {
            GENEVE_PROTO_ETHERNET: parse_inner_ethernet;
            GENEVE_PROTO_IPV4: parse_inner_ipv4;
            GENEVE_PROTO_IPV6: parse_inner_ipv6;
            GENEVE_PROTO_NSH: parse_nsh;
            GENEVE_PROTO_MPLS: parse_mpls;
            default: accept;
        }
    }

    // Add the payload states with bounds checks against geneve_length.
}
*/

/**
 * P4 Match-Action Pipeline for Geneve Tunnel Endpoints (v1model)
 * Select data ports by VNI and payload protocol.
 * Configure send_control with the target's control port.
 * The enclosing pipeline handles decapsulation and egress framing.
 */
/*
control geneve_control(inout headers hdr,
                       inout standard_metadata_t standard_metadata) {
    action forward_data(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action send_control(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action drop_geneve() {
        mark_to_drop(standard_metadata);
    }

    table geneve_forwarding {
        key = {
            hdr.geneve.vni: exact;
            hdr.geneve.protocol: exact;
        }
        actions = {
            forward_data;
            drop_geneve;
            NoAction;
        }
        default_action = drop_geneve();
    }

    table geneve_control_messages {
        key = {
            hdr.geneve.vni: exact;
        }
        actions = {
            send_control;
            drop_geneve;
        }
        default_action = drop_geneve();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.geneve.isValid()) {
            drop_geneve();
        } else if (hdr.geneve.oam_pkt == 1) {
            geneve_control_messages.apply();
        } else {
            geneve_forwarding.apply();
        }
    }
}
*/

#endif
