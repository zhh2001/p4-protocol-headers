#ifndef P4_PROTOCOL_HEADERS_NSH_P4
#define P4_PROTOCOL_HEADERS_NSH_P4

/**
 * Network Service Header definitions (RFC 8300)
 * 网络服务报头，携带服务路径和固定或可变元数据
 * Wire order: [base][service path][context headers][original packet/frame].
 * OAM semantics follow RFC 9451. Protocol numbers use the IANA NSH registry.
 * Metadata formats and required processing are configured for each path.
 */

typedef bit<8> nsh_protocol_t;
typedef bit<16> nsh_md_class_t;

const bit<16> NSH_ETHERTYPE = 0x894F;
const bit<2> NSH_VERSION = 0;
const bit<6> NSH_DEFAULT_TTL = 63;
const bit<8> NSH_DEFAULT_SI = 255;

const bit<4> NSH_MD_TYPE_1 = 0x1;
const bit<4> NSH_MD_TYPE_2 = 0x2;
const bit<4> NSH_MD_EXPERIMENT = 0xF;

/* Registered Next Protocol values. Experiments require explicit configuration. */
const nsh_protocol_t NSH_NEXT_NONE       = 0x00; // RFC 8393, metadata only
const nsh_protocol_t NSH_NEXT_IPV4       = 0x01;
const nsh_protocol_t NSH_NEXT_IPV6       = 0x02;
const nsh_protocol_t NSH_NEXT_ETHER      = 0x03;
const nsh_protocol_t NSH_NEXT_NSH        = 0x04;
const nsh_protocol_t NSH_NEXT_MPLS       = 0x05;
const nsh_protocol_t NSH_NEXT_IOAM       = 0x06; // RFC 9452
const nsh_protocol_t NSH_NEXT_ACTIVE_OAM = 0x07; // RFC 9516
const nsh_protocol_t NSH_NEXT_EXPERIMENT_1 = 0xFE;
const nsh_protocol_t NSH_NEXT_EXPERIMENT_2 = 0xFF;

const nsh_md_class_t NSH_MD_CLASS_IETF = 0x0000;
const nsh_md_class_t NSH_MD_CLASS_BBF = 0x0200;

/**
 * NSH base header (4 bytes)
 * Length counts the complete NSH in 4-byte units, including the service path.
 * MD Type 1 requires Length = 6. MD Type 2 requires Length >= 2.
 * Unassigned bits are zero on origination and ignored and preserved on receipt.
 * O marks a packet containing exclusively SFC OAM data, not user data carrying
 * additional telemetry. O remains unchanged along the service path.
 */
header nsh_t {
    bit<2> version;
    bit<1> o_bit;
    bit<1> unassigned1;
    bit<6> ttl;
    bit<6> length;
    bit<4> unassigned2;
    bit<4> md_type;
    nsh_protocol_t next_protocol;
};

/**
 * Service path header (4 bytes)
 * SPI identifies the service path. SI identifies the position in that path.
 * SFs or SFC proxies decrement SI after performing the required services.
 * SFFs decrement TTL before forwarding lookup. The 6-bit subtraction maps
 * incoming TTL 0 to 63. An SFF cannot forward if the resulting TTL is zero.
 * A nonterminal SFF also discards SI 0. Terminal processing needs path state.
 */
header nsh_service_path_t {
    bit<24> spi;
    bit<8> si;
};

/**
 * MD Type 1 context (16 bytes)
 * These words have no platform, node, flow or policy meaning in RFC 8300.
 * The configured metadata profile defines their interpretation and ordering.
 * A context carrying no metadata is zero. An SF or SFC proxy that does not
 * understand the profile must discard the packet and report the unknown SPI.
 */
header nsh_md1_t {
    bit<32> context_1;
    bit<32> context_2;
    bit<32> context_3;
    bit<32> context_4;
};

/**
 * MD Type 2 context (4-byte prefix, followed by value and padding)
 * Length counts only value bytes, from 0 to 127. Round this length up to a
 * multiple of 4 to locate the next context or original payload. Type is a full
 * 8-bit value defined by the Metadata Class owner. No critical bit is defined.
 * The unassigned bit is zero on origination and ignored on receipt.
 * Only the first Length bytes of value_and_padding are metadata. Padding is
 * ignored, and its received bytes are preserved for an unchanged packet.
 */
header nsh_md2_t {
    nsh_md_class_t md_class;
    bit<8> md_type;
    bit<1> unassigned;
    bit<7> length;
    varbit<1024> value_and_padding;
};

/* At most 244 context bytes fit in a 252-byte NSH. Each MD2 prefix uses 4. */
struct nsh_headers_t {
    nsh_t base;
    nsh_service_path_t path;
    nsh_md1_t md1;
    nsh_md2_t[61] md2;
};

struct nsh_metadata_t {
    bit<16> header_bytes;
    bit<16> context_bytes;
    bit<16> remaining_bytes;
    bit<6> context_count;
    bool oam_flag_error;
};

/**
 * Bounded parsing and local delivery example (P4_16, v1model).
 * The cursor points to the NSH base header. nsh_bytes is the validated number
 * of available transport payload bytes. The enclosing pipeline checks outer
 * lengths, checksums and fragmentation before using this example.
 *
 * MD Types 1 and 2 are supported. Unsupported MD Types, including the
 * unconfigured experimental format, are rejected. MD2 values, unknown types,
 * unassigned bits and padding remain unchanged. Metadata owners enforce the
 * required context set, ordering, duplicates, authentication and semantics.
 * An MD1 handler must know the metadata profile for the selected SPI.
 *
 * Handler ports are local protocol owners. OAM delivery requires a separate,
 * explicit table entry. The error handler reports Active OAM with O = 0
 * (RFC 9516). Unknown and experimental Next Protocol values require explicit
 * handler entries. IOAM and nested NSH payloads remain opaque for their owners.
 * With Next Protocol None, bytes after the NSH are ignored, even if present.
 * A terminal SFP cannot forward those bytes as user traffic (RFC 8393).
 *
 * This example preserves TTL and SI for local processing. It does not perform
 * an SFF forwarding lookup or an SF service. The corresponding owner applies
 * the TTL and SI rules above and determines when the NSH can be removed.
 * The deparser emits base, path, MD1 or the MD2 stack, then the opaque payload.
 */
/*
parser nsh_parser(packet_in pkt, out nsh_headers_t hdr,
                   out nsh_metadata_t meta, in bit<16> nsh_bytes) {
    bit<16> contexts_left;
    bit<32> context_prefix;
    bit<16> padded_value_bytes;
    bit<16> context_size;

    state start {
        meta.header_bytes = 0;
        meta.context_bytes = 0;
        meta.remaining_bytes = 0;
        meta.context_count = 0;
        meta.oam_flag_error = false;
        verify(nsh_bytes >= 8, error.HeaderTooShort);
        pkt.extract(hdr.base);
        verify(hdr.base.version == NSH_VERSION, error.NoMatch);
        verify(hdr.base.length >= 2, error.HeaderTooShort);
        meta.header_bytes = (bit<16>)hdr.base.length * 4;
        verify(meta.header_bytes <= nsh_bytes, error.HeaderTooShort);
        pkt.extract(hdr.path);
        meta.context_bytes = meta.header_bytes - 8;
        meta.remaining_bytes = nsh_bytes - meta.header_bytes;
        meta.oam_flag_error = hdr.base.next_protocol == NSH_NEXT_ACTIVE_OAM
                              && hdr.base.o_bit == 0;
        transition select(hdr.base.md_type) {
            NSH_MD_TYPE_1: fixed_context;
            NSH_MD_TYPE_2: variable_contexts;
            default: unsupported_md;
        }
    }

    state fixed_context {
        verify(hdr.base.length == 6, error.NoMatch);
        pkt.extract(hdr.md1);
        meta.context_count = 1;
        transition accept;
    }

    state variable_contexts {
        contexts_left = meta.context_bytes;
        transition check_contexts;
    }

    state check_contexts {
        transition select(contexts_left) {
            0: accept;
            default: parse_context;
        }
    }

    state parse_context {
        verify(contexts_left >= 4, error.HeaderTooShort);
        context_prefix = pkt.lookahead<bit<32>>();
        padded_value_bytes = ((bit<16>)context_prefix[6:0] + 3) & 0xFFFC;
        context_size = 4 + padded_value_bytes;
        verify(context_size <= contexts_left, error.HeaderTooShort);
        pkt.extract(hdr.md2.next, (bit<32>)padded_value_bytes * 8);
        contexts_left = contexts_left - context_size;
        meta.context_count = meta.context_count + 1;
        transition check_contexts;
    }

    state unsupported_md {
        verify(false, error.NoMatch);
        transition accept;
    }
}

control nsh_control(inout nsh_headers_t hdr, in nsh_metadata_t meta,
                    inout standard_metadata_t standard_metadata,
                    in bit<9> error_handler_port) {
    action deliver_service(bit<9> handler_port) {
        standard_metadata.egress_spec = handler_port;
    }

    action deliver_oam(bit<9> handler_port) {
        standard_metadata.egress_spec = handler_port;
    }

    action drop_service() {
        mark_to_drop(standard_metadata);
    }

    action drop_oam() {
        mark_to_drop(standard_metadata);
    }

    table service_handlers {
        key = {
            hdr.path.spi: exact;
            hdr.path.si: exact;
            hdr.base.md_type: exact;
            hdr.base.next_protocol: exact;
        }
        actions = {
            deliver_service;
            drop_service;
        }
        default_action = drop_service();
    }

    table oam_handlers {
        key = {
            hdr.path.spi: exact;
            hdr.path.si: exact;
            hdr.base.md_type: exact;
            hdr.base.next_protocol: exact;
        }
        actions = {
            deliver_oam;
            drop_oam;
        }
        default_action = drop_oam();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.base.isValid() || !hdr.path.isValid()) {
            mark_to_drop(standard_metadata);
        } else if (meta.oam_flag_error) {
            standard_metadata.egress_spec = error_handler_port;
        } else if (hdr.base.o_bit == 1) {
            oam_handlers.apply();
        } else {
            service_handlers.apply();
        }
    }
}
*/

/**
 * MD Type 1 origination example. Supply a valid 16-byte context whose profile
 * is known for the configured SPI. All MD2 entries must be invalid on entry.
 * The caller supplies the classified SPI, SI, TTL and payload protocol.
 * Use NSH_DEFAULT_TTL when no initial TTL is configured. NSH_DEFAULT_SI is the
 * recommended initial SI. O = 1 is for exclusively SFC OAM data (RFC 9451).
 * The enclosing pipeline adds the selected transport and handles MTU,
 * lengths and checksums. Emit base, path, MD1, then the unchanged payload.
 */
/*
control nsh_md1_encapsulation(inout nsh_headers_t hdr,
                              inout standard_metadata_t standard_metadata,
                              in bit<24> spi, in bit<8> si,
                              in bit<6> initial_ttl,
                              in nsh_protocol_t next_protocol, in bit<1> oam) {
    apply {
        if (!hdr.md1.isValid()
            || (next_protocol == NSH_NEXT_ACTIVE_OAM && oam == 0)) {
            mark_to_drop(standard_metadata);
        } else {
            hdr.base.setValid();
            hdr.base.version = NSH_VERSION;
            hdr.base.o_bit = oam;
            hdr.base.unassigned1 = 0;
            hdr.base.ttl = initial_ttl;
            hdr.base.length = 6;
            hdr.base.unassigned2 = 0;
            hdr.base.md_type = NSH_MD_TYPE_1;
            hdr.base.next_protocol = next_protocol;
            hdr.path.setValid();
            hdr.path.spi = spi;
            hdr.path.si = si;
        }
    }
}
*/

#endif
