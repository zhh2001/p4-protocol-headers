/*
 * Bit Index Explicit Replication encapsulation
 * BIER 封装报头、BIFT 上下文与解析分流示例
 * RFC 8296, with payload identifiers from RFC 9624 and the IANA registry
 */
#ifndef P4_PROTOCOL_HEADERS_BIER_P4
#define P4_PROTOCOL_HEADERS_BIER_P4

const bit<16> BIER_ETHERTYPE_NON_MPLS = 16w0xab37;
const bit<16> BIER_ETHERTYPE_MPLS = 16w0x8847;
const bit<4> BIER_NIBBLE_MPLS = 4w5;
const bit<4> BIER_NIBBLE_NON_MPLS = 4w0;
const bit<4> BIER_VERSION = 4w0;
const bit<4> BIER_VERSION_EXPERIMENTAL = 4w15;

// BSL encodes log2(BitStringLength) - 5. Only values 1..7 are defined.
// The default length is 256 bits, encoded as 3. A BFR MUST obtain the
// actual length from its BIFT-id mapping, not from the received BSL field.
const bit<4> BIER_BSL_64 = 4w1;
const bit<4> BIER_BSL_128 = 4w2;
const bit<4> BIER_BSL_256 = 4w3;
const bit<4> BIER_BSL_512 = 4w4;
const bit<4> BIER_BSL_1024 = 4w5;
const bit<4> BIER_BSL_2048 = 4w6;
const bit<4> BIER_BSL_4096 = 4w7;
const bit<13> BIER_MAX_BITSTRING_BITS = 13w4096;

// IANA BIER Next Protocol Identifiers. Values 0 and 63 are reserved.
const bit<6> BIER_PROTO_MPLS_DOWN = 6w1;
const bit<6> BIER_PROTO_MPLS_UP = 6w2;
const bit<6> BIER_PROTO_ETHERNET = 6w3;
const bit<6> BIER_PROTO_IPV4 = 6w4;
const bit<6> BIER_PROTO_OAM = 6w5;
const bit<6> BIER_PROTO_IPV6 = 6w6;
const bit<6> BIER_PROTO_VXLAN = 6w7; // No IP/UDP header, RFC 9624
const bit<6> BIER_PROTO_NVGRE = 6w8; // No IP header, RFC 9624
const bit<6> BIER_PROTO_GENEVE = 6w9; // No IP/UDP header, RFC 9624

// Initial four octets of the encapsulation. In MPLS this is also the
// bottom label stack entry, with S = 1. Do not extract it twice if an MPLS
// parser already consumed it. BIER-MPLS labels are locally significant,
// downstream assigned, and cannot use penultimate hop popping.
// In non-MPLS networks BIFT-id identifies <SD, SI, BSL> throughout the
// domain. It has no fixed subdivision into SD/SI/BSL fields. TC/S should
// be transmitted as 0/1 and are ignored on receipt. TTL still applies.
header bier_bift_t {
    bit<20> bift_id;
    bit<3> traffic_class;
    bit<1> bottom_of_stack;
    bit<8> ttl;
}

// Eight fixed octets after bier_bift_t, followed by 64..4096 BitString
// bits. Total BIER encapsulation length is 12 + BitStringLength / 8.
// MPLS nibble is 5. Non-MPLS nibble should be 0 on transmission and is
// ignored on receipt. Version 0 is defined here, 15 is experimental.
// OAM is two bits, zero by default. Reserved bits are ignored on receipt.
// DSCP is ignored in MPLS by default. BFIR-id normally identifies the
// ingress BFR within the sub-domain, with values 1..65535.
// SI and SD are inferred from BIFT-id and are not separate wire fields.
header bier_t {
    bit<4> nibble;
    bit<4> version;
    bit<4> bsl;
    bit<20> entropy;
    bit<2> oam;
    bit<2> reserved;
    bit<6> dscp;
    bit<6> proto;
    bit<16> bfir_id;
    varbit<4096> bitstring;
}

// Local configuration, not a wire header. The caller resolves BIFT-id
// using the encapsulation type and any required ingress/label-space
// context. bitstring_bits is the length assigned to that BIFT, not a
// value obtained by decoding the packet's BSL. Unknown BIFTs have known=0.
// The control plane also supplies the BIFT's SD, SI and forwarding state
// to the handler. This example only needs its identity and length.
struct bier_context_t {
    bit<20> bift_id;
    bit<13> bitstring_bits;
    bool mpls;
    bool known;
}

struct bier_metadata_t {
    bit<13> bitstring_bits;
    bit<4> expected_bsl;
    bit<32> encapsulation_bytes;
    bit<32> payload_bytes;
    bool mpls;
}

/*
 * One BIFT-selected BIER header and local delivery example
 * headers contains bier_bift_t bier_bift and bier_t bier.
 * metadata contains bier_metadata_t bier. Invoke with hdr.bier invalid.
 *
 * The caller parses the initial four octets into hdr.bier_bift, resolves
 * the BIFT context, and positions the cursor at Nibble. In MPLS, any
 * preceding transport labels are handled by the caller. Only a label
 * mapped to a BIER BIFT identifies BIER, not the bottom-of-stack bit or
 * nibble alone. Copy a previously extracted bottom entry into bier_bift
 * if necessary and emit that entry only once.
 *
 * remaining_bytes is the physically available size from Nibble through
 * the payload, excluding the initial four octets and any outer headers.
 * The caller validates enclosing packet boundaries. Ethernet padding does
 * not indicate inner payload length. The helper checks the configured
 * BitString length, version, MPLS nibble/S, and consistency with wire BSL.
 * Non-MPLS TC/S/nibble, reserved bits, OAM and DSCP are preserved. Emit
 * bier_bift, bier and the remaining payload unchanged, retaining any
 * preceding transport headers as appropriate. No inner payload is parsed.
 *
 * Handler ports select local processing. The owner validates supported
 * payload types, domain membership, BFIR-id and OAM policy. A BFER should
 * discard unsupported payload protocols. TTL expiry and forwarding are
 * handled there. Incoming TTL 1 can still require local payload delivery
 * when the local BFR's bit is set, but must never cause further forwarding.
 * TTL 0 goes to expiry handling. Replication, bit clearing, BIFT lookup,
 * downstream label rewriting and TTL decrement follow RFC 8279/8296 and
 * need configured forwarding state. This example does not perform them.
 * MPLS payload labels are a separate stack. Upstream-assigned labels use
 * the <BFIR-id, SD> context. VXLAN/NVGRE/GENEVE payloads use RFC 9624.
 */
/*
parser bier_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                   in bier_context_t context, in bit<32> remaining_bytes) {
    state start {
        meta.bier.bitstring_bits = context.bitstring_bits;
        meta.bier.expected_bsl = 0;
        meta.bier.encapsulation_bytes = 0;
        meta.bier.payload_bytes = 0;
        meta.bier.mpls = context.mpls;
        verify(hdr.bier_bift.isValid() && context.known
               && hdr.bier_bift.bift_id == context.bift_id, error.NoMatch);
        transition select(context.bitstring_bits) {
            13w64: bits_64;
            13w128: bits_128;
            13w256: bits_256;
            13w512: bits_512;
            13w1024: bits_1024;
            13w2048: bits_2048;
            13w4096: bits_4096;
            default: unsupported_length;
        }
    }

    state bits_64 {
        meta.bier.expected_bsl = BIER_BSL_64;
        transition parse_bier;
    }

    state bits_128 {
        meta.bier.expected_bsl = BIER_BSL_128;
        transition parse_bier;
    }

    state bits_256 {
        meta.bier.expected_bsl = BIER_BSL_256;
        transition parse_bier;
    }

    state bits_512 {
        meta.bier.expected_bsl = BIER_BSL_512;
        transition parse_bier;
    }

    state bits_1024 {
        meta.bier.expected_bsl = BIER_BSL_1024;
        transition parse_bier;
    }

    state bits_2048 {
        meta.bier.expected_bsl = BIER_BSL_2048;
        transition parse_bier;
    }

    state bits_4096 {
        meta.bier.expected_bsl = BIER_BSL_4096;
        transition parse_bier;
    }

    state unsupported_length {
        verify(false, error.NoMatch);
        transition accept;
    }

    state parse_bier {
        meta.bier.encapsulation_bytes = 12
                                         + ((bit<32>)meta.bier.bitstring_bits >> 3);
        verify(remaining_bytes >= meta.bier.encapsulation_bytes - 4,
               error.NoMatch);
        pkt.extract(hdr.bier, (bit<32>)meta.bier.bitstring_bits);
        verify(hdr.bier.version == BIER_VERSION
               && hdr.bier.bsl == meta.bier.expected_bsl, error.NoMatch);
        meta.bier.payload_bytes = remaining_bytes
                                   - (meta.bier.encapsulation_bytes - 4);
        transition select(context.mpls) {
            true: mpls_fields;
            false: accept;
        }
    }

    state mpls_fields {
        verify(hdr.bier_bift.bottom_of_stack == 1
               && hdr.bier.nibble == BIER_NIBBLE_MPLS, error.NoMatch);
        transition accept;
    }
}

// v1model example. handler_port identifies the local BIER processing owner.
control bier_control(inout headers hdr, inout metadata meta,
                     inout standard_metadata_t standard_metadata,
                     in bit<9> handler_port) {
    action deliver(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action deliver_default() {
        standard_metadata.egress_spec = handler_port;
    }

    table payload_handlers {
        key = {
            standard_metadata.ingress_port: exact;
            meta.bier.mpls: exact;
            hdr.bier_bift.bift_id: exact;
            hdr.bier.proto: exact;
        }
        actions = { deliver; deliver_default; }
        default_action = deliver_default();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.bier_bift.isValid() || !hdr.bier.isValid()) {
            mark_to_drop(standard_metadata);
        } else {
            payload_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_BIER_P4
