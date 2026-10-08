#ifndef P4_PROTOCOL_HEADERS_SRMPLS_P4
#define P4_PROTOCOL_HEADERS_SRMPLS_P4

/**
 * Segment Routing with the MPLS Data Plane (RFC 8660)
 * 基于 MPLS 标签栈的段路由
 * SR-MPLS uses the ordinary MPLS label stack format from RFC 3032.
 */

typedef bit<20> srmpls_label_t;

const bit<16> SRMPLS_ETHERTYPE_UNICAST = 0x8847;
const bit<16> SRMPLS_ETHERTYPE_MULTICAST = 0x8848;

/**
 * Label Stack Entry (4 bytes)
 * The label is an actual forwarding label, not necessarily a SID index.
 * A label represents a SID on the wire. No extra SID or flags field follows.
 * Choose this type or mpls.p4's mpls_shim when declaring a label stack.
 */
header srmpls_t {
    srmpls_label_t label;
    bit<3>        traffic_class;
    bit<1>        bottom_of_stack; // 1 only on the final stack entry
    bit<8>        ttl;
};

const srmpls_label_t SRMPLS_IPV4_EXPLICIT_NULL = 0;
const srmpls_label_t SRMPLS_IPV6_EXPLICIT_NULL = 2;
// Control-plane binding only. This value never appears in a packet.
const srmpls_label_t SRMPLS_IMPLICIT_NULL = 3;

/*
 * SRGB ranges and local labels come from control-plane configuration.
 * Map a global SID index using the receiving node's advertised SRGB ranges.
 * A fixed base such as 16000 is a deployment choice, not a protocol constant.
 * Special-purpose labels 0-15 cannot be allocated as ordinary SR-MPLS SIDs.
 * PUSH adds labels, CONTINUE swaps the top label, NEXT pops the top label.
 * SID-to-SRv6 mapping and traffic-engineering constraints belong to configured
 * policies. They are not additional fields in the MPLS label stack entry.
 */

// Local state for the examples, not fields transmitted after an MPLS label.
struct srmpls_metadata_t {
    bit<8>         label_count;
    bit<8>         output_ttl;
    bit<1>         payload_exposed;
    srmpls_label_t popped_label;
};

/**
 * P4 Parser Logic for a Basic SR-MPLS Stack
 * The cursor points to the top label. Pass the validated remaining packet
 * length as mpls_available, excluding any link trailer supplied by the target.
 * The headers struct contains srmpls_t[16] labels, empty on entry.
 * More than 16 entries cause a parser error. This is an example capacity,
 * not a protocol limit. Adjust the stack size and PUSH capacity check together.
 * The parser stops at the first Bottom of Stack bit.
 *
 * This example accepts ordinary labels and IPv4/IPv6 Explicit Null, including
 * Explicit Null above the bottom as permitted by RFC 4182. Implicit Null is
 * never valid on the wire. Other special-purpose labels require their own
 * handlers, including Router Alert, ELI/entropy labels, GAL, XL and MNA.
 * The parent handles parser errors, special-label semantics and payload
 * parsing using the label's configured service binding. A payload is not
 * necessarily IP. Label Count does not include any unparsed payload bytes.
 */
/*
parser srmpls_parser(packet_in pkt, inout headers hdr,
                     inout srmpls_metadata_t srmpls_meta,
                     in bit<16> mpls_available) {
    bit<16> bytes_left;

    state start {
        srmpls_meta.label_count = 0;
        srmpls_meta.output_ttl = 0;
        srmpls_meta.payload_exposed = 0;
        srmpls_meta.popped_label = 0;
        bytes_left = mpls_available;
        transition parse_label;
    }

    state parse_label {
        verify(bytes_left >= 4, error.HeaderTooShort);
        pkt.extract(hdr.labels.next);
        verify(hdr.labels.last.label >= 16
               || hdr.labels.last.label == SRMPLS_IPV4_EXPLICIT_NULL
               || hdr.labels.last.label == SRMPLS_IPV6_EXPLICIT_NULL,
               error.NoMatch);
        srmpls_meta.label_count = srmpls_meta.label_count + 1;
        bytes_left = bytes_left - 4;
        transition select(hdr.labels.last.bottom_of_stack) {
            1: accept;
            default: parse_label;
        }
    }
}
*/

/**
 * Basic Label Stack Operations (v1model, Uniform TTL from RFC 3443)
 * Run once for an incoming MPLS packet. The control plane programs actual
 * outgoing labels and forwarding ports from each SID's instruction.
 * A PUSH here adds one SID to an existing stack. For an IP headend, process
 * the IP hop first, then initialize pushed labels from the resulting IP TTL.
 * CONTINUE uses swap_segment. NEXT and PHP use pop_segment.
 * An Implicit Null binding is programmed as POP, never SWAP to label 3.
 *
 * PUSH and SWAP preserve the existing stack's Bottom of Stack bits.
 * SWAP keeps TC. PUSH uses a configured TC and copies the forwarded TTL.
 * POP copies output_ttl to the newly exposed label. If no labels remain,
 * payload_exposed and popped_label let the parent select the payload binding.
 * For IP, the parent copies output_ttl to TTL/Hop Limit, updates the IPv4
 * checksum and restores the correct link protocol before forwarding.
 * It also handles the forwarding lookup required by the popped instruction,
 * egress framing, TC policy, MTU and TTL-expiry error processing.
 *
 * Explicit Null packets go intact to explicit_null_port, a configured local
 * MPLS handler. That handler pops the null label and looks up the exposed
 * label or IP packet. It must apply TTL processing once before forwarding.
 * Ordinary label operations use the forwarding table below.
 */
/*
control srmpls_control(inout headers hdr,
                       inout srmpls_metadata_t srmpls_meta,
                       inout standard_metadata_t standard_metadata,
                       in bit<9> explicit_null_port) {
    action drop_srmpls() {
        mark_to_drop(standard_metadata);
    }

    action push_segment(srmpls_label_t new_label, bit<3> tc, bit<9> port) {
        if (new_label < 16 || srmpls_meta.label_count >= 16) {
            drop_srmpls();
        } else {
            hdr.labels[0].ttl = srmpls_meta.output_ttl;
            hdr.labels.push_front(1);
            hdr.labels[0].setValid();
            hdr.labels[0].label = new_label;
            hdr.labels[0].traffic_class = tc;
            hdr.labels[0].bottom_of_stack = 0;
            hdr.labels[0].ttl = srmpls_meta.output_ttl;
            srmpls_meta.label_count = srmpls_meta.label_count + 1;
            standard_metadata.egress_spec = port;
        }
    }

    action swap_segment(srmpls_label_t new_label, bit<9> port) {
        if (new_label < 16
            && new_label != SRMPLS_IPV4_EXPLICIT_NULL
            && new_label != SRMPLS_IPV6_EXPLICIT_NULL) {
            drop_srmpls();
        } else {
            hdr.labels[0].label = new_label;
            hdr.labels[0].ttl = srmpls_meta.output_ttl;
            standard_metadata.egress_spec = port;
        }
    }

    action pop_segment(bit<9> port) {
        srmpls_meta.popped_label = hdr.labels[0].label;
        srmpls_meta.payload_exposed = hdr.labels[0].bottom_of_stack;
        hdr.labels.pop_front(1);
        srmpls_meta.label_count = srmpls_meta.label_count - 1;
        if (hdr.labels[0].isValid()) {
            hdr.labels[0].ttl = srmpls_meta.output_ttl;
        }
        standard_metadata.egress_spec = port;
    }

    table srmpls_forwarding {
        key = {
            hdr.labels[0].label: exact;
        }
        actions = {
            push_segment;
            swap_segment;
            pop_segment;
            drop_srmpls;
        }
        default_action = drop_srmpls();
    }

    apply {
        srmpls_meta.output_ttl = 0;
        srmpls_meta.payload_exposed = 0;
        srmpls_meta.popped_label = 0;
        if (standard_metadata.parser_error != error.NoError
            || !hdr.labels[0].isValid()) {
            drop_srmpls();
        } else if (hdr.labels[0].label == SRMPLS_IPV4_EXPLICIT_NULL
                   || hdr.labels[0].label == SRMPLS_IPV6_EXPLICIT_NULL) {
            standard_metadata.egress_spec = explicit_null_port;
        } else if (hdr.labels[0].ttl <= 1) {
            drop_srmpls();
        } else {
            srmpls_meta.output_ttl = hdr.labels[0].ttl - 1;
            srmpls_forwarding.apply();
        }
    }
}
*/

#endif
