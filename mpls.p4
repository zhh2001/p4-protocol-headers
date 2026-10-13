/*
 * Multiprotocol Label Switching
 * MPLS 标签栈、LDP 与 RSVP-TE 报头
 * RFC 3032, RFC 3443, RFC 4182, RFC 5036, RFC 2205 and RFC 3209
 */
#ifndef P4_PROTOCOL_HEADERS_MPLS_P4
#define P4_PROTOCOL_HEADERS_MPLS_P4

typedef bit<20> mpls_label_t;

const bit<16> MPLS_ETHERTYPE_UNICAST = 16w0x8847;
const bit<16> MPLS_ETHERTYPE_MULTICAST = 16w0x8848;
const bit<16> MPLS_LDP_PORT = 16w646; // TCP sessions, UDP discovery
const bit<8> MPLS_RSVP_IP_PROTOCOL = 8w46;
const bit<16> MPLS_LDP_VERSION = 16w1;
const bit<4> MPLS_RSVP_VERSION = 4w1;
const bit<8> MPLS_EXAMPLE_MAX_LABELS = 8w16;
const bit<8> MPLS_EXAMPLE_MAX_LDP_MESSAGES = 8w16;
const bit<8> MPLS_EXAMPLE_MAX_RSVP_OBJECTS = 8w32;

// Local forwarding operations, not fields in an MPLS packet.
enum bit<8> mpls_operation {
    PUSH = 0,
    SWAP = 1,
    POP = 2
};

// Assigned base special-purpose labels from the IANA registry.
// Implicit Null is a control-plane binding and never appears on the wire.
// MNA (RFC 9994), ELI and XL introduce context that requires its own parser.
enum bit<20> mpls_special_labels {
    IPV4_EXPLICIT_NULL = 0,
    ROUTER_ALERT = 1,
    IPV6_EXPLICIT_NULL = 2,
    IMPLICIT_NULL = 3,
    MPLS_NETWORK_ACTIONS = 4,
    ENTROPY_LABEL_INDICATOR = 7,
    GENERIC_ASSOCIATED_CHANNEL = 13,
    OAM_ALERT = 14,
    EXTENSION_LABEL = 15
};

// Four-octet label stack entry. Top label first, S = 1 at the bottom.
// TC is the former EXP field (RFC 5462). Payload type comes from the
// label's service binding, not solely from S or the first payload nibble.
header mpls_shim {
    mpls_label_t label;
    bit<3> traffic_class;
    bit<1> bottom_of_stack;
    bit<8> ttl;
};

// Fourteen-octet untagged Ethernet prefix. VLAN tags need a separate parser.
// Use this type or ethernet.p4's Ethernet type, without extracting both.
header mpls_transport {
    bit<48> dst_mac;
    bit<48> src_mac;
    bit<16> eth_type;
};

// MPLS has no shared control header for LDP and RSVP. LDP runs over
// TCP/UDP, RSVP over IP protocol 46. Neither follows every MPLS shim.

// LDP PDU prefix, ten octets. pdu_length excludes the first four octets,
// so total length is pdu_length + 4. The six-octet identifier is LSR ID
// plus label-space ID. A PDU contains one or more messages, with no padding.
// Platform-wide label-space IDs SHOULD be zero, not MUST (RFC 5036).
header mpls_ldp {
    bit<16> version;
    bit<16> pdu_length;
    bit<32> lsr_id;
    bit<16> label_space;
};

const bit<15> MPLS_LDP_LABEL_MAPPING = 15w0x0400;
const bit<14> MPLS_LDP_FEC_TLV = 14w0x0100;
const bit<14> MPLS_LDP_GENERIC_LABEL_TLV = 14w0x0200;

// Eight fixed octets, then raw parameters. message_length excludes U,
// type and length, but includes the four-octet message_id, so it is >= 4.
// U controls treatment of unknown message types. No alignment padding.
// Label Mapping uses this prefix, followed by a FEC TLV, a label TLV and
// optional TLVs. It has no single fixed FEC/label/attributes body.
header mpls_ldp_message_t {
    bit<1> unknown;
    bit<15> message_type;
    bit<16> message_length;
    bit<32> message_id;
    varbit<524248> parameters; // (65535 - 4) * 8, bounded by the PDU
};

// LDP TLV: length is value octets only, with no alignment padding.
// F is meaningful for an unknown TLV only when U = 1. The session owner
// applies U/F rules and validates required parameters and nested values.
header mpls_ldp_tlv_t {
    bit<1> unknown;
    bit<1> forward;
    bit<14> type;
    bit<16> length;
    varbit<524280> value;
};

// Alternative TLV values, not additional fields after a raw TLV value.
// FEC type 1 is a single-octet wildcard. Type 2 starts with this prefix,
// then ceil(prefix_length / 8) address octets, with no full-address padding.
// AFI 1/2 denotes IPv4/IPv6, with prefix lengths <= 32/128 respectively.
// A FEC TLV can contain multiple elements, not a single 32-bit FEC.
header mpls_ldp_wildcard_fec_t {
    bit<8> fec_type;
};

header mpls_ldp_prefix_fec_t {
    bit<8> fec_type;
    bit<16> address_family;
    bit<8> prefix_length;
    varbit<128> prefix;
};

// Generic Label TLV has a four-octet value and length 4. Preserve its
// complete representation. RFC 5036 section 3.4.2.1 shows a label in the
// high twenty bits. Right-aligned deployed encodings need explicit peer
// policy before interpretation. This is not a shim with TC, S and TTL.
header mpls_ldp_generic_label_t {
    bit<32> label_field;
};

// RSVP common header, eight octets. length includes this header and all
// objects. checksum covers the whole message, with zero meaning omitted.
// send_ttl is the IP TTL used by the sender, not a 16-bit MPLS TTL.
// Flags include extension assignments and reserved bits remain raw.
header mpls_rsvp_te {
    bit<4> version;
    bit<4> flags;
    bit<8> message_type;
    bit<16> rsvp_checksum;
    bit<8> send_ttl;
    bit<8> reserved;
    bit<16> length;
};

// Four-octet RSVP object prefix plus raw body. length includes the prefix,
// is >= 4 and a multiple of 4. Unknown-class behavior depends on the two
// high bits of class_number. Preserve the object for the RSVP owner.
header mpls_rsvp_object_t {
    bit<16> length;
    bit<8> class_number;
    bit<8> c_type;
    varbit<524224> value; // (65532 - 4) * 8
};

const bit<8> MPLS_RSVP_LABEL_CLASS = 8w16;
const bit<8> MPLS_RSVP_LABEL_REQUEST_CLASS = 8w19;
const bit<8> MPLS_RSVP_ERO_CLASS = 8w20;

// RSVP LABEL class 16/C-Type 1, four-octet generic MPLS value.
// RFC 3209 explicitly uses right alignment, with label <= 1048575.
header mpls_rsvp_label_t {
    bit<12> reserved;
    mpls_label_t label;
};

// LABEL_REQUEST class 19/C-Type 1, four-octet body. l3pid is an EtherType.
header mpls_rsvp_label_request_t {
    bit<16> reserved;
    bit<16> l3pid;
};

// ERO class 20/C-Type 1 contains a sequence of these subobjects, not a
// separate fixed routing header. length includes L/type/length, is >= 4
// and a multiple of 4, so the largest encoded length is 252 octets.
header mpls_ero {
    bit<1> loose;
    bit<7> type;
    bit<8> length;
    varbit<2000> value;
};

// Alternative complete ERO subobjects. Extract once instead of mpls_ero.
// Address host bits and reserved padding are ignored on receipt.
header mpls_ero_ipv4_t {
    bit<1> loose;
    bit<7> type; // 1
    bit<8> length; // 8
    bit<32> address;
    bit<8> prefix_length; // 0..32
    bit<8> reserved;
};

header mpls_ero_ipv6_t {
    bit<1> loose;
    bit<7> type; // 2
    bit<8> length; // 20
    bit<128> address;
    bit<8> prefix_length; // 0..128
    bit<8> reserved;
};

header mpls_ero_as_t {
    bit<1> loose;
    bit<7> type; // 32
    bit<8> length; // 4
    bit<16> as_number;
};

// Local parser/control state, not transmitted protocol fields.
struct mpls_metadata_t {
    bit<32> remaining;
    bit<8> label_count;
    bit<8> output_ttl;
    bit<1> payload_exposed;
    mpls_label_t popped_label;
    bool special_label;
    bool labels_pending;
};

struct mpls_ldp_metadata_t {
    bit<32> remaining;
    bit<16> message_length;
    bit<8> message_count;
    bool messages_pending;
};

struct mpls_rsvp_metadata_t {
    bit<32> remaining;
    bit<16> object_length;
    bit<8> object_count;
    bool objects_pending;
};

/*
 * Bounded label-stack example
 * headers contains mpls_shim[16] labels, initially invalid. The cursor
 * points to the top label and available_bytes is the physically available
 * MPLS region after enclosing length checks, excluding link trailers.
 * Stop at S = 1, at a special-purpose label, or at the example capacity.
 * Entries after a special label can have different formats, e.g. MNA NAS,
 * an entropy label or an extended label. They remain unparsed and intact.
 * The owner finishes pending stacks and applies special-label semantics.
 * Explicit Null is allowed above the bottom (RFC 4182). Implicit Null is
 * rejected when encountered as a base label. S and payload contents alone
 * do not identify a service. Emit labels and the untouched remainder once.
 */
/*
parser mpls_parser(packet_in pkt, inout headers hdr,
                   inout mpls_metadata_t meta, in bit<32> available_bytes) {
    state start {
        meta.remaining = available_bytes;
        meta.label_count = 0;
        meta.output_ttl = 0;
        meta.payload_exposed = 0;
        meta.popped_label = 0;
        meta.special_label = false;
        meta.labels_pending = false;
        transition parse_label;
    }

    state parse_label {
        verify(meta.remaining >= 4, error.HeaderTooShort);
        pkt.extract(hdr.labels.next);
        verify(hdr.labels.last.label != 20w3, error.NoMatch);
        meta.label_count = meta.label_count + 1;
        meta.remaining = meta.remaining - 4;
        transition select(hdr.labels.last.label) {
            20w0 .. 20w15: special_label;
            default: check_bottom;
        }
    }

    state special_label {
        meta.special_label = true;
        transition accept;
    }

    state check_bottom {
        transition select(hdr.labels.last.bottom_of_stack) {
            1: accept;
            default: check_capacity;
        }
    }

    state check_capacity {
        verify(meta.remaining >= 4, error.HeaderTooShort);
        transition select(meta.label_count) {
            MPLS_EXAMPLE_MAX_LABELS: pending_labels;
            default: parse_label;
        }
    }

    state pending_labels {
        meta.labels_pending = true;
        transition accept;
    }
}
*/

/*
 * PUSH, SWAP and POP for an incoming MPLS stack (v1model, Uniform TTL)
 * Table labels and output ports come from the configured forwarding state.
 * Run once per forwarding hop. PUSH adds one label to an existing stack.
 * IP headends first process the IP hop, then copy its TTL to new labels.
 * SWAP preserves TC and S. PUSH uses configured TC and preserves old S.
 * POP transfers output_ttl to the newly exposed label, without decrementing
 * again. An Implicit Null binding is programmed as POP, never as SWAP to 3.
 *
 * When POP empties the stack, the parent uses popped_label's service binding
 * to parse the payload and restore link encapsulation. For an IP payload it
 * copies output_ttl to TTL/Hop Limit and updates the IPv4 header checksum.
 * The parent also supplies egress framing, TC policy, MTU and routing state.
 * special_port and expiry_port select local handlers, never network egress.
 * Special and pending stacks go there unchanged. The handler completes
 * parsing and applies TTL processing once if the packet is to be forwarded.
 * Expired ordinary stacks go intact to error handling, with no forwarding.
 */
/*
control mpls_control(inout headers hdr, inout mpls_metadata_t meta,
                     inout standard_metadata_t standard_metadata,
                     in bit<9> special_port, in bit<9> expiry_port) {
    action drop_mpls() {
        mark_to_drop(standard_metadata);
    }

    action push_label(mpls_label_t new_label, bit<3> tc, bit<9> port) {
        if (new_label < 16 || meta.label_count >= MPLS_EXAMPLE_MAX_LABELS) {
            drop_mpls();
        } else {
            hdr.labels[0].ttl = meta.output_ttl;
            hdr.labels.push_front(1);
            hdr.labels[0].setValid();
            hdr.labels[0].label = new_label;
            hdr.labels[0].traffic_class = tc;
            hdr.labels[0].bottom_of_stack = 0;
            hdr.labels[0].ttl = meta.output_ttl;
            meta.label_count = meta.label_count + 1;
            standard_metadata.egress_spec = port;
        }
    }

    action swap_label(mpls_label_t new_label, bit<9> port) {
        if (new_label < 16 && new_label != 0 && new_label != 2) {
            drop_mpls();
        } else {
            hdr.labels[0].label = new_label;
            hdr.labels[0].ttl = meta.output_ttl;
            standard_metadata.egress_spec = port;
        }
    }

    action pop_label(bit<9> port) {
        meta.popped_label = hdr.labels[0].label;
        meta.payload_exposed = hdr.labels[0].bottom_of_stack;
        hdr.labels.pop_front(1);
        meta.label_count = meta.label_count - 1;
        if (hdr.labels[0].isValid()) {
            hdr.labels[0].ttl = meta.output_ttl;
        }
        standard_metadata.egress_spec = port;
    }

    table mpls_forwarding {
        key = {
            hdr.labels[0].label: exact;
        }
        actions = {
            push_label;
            swap_label;
            pop_label;
            drop_mpls;
        }
        default_action = drop_mpls();
    }

    apply {
        meta.output_ttl = 0;
        meta.payload_exposed = 0;
        meta.popped_label = 0;
        if (standard_metadata.parser_error != error.NoError
            || !hdr.labels[0].isValid()) {
            drop_mpls();
        } else if (meta.special_label || meta.labels_pending) {
            standard_metadata.egress_spec = special_port;
        } else if (hdr.labels[0].ttl <= 1) {
            standard_metadata.egress_spec = expiry_port;
        } else {
            meta.output_ttl = hdr.labels[0].ttl - 1;
            mpls_forwarding.apply();
        }
    }
}
*/

/*
 * One framed LDP PDU and one RSVP message
 * headers contains mpls_ldp ldp, mpls_ldp_message_t[16] ldp_messages,
 * mpls_rsvp_te rsvp and mpls_rsvp_object_t[32] rsvp_objects, invalid on entry.
 * Each helper starts at its protocol header. framed_bytes is the physically
 * present size of exactly one complete message/PDU after outer length checks.
 * TCP reassembly and LDP PDU framing belong to the caller, not these parsers.
 * The owner enforces the LDP negotiated maximum, mandatory parameters, U/F
 * rules, RSVP class/C-Type semantics, checksum, authentication and sessions.
 * Raw parameters/object bodies include nested TLVs and ERO subobjects.
 * Capacities are local storage choices. Pending messages/objects and their
 * unparsed bytes go unchanged to the owner. Emit each parsed header and
 * stored raw body once, followed by the untouched remainder. On parser error
 * drop the packet. Otherwise deliver to a configured local protocol handler.
 */
/*
parser mpls_ldp_parser(packet_in pkt, inout headers hdr,
                       inout mpls_ldp_metadata_t meta,
                       in bit<32> framed_bytes) {
    state start {
        meta.remaining = 0;
        meta.message_length = 0;
        meta.message_count = 0;
        meta.messages_pending = false;
        verify(framed_bytes >= 18, error.HeaderTooShort);
        pkt.extract(hdr.ldp);
        verify(hdr.ldp.version == MPLS_LDP_VERSION, error.NoMatch);
        verify((bit<32>)hdr.ldp.pdu_length + 4 == framed_bytes,
               error.NoMatch);
        meta.remaining = framed_bytes - 10;
        transition parse_message;
    }

    state parse_message {
        verify(meta.remaining >= 8, error.HeaderTooShort);
        meta.message_length = pkt.lookahead<bit<64>>()[47:32];
        verify(meta.message_length >= 4
               && (bit<32>)meta.message_length + 4 <= meta.remaining,
               error.NoMatch);
        pkt.extract(hdr.ldp_messages.next,
                    ((bit<32>)meta.message_length - 4) * 8);
        meta.remaining = meta.remaining - (bit<32>)meta.message_length - 4;
        meta.message_count = meta.message_count + 1;
        transition select(meta.remaining) {
            0: accept;
            default: check_capacity;
        }
    }

    state check_capacity {
        verify(meta.remaining >= 8, error.HeaderTooShort);
        transition select(meta.message_count) {
            MPLS_EXAMPLE_MAX_LDP_MESSAGES: pending_messages;
            default: parse_message;
        }
    }

    state pending_messages {
        meta.messages_pending = true;
        transition accept;
    }
}

parser mpls_rsvp_parser(packet_in pkt, inout headers hdr,
                        inout mpls_rsvp_metadata_t meta,
                        in bit<32> framed_bytes) {
    state start {
        meta.remaining = 0;
        meta.object_length = 0;
        meta.object_count = 0;
        meta.objects_pending = false;
        verify(framed_bytes >= 8, error.HeaderTooShort);
        pkt.extract(hdr.rsvp);
        verify(hdr.rsvp.version == MPLS_RSVP_VERSION
               && (bit<32>)hdr.rsvp.length == framed_bytes
               && hdr.rsvp.length[1:0] == 0, error.NoMatch);
        meta.remaining = framed_bytes - 8;
        transition select(meta.remaining) {
            0: accept;
            default: parse_object;
        }
    }

    state parse_object {
        verify(meta.remaining >= 4, error.HeaderTooShort);
        meta.object_length = pkt.lookahead<bit<32>>()[31:16];
        verify(meta.object_length >= 4 && meta.object_length[1:0] == 0
               && (bit<32>)meta.object_length <= meta.remaining,
               error.NoMatch);
        pkt.extract(hdr.rsvp_objects.next,
                    ((bit<32>)meta.object_length - 4) * 8);
        meta.remaining = meta.remaining - (bit<32>)meta.object_length;
        meta.object_count = meta.object_count + 1;
        transition select(meta.remaining) {
            0: accept;
            default: check_capacity;
        }
    }

    state check_capacity {
        verify(meta.remaining >= 4, error.HeaderTooShort);
        transition select(meta.object_count) {
            MPLS_EXAMPLE_MAX_RSVP_OBJECTS: pending_objects;
            default: parse_object;
        }
    }

    state pending_objects {
        meta.objects_pending = true;
        transition accept;
    }
}
*/

#endif
