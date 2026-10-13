/*
 * PCEP extensions for SR-MPLS, SRv6 and SR Policy
 * SR 路由子对象、能力 TLV 和有界 ERO/RRO 解析示例
 * RFC 8408, RFC 8664, RFC 8697, RFC 9603, RFC 9862 and RFC 9933
 */
#ifndef P4_PROTOCOL_HEADERS_PCEP_SR_P4
#define P4_PROTOCOL_HEADERS_PCEP_SR_P4

#include "pcep.p4"

const bit<8> PCEP_PST_RSVP_TE = 0;
const bit<8> PCEP_PST_SR_MPLS = 1;
const bit<8> PCEP_PST_SRV6 = 3;
const bit<16> PCEP_PATH_SETUP_TYPE_TLV = 28;
const bit<16> PCEP_PATH_SETUP_TYPE_CAPABILITY_TLV = 34;
// These are sub-TLVs inside TLV 34. The standalone TLV 26 is deprecated.
const bit<16> PCEP_SR_CAPABILITY_SUBTLV = 26;
const bit<16> PCEP_SRV6_CAPABILITY_SUBTLV = 27;
const bit<8> PCEP_SR_CAPABILITY_X = 8w0x01;
const bit<8> PCEP_SR_CAPABILITY_N = 8w0x02;
const bit<8> PCEP_SR_CAPABILITY_ALGORITHM = 8w0x04; // RFC 9933
const bit<16> PCEP_SRV6_CAPABILITY_N = 16w0x0002;
const bit<16> PCEP_SRV6_CAPABILITY_ALGORITHM = 16w0x0004; // RFC 9933

// Subobject types in ERO (class 7/type 1) and RRO (class 8/type 1).
// Both SR-MPLS ERO and RRO use 36, both SRv6 ERO and RRO use 40.
const bit<8> PCEP_SR_ROUTE_SUBOBJECT = 36;
const bit<8> PCEP_SRV6_ROUTE_SUBOBJECT = 40;
const bit<4> PCEP_SR_NAI_ABSENT = 0;
const bit<4> PCEP_SR_NAI_IPV4_NODE = 1;
const bit<4> PCEP_SR_NAI_IPV6_NODE = 2;
const bit<4> PCEP_SR_NAI_IPV4_ADJACENCY = 3;
const bit<4> PCEP_SR_NAI_IPV6_ADJACENCY = 4;
const bit<4> PCEP_SR_NAI_UNNUMBERED_ADJACENCY = 5;
const bit<4> PCEP_SR_NAI_IPV6_LINK_LOCAL_ADJACENCY = 6;
const bit<12> PCEP_SR_M = 12w0x001;
const bit<12> PCEP_SR_C = 12w0x002;
const bit<12> PCEP_SR_S = 12w0x004;
const bit<12> PCEP_SR_F = 12w0x008;
const bit<12> PCEP_SR_A = 12w0x010; // RFC 9933
const bit<12> PCEP_SRV6_S = 12w0x001;
const bit<12> PCEP_SRV6_F = 12w0x002;
const bit<12> PCEP_SRV6_T = 12w0x004;
const bit<12> PCEP_SRV6_V = 12w0x008;
const bit<12> PCEP_SRV6_A = 12w0x010; // RFC 9933
const bit<16> PCEP_SRV6_BEHAVIOR_END = 16w0x0001;
const bit<16> PCEP_SRV6_BEHAVIOR_END_X = 16w0x0005;
const bit<16> PCEP_SRV6_BEHAVIOR_UNKNOWN = 16w0xffff;

// PATH-SETUP-TYPE TLV value, length 4, in an RP or SRP object.
header pcep_path_setup_type_t {
    bit<24> reserved;
    bit<8> path_setup_type;
}

// TLV 34 value prefix, followed by num_psts one-octet PSTs. num_psts > 0.
// Pad the list to four-octet alignment before any capability sub-TLVs.
// With no sub-TLVs, length is 4 + num_psts, excluding list padding. With
// sub-TLVs, length includes list padding and excludes the final sub-TLV's
// padding. The enclosing TLV/object bounds still apply (RFC 8408).
header pcep_path_setup_type_capability_t {
    bit<24> reserved;
    bit<8> num_psts;
}

header pcep_path_setup_types_t {
    varbit<2040> path_setup_types;
}

// Sub-TLV 26 value, length 4. MSD is the maximum imposed MPLS SID depth.
// X means no MSD limit, N means NAI-to-SID resolution. The algorithm flag
// advertises RFC 9933 support. PST 1 requires this sub-TLV in TLV 34.
header pcep_sr_capability_t {
    bit<16> reserved;
    bit<8> flags;
    bit<8> maximum_sid_depth;
}

// Sub-TLV 27 value prefix, followed by zero or more two-octet MSD pairs.
// length = 4 + 2 * pair_count, excluding four-octet alignment padding.
// N means NAI-to-SID resolution. PST 3 requires this sub-TLV in TLV 34.
header pcep_srv6_capability_t {
    bit<16> reserved;
    bit<16> flags;
}

header pcep_srv6_msd_t {
    bit<8> msd_type; // IANA IGP MSD Types
    bit<8> msd_value;
}

// The following are alternative fixed subobject prefixes. length includes
// the prefix and conditional fields. Extract either a typed prefix and
// its fields below, or the generic pcep_sr_route_subobject_t, not both.
// SR-MPLS length is at least 8 and a multiple of 4. Optional fields are
// SID (4 octets), NAI, then the RFC 9933 Subobject Extension Block.
// S means SID absent, F means NAI absent. S and F cannot both be set.
// If S is set, M/C must be zero. M selects an MPLS entry instead of an
// index into SRGB/SRLB, C supplies TC/S/TTL and requires M. NT is ignored
// when F is set. A requires negotiated algorithm support and an extension
// block. Unassigned flags are ignored on receipt. L is only in ERO.
header pcep_sr_ero_t {
    bit<1> loose;
    bit<7> type;
    bit<8> length;
    bit<4> nai_type;
    bit<12> flags;
}

header pcep_sr_rro_t {
    bit<8> type;
    bit<8> length;
    bit<4> nai_type;
    bit<12> flags;
}

header pcep_sr_sid_index_t {
    bit<32> sid_index;
}

header pcep_sr_mpls_sid_t {
    bit<20> label;
    bit<3> traffic_class;
    bit<1> bottom_of_stack;
    bit<8> ttl;
}

// First four octets of the RFC 9933 extension block. A alone adds 4 bytes.
// Future flags can extend the block in multiples of four octets. Algorithm
// is meaningful only with A. The block follows all other optional fields.
header pcep_sr_subobject_extension_t {
    bit<24> unassigned;
    bit<8> algorithm;
}

// SRv6 length is at least 24 and a multiple of 4. Optional fields are
// SRv6 SID (16 octets), NAI (NT 2/4/6), then SID structure (8 octets).
// S/F mean SID/NAI absent. T means structure present, but is ignored if S
// is set. S and F cannot both be set. V requests SID verification in ERO
// and is ignored in RRO. Endpoint behavior is 16 bits, unknown is 0xffff.
// RFC 9933 assigns one former reserved octet to Algorithm, valid with A.
// Algorithm does not change the length and requires negotiated support.
header pcep_srv6_ero_t {
    bit<1> loose;
    bit<7> type;
    bit<8> length;
    bit<4> nai_type;
    bit<12> flags;
    bit<8> reserved;
    bit<8> algorithm;
    bit<16> endpoint_behavior;
}

header pcep_srv6_rro_t {
    bit<8> type;
    bit<8> length;
    bit<4> nai_type;
    bit<12> flags;
    bit<8> reserved;
    bit<8> algorithm;
    bit<16> endpoint_behavior;
}

header pcep_srv6_sid_t {
    bit<128> sid;
}

// Lengths are in bits. The handler validates their sum <= 128. Reserved
// and unassigned flags are zero on transmission and ignored on receipt.
header pcep_srv6_sid_structure_t {
    bit<8> locator_block_length;
    bit<8> locator_node_length;
    bit<8> function_length;
    bit<8> argument_length;
    bit<24> reserved;
    bit<8> flags;
}

// Conditional NAI values, with no embedded type/length prefix.
header pcep_sr_ipv4_node_t {
    bit<32> node;
}

header pcep_sr_ipv6_node_t {
    bit<128> node;
}

header pcep_sr_ipv4_adjacency_t {
    bit<32> local_address;
    bit<32> remote_address;
}

header pcep_sr_ipv6_adjacency_t {
    bit<128> local_address;
    bit<128> remote_address;
}

header pcep_sr_unnumbered_adjacency_t {
    bit<32> local_node;
    bit<32> local_interface;
    bit<32> remote_node;
    bit<32> remote_interface;
}

// Global node addresses and interface IDs identify a link-local adjacency.
header pcep_sr_ipv6_link_local_adjacency_t {
    bit<128> local_node;
    bit<32> local_interface;
    bit<128> remote_node;
    bit<32> remote_interface;
}

const pcep_object_class_t PCEP_ASSOCIATION_OBJ = 40;
const bit<16> PCEP_SR_POLICY_ASSOCIATION = 6;
const bit<16> PCEP_ASSOCIATION_REMOVE = 16w0x0001;
const bit<16> PCEP_EXTENDED_ASSOCIATION_ID_TLV = 31;
const bit<16> PCEP_SR_POLICY_NAME_TLV = 56;
const bit<16> PCEP_SR_CANDIDATE_PATH_ID_TLV = 57;
const bit<16> PCEP_SR_CANDIDATE_PATH_NAME_TLV = 58;
const bit<16> PCEP_SR_CANDIDATE_PATH_PREFERENCE_TLV = 59;
const bit<8> PCEP_SR_POLICY_ORIGIN_PCEP = 10;
const bit<32> PCEP_SR_POLICY_DEFAULT_PREFERENCE = 100;

// ASSOCIATION fixed bodies, class 40/type 1 (IPv4) or type 2 (IPv6).
// SR Policy uses association_type 6, association_id 1, source = headend.
// TLVs follow these bodies. Extended Association ID and Candidate Path ID
// are mandatory for SRPA. Use pcep_tlv_t for their prefixes and raw values.
header pcep_sr_ipv4_association_t {
    bit<16> reserved;
    bit<16> flags;
    bit<16> association_type;
    bit<16> association_id;
    bit<32> association_source;
}

header pcep_sr_ipv6_association_t {
    bit<16> reserved;
    bit<16> flags;
    bit<16> association_type;
    bit<16> association_id;
    bit<128> association_source;
}

// Extended Association ID TLV values for SRPA, lengths 8 and 20. Color
// is nonzero. Endpoint can be unspecified for Color-Only steering.
header pcep_sr_policy_ipv4_id_t {
    bit<32> color;
    bit<32> endpoint;
}

header pcep_sr_policy_ipv6_id_t {
    bit<32> color;
    bit<128> endpoint;
}

// Candidate Path ID TLV value, length 28. Originator address is always
// 128 bits. In PCInitiate, protocol_origin is 10 and the PCE is originator.
header pcep_sr_candidate_path_id_t {
    bit<8> protocol_origin;
    bit<24> reserved;
    bit<32> originator_asn;
    bit<128> originator_address;
    bit<32> discriminator;
}

// TLV 56/58 value, printable ASCII without a NULL terminator. length > 0,
// excluding padding. 255 octets is recommended, not the wire limit.
header pcep_sr_policy_name_t {
    varbit<524280> name;
}

// Candidate Path Preference TLV value, length 4. Absent means 100.
header pcep_sr_candidate_path_preference_t {
    bit<32> preference;
}

const bit<16> PCEP_SR_ALGORITHM_TLV = 66;
const bit<8> PCEP_SR_ALGORITHM_STRICT = 8w0x01;

// LSPA SR-Algorithm TLV value, length 4, for PST 1/3 (RFC 9933).
header pcep_sr_algorithm_t {
    bit<16> reserved;
    bit<8> flags;
    bit<8> algorithm;
}

const bit<8> PCEP_SR_METRIC_SID_DEPTH = 11;
const bit<8> PCEP_SR_METRIC_BOUND = 8w0x01;
const bit<8> PCEP_SR_METRIC_COMPUTED = 8w0x02;

// METRIC fixed body, class 6/type 1. metric_value is IEEE 754 binary32,
// not an integer threshold. T=11 counts SIDs, not every ERO subobject.
header pcep_sr_metric_t {
    bit<16> reserved;
    bit<8> flags;
    bit<8> metric_type;
    bit<32> metric_value;
}

// Generic ordered storage for any ERO/RRO subobject. In ERO the high bit
// of type_flags is L and the low seven bits are Type. RRO uses all eight
// bits as Type. length includes the two-octet prefix, with no TLV padding.
// The capacity covers the eight-bit length field, including unknown types.
header pcep_sr_route_subobject_t {
    bit<8> type_flags;
    bit<8> length;
    varbit<2024> value;
}

const bit<8> PCEP_SR_EXAMPLE_MAX_SUBOBJECTS = 64; // Storage, not a wire limit

struct pcep_sr_metadata_t {
    pcep_object_class_t route_class;
    bit<32> route_bytes;
    bit<32> parsed_bytes;
    bit<32> remaining;
    bit<8> subobject_bytes;
    bit<8> subobject_type;
    bit<8> subobject_count;
    bool sr_mpls_seen;
    bool srv6_seen;
    bool subobjects_pending;
}

/*
 * One framed ERO/RRO body and local delivery example
 * headers contains pcep_sr_route_subobject_t[64] pcep_sr_subobjects.
 * metadata contains pcep_sr_metadata_t pcep_sr. Invoke with headers invalid.
 *
 * The caller handles TCP framing and validates the PCEP common/object
 * prefixes, including ERO/RRO class/type and object bounds. route_bytes
 * is the physically available body size, object_length - 4. The cursor
 * starts after that object's prefix. This replaces extraction of its raw
 * pcep_object_t.object_value. Do not parse an already extracted body again.
 * Other PCEP objects and trailing bytes are outside this helper's bounds.
 *
 * This checks subobject framing and SR minimum/aligned lengths. Conditional
 * fields, unknown types, flags and extensions remain in their original
 * order. Store at most 64 subobjects. If more remain, set subobjects_pending
 * and leave the cursor at the next prefix. The handler must finish that
 * tail and validate all lengths before interpreting the route. Emit the
 * valid stack, then the remaining payload, to preserve the object's bytes.
 * Empty EROs can signal failed computations. Message-specific rules apply.
 *
 * The session owner checks SID/NAI/structure/extension sizes against NT and
 * flags, capabilities, PST, route consistency and supported types. It also
 * handles SID resolution, SID verification, SR Policy TLVs, path computation
 * and PCErr responses. Parsing a route does not install or negotiate it.
 * Unknown types remain available for the appropriate protocol error, rather
 * than being interpreted as a known SR subobject. Local ports select owners.
 */
/*
parser pcep_sr_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                      in pcep_object_class_t route_class,
                      in bit<32> route_bytes) {
    bit<16> prefix;

    state start {
        meta.pcep_sr.route_class = route_class;
        meta.pcep_sr.route_bytes = route_bytes;
        meta.pcep_sr.parsed_bytes = 0;
        meta.pcep_sr.remaining = route_bytes;
        meta.pcep_sr.subobject_bytes = 0;
        meta.pcep_sr.subobject_type = 0;
        meta.pcep_sr.subobject_count = 0;
        meta.pcep_sr.sr_mpls_seen = false;
        meta.pcep_sr.srv6_seen = false;
        meta.pcep_sr.subobjects_pending = false;
        verify((route_class == PCEP_ERO_OBJ || route_class == PCEP_RRO_OBJ)
               && route_bytes <= 65528 && route_bytes[1:0] == 0,
               error.NoMatch);
        transition next_subobject;
    }

    state next_subobject {
        transition select(meta.pcep_sr.remaining, meta.pcep_sr.subobject_count) {
            (0, _): accept;
            (_, PCEP_SR_EXAMPLE_MAX_SUBOBJECTS): pending;
            default: subobject;
        }
    }

    state subobject {
        verify(meta.pcep_sr.remaining >= 2, error.NoMatch);
        prefix = pkt.lookahead<bit<16>>();
        meta.pcep_sr.subobject_bytes = prefix[7:0];
        meta.pcep_sr.subobject_type = prefix[15:8];
        verify(meta.pcep_sr.subobject_bytes >= 2
               && (bit<32>)meta.pcep_sr.subobject_bytes <= meta.pcep_sr.remaining,
               error.NoMatch);
        transition select(meta.pcep_sr.route_class) {
            PCEP_ERO_OBJ: ero_type;
            default: route_type;
        }
    }

    state ero_type {
        meta.pcep_sr.subobject_type = meta.pcep_sr.subobject_type & 8w0x7f;
        transition route_type;
    }

    state route_type {
        transition select(meta.pcep_sr.subobject_type) {
            PCEP_SR_ROUTE_SUBOBJECT: sr_mpls;
            PCEP_SRV6_ROUTE_SUBOBJECT: srv6;
            default: extract_subobject;
        }
    }

    state sr_mpls {
        verify(meta.pcep_sr.subobject_bytes >= 8
               && meta.pcep_sr.subobject_bytes[1:0] == 0, error.NoMatch);
        meta.pcep_sr.sr_mpls_seen = true;
        transition extract_subobject;
    }

    state srv6 {
        verify(meta.pcep_sr.subobject_bytes >= 24
               && meta.pcep_sr.subobject_bytes[1:0] == 0, error.NoMatch);
        meta.pcep_sr.srv6_seen = true;
        transition extract_subobject;
    }

    state extract_subobject {
        pkt.extract(hdr.pcep_sr_subobjects.next,
                    ((bit<32>)meta.pcep_sr.subobject_bytes - 2) * 8);
        meta.pcep_sr.subobject_count = meta.pcep_sr.subobject_count + 1;
        meta.pcep_sr.parsed_bytes = meta.pcep_sr.parsed_bytes
                                    + (bit<32>)meta.pcep_sr.subobject_bytes;
        meta.pcep_sr.remaining = meta.pcep_sr.remaining
                                 - (bit<32>)meta.pcep_sr.subobject_bytes;
        transition next_subobject;
    }

    state pending {
        meta.pcep_sr.subobjects_pending = true;
        transition accept;
    }
}

// v1model example. handler_port identifies the local PCEP session owner.
control pcep_sr_control(inout headers hdr, inout metadata meta,
                        inout standard_metadata_t standard_metadata,
                        in bit<9> handler_port) {
    action deliver(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action deliver_default() {
        standard_metadata.egress_spec = handler_port;
    }

    table route_handlers {
        key = {
            standard_metadata.ingress_port: exact;
            meta.pcep_sr.route_class: exact;
            meta.pcep_sr.sr_mpls_seen: exact;
            meta.pcep_sr.srv6_seen: exact;
            meta.pcep_sr.subobjects_pending: exact;
        }
        actions = { deliver; deliver_default; }
        default_action = deliver_default();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError) {
            mark_to_drop(standard_metadata);
        } else {
            route_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_PCEP_SR_P4
