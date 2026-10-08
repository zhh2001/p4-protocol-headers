#ifndef P4_PROTOCOL_HEADERS_BGP_SR_P4
#define P4_PROTOCOL_HEADERS_BGP_SR_P4

/**
 * BGP SR Policy (RFC 9830, RFC 9012)
 * SR Policy NLRI、隧道属性和段列表定义
 * Include bgp.p4 separately for BGP message and path attribute framing.
 * NLRI and the Tunnel Encapsulation attribute occupy separate UPDATE regions.
 */
const bit<16> BGP_SR_AFI_IPV4 = 1;
const bit<16> BGP_SR_AFI_IPV6 = 2;
const bit<8> BGP_SR_SAFI = 73;
const bit<8> BGP_SR_NLRI_IPV4_BITS = 96;
const bit<8> BGP_SR_NLRI_IPV6_BITS = 192;
const bit<8> BGP_SR_TUNNEL_ATTRIBUTE = 23;
const bit<16> BGP_SR_TUNNEL_TYPE = 15;

/* Sub-TLV types inside the SR Policy Tunnel TLV. */
const bit<8> BGP_SR_PREFERENCE = 12;
const bit<8> BGP_SR_BINDING_SID = 13;
const bit<8> BGP_SR_ENLP = 14;
const bit<8> BGP_SR_PRIORITY = 15;
const bit<8> BGP_SR_SRV6_BINDING_SID = 20;
const bit<8> BGP_SR_SEGMENT_LIST = 128;
const bit<8> BGP_SR_CANDIDATE_PATH_NAME = 129;
const bit<8> BGP_SR_POLICY_NAME = 130;

/* Sub-TLV types inside a Segment List, a separate type namespace. */
const bit<8> BGP_SR_SEGMENT_A = 1;
const bit<8> BGP_SR_SEGMENT_B = 13;
const bit<8> BGP_SR_WEIGHT = 9;

/* Masks in the respective one-byte Flags fields. */
const bit<8> BGP_SR_BSID_SPECIFIED_ONLY = 0x80;
const bit<8> BGP_SR_BSID_DROP_INVALID = 0x40;
const bit<8> BGP_SR_SRV6_BSID_STRUCTURE = 0x20;
const bit<8> BGP_SR_SEGMENT_VERIFY = 0x80;
const bit<8> BGP_SR_SEGMENT_STRUCTURE = 0x10;

/**
 * One SR Policy NLRI, selected by AFI (13 or 25 bytes).
 * Length counts bits after the length octet, not bytes or the whole record.
 * Color is a nonzero unsigned value. Distinguisher separates candidate paths.
 * Endpoint can be unicast or unspecified. ADD-PATH, when negotiated, adds a
 * four-byte path identifier before this NLRI and is handled by the caller.
 */
header bgp_sr_ipv4_nlri_t {
    bit<8>  length;
    bit<32> distinguisher;
    bit<32> color;
    bit<32> endpoint;
};

header bgp_sr_ipv6_nlri_t {
    bit<8>   length;
    bit<32>  distinguisher;
    bit<32>  color;
    bit<128> endpoint;
};

/**
 * Tunnel Encapsulation TLV prefix (4 bytes), inside BGP attribute 23.
 * Tunnel Type is 15 for SR Policy. Length counts subsequent value bytes.
 * An SR Policy advertisement contains exactly one SR Policy Tunnel TLV.
 * Other tunnel types and duplicate SR Policy Tunnel TLVs are malformed.
 */
header bgp_sr_tunnel_t {
    bit<16> tunnel_type;
    bit<16> length;
};

/**
 * Tunnel sub-TLV prefixes. Type 0-127 uses an 8-bit length, type 128-255
 * a 16-bit length. Both lengths count value bytes only (RFC 9012).
 */
header bgp_sr_short_sub_tlv_t {
    bit<8> type;
    bit<8> length;
};

header bgp_sr_long_sub_tlv_t {
    bit<8>  type;
    bit<16> length;
};

/**
 * Ordered generic tunnel sub-TLV, for a mixed short/long header stack.
 * Body includes the encoded length field and opaque value. Extract
 * (length bytes + value bytes) * 8 variable bits after checking the bounds.
 * Capacity covers two length octets and the largest 16-bit value length.
 * Enclosing BGP message, attribute, tunnel and target limits still apply.
 */
header bgp_sr_sub_tlv_t {
    bit<8> type;
    varbit<524296> body;
};

/**
 * The following headers describe sub-TLV VALUES, excluding Type and Length.
 * Check the type, length and enclosing bounds before extracting a value.
 * Reserved fields and unassigned flag bits are sent as zero and ignored
 * on receipt. RFC 9831 segment extensions can use the generic representation.
 */
header bgp_sr_preference_t {       // Type 12, value length 6
    bit<8>  flags;
    bit<8>  reserved;
    bit<32> preference;
};

/* Type 13: value length 2, 6 or 18. Extract this prefix, then no SID,
 * bgp_sr_binding_label_t, or bgp_sr_ipv6_sid_t respectively.
 */
header bgp_sr_binding_sid_prefix_t {
    bit<8> flags;                 // S=0x80, I=0x40
    bit<8> reserved;
};

header bgp_sr_binding_label_t {
    bit<20> label;                // Binding label must be greater than 15
    bit<12> reserved;             // TC, S and TTL are unused for a BSID
};

header bgp_sr_ipv6_sid_t {
    bit<128> sid;
};

/* Type 20, value length 18 or 26. B=0x20 selects the eight-byte
 * bgp_sr_sid_structure_t suffix. A zero SID carries behavior or flags without
 * specifying a BSID.
 */
header bgp_sr_srv6_binding_sid_t {
    bit<8>   flags;
    bit<8>   reserved;
    bit<128> sid;
};

/* Type 128: value begins with this reserved octet, followed by nested
 * Weight/Segment sub-TLVs. The enclosing value length includes this octet.
 */
header bgp_sr_segment_list_t {
    bit<8> reserved;
};

header bgp_sr_weight_t {           // Nested type 9, value length 6
    bit<8>  flags;
    bit<8>  reserved;
    bit<32> weight;               // Nonzero
};

/* Nested type 1, value length 6. S is sent as zero and ignored on receipt.
 * TC=0 and TTL=255 let the receiver choose their values. These are control
 * plane recommendations, not a data-plane label already in a packet stack.
 */
header bgp_sr_segment_a_t {
    bit<8>  flags;                // V=0x80, B is ignored for Type A
    bit<8>  reserved;
    bit<20> label;
    bit<3>  tc;
    bit<1>  s;
    bit<8>  ttl;
};

/* Nested type 13, value length 18 or 26. B=0x10 selects the
 * bgp_sr_sid_structure_t suffix. The old draft type 2 is deprecated.
 */
header bgp_sr_segment_b_t {
    bit<8>   flags;               // V=0x80, B=0x10
    bit<8>   reserved;
    bit<128> sid;
};

header bgp_sr_sid_structure_t {    // Optional eight-byte SRv6 suffix
    bit<16> endpoint_behavior;    // 0xffff leaves the behavior to the headend
    bit<16> reserved;
    bit<8>  locator_block_length;
    bit<8>  locator_node_length;
    bit<8>  function_length;
    bit<8>  argument_length;      // The four bit-length fields sum to <= 128
};

header bgp_sr_enlp_t {             // Type 14, value length 3
    bit<8> flags;
    bit<8> reserved;
    bit<8> enlp;                  // Values 1-4, other values are ignored
};

header bgp_sr_priority_t {         // Type 15, value length 2
    bit<8> priority;
    bit<8> reserved;
};

/* Types 129/130: one reserved value octet, then a name without a NUL
 * terminator. Names are recommended to fit in 255 bytes. The wire length
 * field is 16 bits, so this is not a fixed 255-byte storage limit.
 */
header bgp_sr_name_t {
    bit<8> reserved;
    varbit<524272> name;
};

/* Color Extended Community (8 bytes), on service routes (RFC 9012, 9830).
 * It is distinct from Color in an SR Policy NLRI. Color-only types 0/1/2
 * select endpoint matching modes. Received type 3 is treated as type 0.
 */
header bgp_sr_color_community_t {
    bit<8>  type;                 // 0x03, transitive opaque
    bit<8>  subtype;              // 0x0b
    bit<2>  color_only_type;
    bit<14> unassigned;
    bit<32> color;
};

struct bgp_sr_nlri_metadata_t {
    bit<16>  afi;
    bit<32>  distinguisher;
    bit<32>  color;
    bit<128> endpoint;            // IPv4 is zero-extended, distinguish by AFI
};

struct bgp_sr_tlv_metadata_t {
    bit<16> count;
};

/**
 * P4 Parser Logic for One SR Policy NLRI
 * The cursor points to the length octet. Pass the AFI/SAFI from a validated
 * MP_REACH_NLRI or MP_UNREACH_NLRI and the byte count of one framed NLRI.
 * Strip any negotiated ADD-PATH identifier before invoking this parser.
 * The headers struct contains bgp_sr_ipv4_nlri_t sr_nlri_ipv4 and
 * bgp_sr_ipv6_nlri_t sr_nlri_ipv6. Metadata contains
 * bgp_sr_nlri_metadata_t sr_nlri.
 *
 * This parser checks the AFI/SAFI and length encoding. The caller handles
 * BGP/TCP framing, multiple NLRIs, next hops, path attributes, peer context,
 * checksums and parser errors. The application and SR Policy Module (SRPM)
 * validate the policy fields and eligibility for use at the headend.
 */
/*
parser bgp_sr_nlri_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                         in bit<16> afi, in bit<8> safi,
                         in bit<16> nlri_length) {
    state start {
        hdr.sr_nlri_ipv4.setInvalid();
        hdr.sr_nlri_ipv6.setInvalid();
        meta.sr_nlri.afi = afi;
        meta.sr_nlri.distinguisher = 0;
        meta.sr_nlri.color = 0;
        meta.sr_nlri.endpoint = 0;
        verify(safi == BGP_SR_SAFI, error.NoMatch);
        verify(afi == BGP_SR_AFI_IPV4 || afi == BGP_SR_AFI_IPV6, error.NoMatch);
        transition select(afi) {
            BGP_SR_AFI_IPV4: parse_ipv4;
            BGP_SR_AFI_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        verify(nlri_length == 13, error.NoMatch);
        pkt.extract(hdr.sr_nlri_ipv4);
        verify(hdr.sr_nlri_ipv4.length == BGP_SR_NLRI_IPV4_BITS, error.NoMatch);
        meta.sr_nlri.distinguisher = hdr.sr_nlri_ipv4.distinguisher;
        meta.sr_nlri.color = hdr.sr_nlri_ipv4.color;
        meta.sr_nlri.endpoint = (bit<128>) hdr.sr_nlri_ipv4.endpoint;
        transition accept;
    }

    state parse_ipv6 {
        verify(nlri_length == 25, error.NoMatch);
        pkt.extract(hdr.sr_nlri_ipv6);
        verify(hdr.sr_nlri_ipv6.length == BGP_SR_NLRI_IPV6_BITS, error.NoMatch);
        meta.sr_nlri.distinguisher = hdr.sr_nlri_ipv6.distinguisher;
        meta.sr_nlri.color = hdr.sr_nlri_ipv6.color;
        meta.sr_nlri.endpoint = hdr.sr_nlri_ipv6.endpoint;
        transition accept;
    }
}
*/

/**
 * P4 Parser Logic for an SR Policy Tunnel Encapsulation Attribute Value
 * The cursor points to the Tunnel TLV, not a BGP path attribute prefix.
 * attribute_length counts only the value of attribute 23. The caller checks
 * its BGP flags and length, AFI/SAFI applicability and message bounds.
 * The headers struct contains bgp_sr_tunnel_t sr_tunnel and
 * bgp_sr_sub_tlv_t[16] sr_sub_tlvs. Metadata contains
 * bgp_sr_tlv_metadata_t sr_tlvs. The stack must be empty on entry.
 *
 * Sixteen sub-TLVs is an example storage limit, not a protocol limit.
 * This parser checks the single Tunnel TLV and generic sub-TLV boundaries.
 * Values remain opaque, including Segment List contents. Unknown and
 * inapplicable sub-TLVs are retained for application-level handling.
 * Duplicates of single-instance sub-TLVs use the first instance. The SRPM
 * validates segments, weights, BSIDs and candidate paths. The BGP application
 * performs required TLV validation and RFC 9830/RFC 7606 error handling.
 * Emit the tunnel prefix and ordered stack to preserve the attribute bytes.
 */
/*
parser bgp_sr_tunnel_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                           in bit<16> attribute_length) {
    bit<16> remaining;
    bit<8> sub_type;
    bit<16> short_prefix;
    bit<24> long_prefix;
    bit<16> value_bytes;
    bit<16> record_bytes;
    bit<32> body_bits;

    state start {
        hdr.sr_tunnel.setInvalid();
        meta.sr_tlvs.count = 0;
        verify(attribute_length >= 4, error.HeaderTooShort);
        pkt.extract(hdr.sr_tunnel);
        verify(hdr.sr_tunnel.tunnel_type == BGP_SR_TUNNEL_TYPE, error.NoMatch);
        verify(hdr.sr_tunnel.length == attribute_length - 4, error.NoMatch);
        remaining = hdr.sr_tunnel.length;
        transition check_sub_tlvs;
    }

    state check_sub_tlvs {
        transition select(remaining) {
            0: accept;
            default: identify_sub_tlv;
        }
    }

    state identify_sub_tlv {
        verify(meta.sr_tlvs.count < 16, error.StackOutOfBounds);
        verify(remaining >= 2, error.HeaderTooShort);
        sub_type = pkt.lookahead<bit<8>>();
        transition select(sub_type) {
            0..127: parse_short_sub_tlv;
            default: parse_long_sub_tlv;
        }
    }

    state parse_short_sub_tlv {
        short_prefix = pkt.lookahead<bit<16>>();
        value_bytes = (bit<16>) short_prefix[7:0];
        verify(value_bytes <= remaining - 2, error.HeaderTooShort);
        record_bytes = value_bytes + 2;
        body_bits = ((bit<32>) value_bytes + 1) * 8;
        transition extract_sub_tlv;
    }

    state parse_long_sub_tlv {
        verify(remaining >= 3, error.HeaderTooShort);
        long_prefix = pkt.lookahead<bit<24>>();
        value_bytes = long_prefix[15:0];
        verify(value_bytes <= remaining - 3, error.HeaderTooShort);
        record_bytes = value_bytes + 3;
        body_bits = ((bit<32>) value_bytes + 2) * 8;
        transition extract_sub_tlv;
    }

    state extract_sub_tlv {
        pkt.extract(hdr.sr_sub_tlvs.next, body_bits);
        meta.sr_tlvs.count = meta.sr_tlvs.count + 1;
        remaining = remaining - record_bytes;
        transition check_sub_tlvs;
    }
}
*/

/**
 * P4 Match-Action Pipeline for Parsed SR Policy NLRIs (v1model)
 * Select an application handler by AFI and Color and keep the packet intact.
 * The enclosing application retains advertisement/withdrawal and connection
 * context, associates NLRIs with attributes and delivers CPs to the SRPM.
 * Candidate path selection, data-plane installation and PCEP coordination
 * require control-plane state and are performed outside this table.
 */
/*
control bgp_sr_nlri_control(inout headers hdr, inout metadata meta,
                           inout standard_metadata_t standard_metadata) {
    action send_sr_policy(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action drop_sr_policy() {
        mark_to_drop(standard_metadata);
    }

    table sr_policy_handlers {
        key = {
            meta.sr_nlri.afi: exact;
            meta.sr_nlri.color: exact;
        }
        actions = {
            send_sr_policy;
            drop_sr_policy;
        }
        default_action = drop_sr_policy();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || (!hdr.sr_nlri_ipv4.isValid() && !hdr.sr_nlri_ipv6.isValid())) {
            drop_sr_policy();
        } else {
            sr_policy_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_BGP_SR_P4
