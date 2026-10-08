/**
 * BGP Link-State headers (RFC 9552)
 * BGP-LS carries topology NLRIs in MP_REACH_NLRI or MP_UNREACH_NLRI.
 * Attribute 29 carries a separate sequence of node, link or prefix TLVs.
 * Use bgp.p4 for the surrounding BGP path attribute and message headers.
 */
#ifndef P4_PROTOCOL_HEADERS_BGP_LS_P4
#define P4_PROTOCOL_HEADERS_BGP_LS_P4

typedef bit<8> bgp_ls_protocol_id_t;
typedef bit<16> bgp_ls_tlv_type_t;

const bit<16> BGP_LS_AFI = 16w16388;
const bit<8> BGP_LS_SAFI = 8w71;
const bit<8> BGP_LS_VPN_SAFI = 8w72;
const bit<8> BGP_LS_ATTRIBUTE = 8w29; // Optional, non-transitive

const bit<16> BGP_LS_NODE_NLRI = 16w1;
const bit<16> BGP_LS_LINK_NLRI = 16w2;
const bit<16> BGP_LS_IPV4_PREFIX_NLRI = 16w3;
const bit<16> BGP_LS_IPV6_PREFIX_NLRI = 16w4;

// Base protocol identifiers from RFC 9552. Other registered and private
// identifiers remain available to extensions and application handlers.
const bgp_ls_protocol_id_t BGP_LS_PROTO_ISIS_L1 = 8w1;
const bgp_ls_protocol_id_t BGP_LS_PROTO_ISIS_L2 = 8w2;
const bgp_ls_protocol_id_t BGP_LS_PROTO_OSPFV2 = 8w3;
const bgp_ls_protocol_id_t BGP_LS_PROTO_DIRECT = 8w4;
const bgp_ls_protocol_id_t BGP_LS_PROTO_STATIC = 8w5;
const bgp_ls_protocol_id_t BGP_LS_PROTO_OSPFV3 = 8w6;

// Length counts the value after this four-octet prefix, including the RD
// for SAFI 72. It excludes the type and length fields.
header bgp_ls_nlri_t {
    bit<16> type;
    bit<16> length;
}

// Present only for BGP-LS-VPN (SAFI 72), before the NLRI-specific body.
// The route distinguisher uses the formats defined in RFC 4364.
header bgp_ls_vpn_rd_t {
    bit<64> route_distinguisher;
}

// Common nine-octet prefix of Node, Link and IPv4/IPv6 Prefix NLRIs.
// Identifier distinguishes IGP domains and instances. New NLRI types may
// have different bodies and must not be assumed to use this prefix.
header bgp_ls_base_t {
    bgp_ls_protocol_id_t protocol_id;
    bit<64> identifier;
}

// All descriptor and attribute TLVs use 16-bit type and value length.
// There is no alignment padding. The value may contain nested TLVs.
// This header retains the entire TLV, including unknown types.
header bgp_ls_tlv_t {
    bgp_ls_tlv_type_t type;
    bit<16> length;
    varbit<524280> value; // At most 65535 value octets
}

// Alternative prefix for callers that extract a typed value separately.
// Emit either a complete generic TLV or this prefix followed by its value.
header bgp_ls_tlv_prefix_t {
    bgp_ls_tlv_type_t type;
    bit<16> length;
}

header bgp_ls_opaque_nlri_t {
    varbit<524280> value;
}

const bgp_ls_tlv_type_t BGP_LS_LOCAL_NODE_DESCRIPTORS = 16w256;
const bgp_ls_tlv_type_t BGP_LS_REMOTE_NODE_DESCRIPTORS = 16w257;
const bgp_ls_tlv_type_t BGP_LS_LINK_IDENTIFIERS = 16w258;
const bgp_ls_tlv_type_t BGP_LS_IPV4_INTERFACE_ADDRESS = 16w259;
const bgp_ls_tlv_type_t BGP_LS_IPV4_NEIGHBOR_ADDRESS = 16w260;
const bgp_ls_tlv_type_t BGP_LS_IPV6_INTERFACE_ADDRESS = 16w261;
const bgp_ls_tlv_type_t BGP_LS_IPV6_NEIGHBOR_ADDRESS = 16w262;
const bgp_ls_tlv_type_t BGP_LS_MULTI_TOPOLOGY_ID = 16w263;
const bgp_ls_tlv_type_t BGP_LS_OSPF_ROUTE_TYPE = 16w264;
const bgp_ls_tlv_type_t BGP_LS_IP_REACHABILITY = 16w265;

// Sub-TLVs within Local/Remote Node Descriptors.
const bgp_ls_tlv_type_t BGP_LS_AUTONOMOUS_SYSTEM = 16w512;
const bgp_ls_tlv_type_t BGP_LS_IDENTIFIER = 16w513; // Deprecated, not a Router-ID
const bgp_ls_tlv_type_t BGP_LS_OSPF_AREA_ID = 16w514;
const bgp_ls_tlv_type_t BGP_LS_IGP_ROUTER_ID = 16w515;

const bgp_ls_tlv_type_t BGP_LS_NODE_FLAGS = 16w1024;
const bgp_ls_tlv_type_t BGP_LS_OPAQUE_NODE_ATTRIBUTE = 16w1025;
const bgp_ls_tlv_type_t BGP_LS_NODE_NAME = 16w1026;
const bgp_ls_tlv_type_t BGP_LS_ISIS_AREA_ID = 16w1027;
const bgp_ls_tlv_type_t BGP_LS_LOCAL_IPV4_ROUTER_ID = 16w1028;
const bgp_ls_tlv_type_t BGP_LS_LOCAL_IPV6_ROUTER_ID = 16w1029;
const bgp_ls_tlv_type_t BGP_LS_REMOTE_IPV4_ROUTER_ID = 16w1030;
const bgp_ls_tlv_type_t BGP_LS_REMOTE_IPV6_ROUTER_ID = 16w1031;
const bgp_ls_tlv_type_t BGP_LS_ADMINISTRATIVE_GROUP = 16w1088;
const bgp_ls_tlv_type_t BGP_LS_MAXIMUM_LINK_BANDWIDTH = 16w1089;
const bgp_ls_tlv_type_t BGP_LS_MAXIMUM_RESERVABLE_BANDWIDTH = 16w1090;
const bgp_ls_tlv_type_t BGP_LS_UNRESERVED_BANDWIDTH = 16w1091;
const bgp_ls_tlv_type_t BGP_LS_TE_DEFAULT_METRIC = 16w1092;
const bgp_ls_tlv_type_t BGP_LS_LINK_PROTECTION_TYPE = 16w1093;
const bgp_ls_tlv_type_t BGP_LS_MPLS_PROTOCOL_MASK = 16w1094;
const bgp_ls_tlv_type_t BGP_LS_IGP_METRIC = 16w1095;
const bgp_ls_tlv_type_t BGP_LS_SHARED_RISK_LINK_GROUP = 16w1096;
const bgp_ls_tlv_type_t BGP_LS_OPAQUE_LINK_ATTRIBUTE = 16w1097;
const bgp_ls_tlv_type_t BGP_LS_LINK_NAME = 16w1098;
const bgp_ls_tlv_type_t BGP_LS_IGP_FLAGS = 16w1152;
const bgp_ls_tlv_type_t BGP_LS_IGP_ROUTE_TAG = 16w1153;
const bgp_ls_tlv_type_t BGP_LS_IGP_EXTENDED_ROUTE_TAG = 16w1154;
const bgp_ls_tlv_type_t BGP_LS_PREFIX_METRIC = 16w1155;
const bgp_ls_tlv_type_t BGP_LS_OSPF_FORWARDING_ADDRESS = 16w1156;
const bgp_ls_tlv_type_t BGP_LS_OPAQUE_PREFIX_ATTRIBUTE = 16w1157;

// The following headers describe values only, without a TLV prefix.
// The enclosing TLV length and source protocol select the appropriate form.
header bgp_ls_as_value_t {
    bit<32> autonomous_system;
}

header bgp_ls_identifier_value_t {
    bit<32> identifier; // Deprecated sub-TLV 513
}

header bgp_ls_ospf_area_value_t {
    bit<32> area_id;
}

// Also used for interface, neighbor, auxiliary Router-ID and forwarding
// address values. A forwarding address may be either IPv4 or IPv6.
header bgp_ls_ipv4_address_value_t {
    bit<32> address;
}

header bgp_ls_ipv6_address_value_t {
    bit<128> address;
}

// IGP Router-ID values: IS-IS system ID (6 octets) or pseudonode (7).
// OSPF uses a 4-octet Router-ID or an 8-octet pseudonode value.
header bgp_ls_isis_router_value_t {
    bit<48> system_id;
}

header bgp_ls_isis_pseudonode_value_t {
    bit<48> system_id;
    bit<8> pseudonode_id;
}

header bgp_ls_ospf_pseudonode_value_t {
    bit<32> router_id;
    bit<32> interface_id; // IPv4 interface address for OSPFv2, ID for OSPFv3
}

header bgp_ls_link_identifiers_value_t {
    bit<32> local_id;
    bit<32> remote_id;
}

// Repeat for each two-octet entry. Link/Prefix Descriptors carry one MT-ID.
// Node attributes may carry an array. Reserved-bit meaning depends on usage.
header bgp_ls_multi_topology_value_t {
    bit<4> reserved;
    bit<12> topology_id;
}

header bgp_ls_ospf_route_type_value_t {
    bit<8> route_type; // 1 Intra, 2 Inter, 3/4 External, 5/6 NSSA
}

// TLV 265: value length is 1 + ceil(prefix_length / 8).
// IPv4 prefixes have 0..32 bits, IPv6 prefixes have 0..128 bits.
// Prefix bytes have no address-sized padding. Unused trailing bits are zero.
header bgp_ls_reachability_value_t {
    bit<8> prefix_length;
    varbit<128> prefix;
}

// RFC 9552 Figure 15 with verified erratum 7789 (Attached, not T).
header bgp_ls_node_flags_value_t {
    bit<1> overload;
    bit<1> attached;
    bit<1> external;
    bit<1> abr;
    bit<1> router;
    bit<1> v6;
    bit<2> reserved;
}

// Node Name (1026) and Link Name (1098) are at most 255 octets of 7-bit ASCII.
header bgp_ls_name_value_t {
    varbit<2040> name;
}

header bgp_ls_admin_group_value_t {
    bit<32> administrative_group;
}

// TLVs 1089/1090 use one IEEE 754 binary32 value, in bytes per second.
// TLV 1091 uses eight such values in priority order 0..7.
header bgp_ls_bandwidth_value_t {
    bit<32> bandwidth;
}

header bgp_ls_unreserved_bandwidth_value_t {
    bit<32> priority_0;
    bit<32> priority_1;
    bit<32> priority_2;
    bit<32> priority_3;
    bit<32> priority_4;
    bit<32> priority_5;
    bit<32> priority_6;
    bit<32> priority_7;
}

header bgp_ls_te_metric_value_t {
    bit<32> metric;
}

header bgp_ls_link_protection_value_t {
    bit<16> protection_type;
}

header bgp_ls_mpls_protocol_value_t {
    bit<1> ldp;
    bit<1> rsvp_te;
    bit<6> reserved;
}

// TLV 1095 has 1 octet for IS-IS small metrics, 2 for OSPF, 3 for IS-IS wide.
header bgp_ls_igp_metric_value_t {
    varbit<24> metric;
}

// Repeat these entries for SRLG (1096), route tags (1153/1154).
header bgp_ls_srlg_value_t {
    bit<32> group;
}

header bgp_ls_route_tag_value_t {
    bit<32> tag;
}

header bgp_ls_extended_route_tag_value_t {
    bit<64> tag;
}

header bgp_ls_igp_flags_value_t {
    bit<1> down;
    bit<1> no_unicast;
    bit<1> local_address;
    bit<1> propagate_nssa;
    bit<4> reserved;
}

header bgp_ls_prefix_metric_value_t {
    bit<32> metric;
}

struct bgp_ls_tlv_metadata_t {
    bit<8> count;
}

struct bgp_ls_nlri_metadata_t {
    bit<1> known_type;
    bit<1> vpn;
    bgp_ls_protocol_id_t protocol_id;
    bit<64> identifier;
    bit<64> route_distinguisher;
}

/**
 * P4 Parser Logic for a Bounded BGP-LS TLV Area
 * The cursor points to the first TLV in an already bounded area.
 * area_length counts only that area, such as attribute 29's value or the
 * descriptors after a base NLRI prefix. The caller checks message bounds.
 * The stack must be empty on entry. Sixteen TLVs is an example storage limit,
 * not a protocol limit. Unknown types and nested values remain intact.
 * Emit the ordered stack to retain the original TLV bytes without padding.
 *
 * This parser checks framing only. The BGP application validates mandatory
 * descriptors, nested TLVs, source-protocol formats and canonical NLRI order.
 * Attribute TLV ordering is not mandatory. The application preserves unknown
 * information and applies the error handling in RFC 9552 and RFC 7606.
 */
/*
parser bgp_ls_tlv_parser(packet_in pkt, inout bgp_ls_tlv_t[16] tlvs,
                         inout bgp_ls_tlv_metadata_t tlv_meta,
                         in bit<16> area_length) {
    bit<16> remaining;
    bit<32> prefix;
    bit<16> value_bytes;
    bit<32> value_bits;

    state start {
        tlv_meta.count = 0;
        remaining = area_length;
        transition check_tlvs;
    }

    state check_tlvs {
        transition select(remaining) {
            0: accept;
            default: parse_tlv;
        }
    }

    state parse_tlv {
        verify(tlv_meta.count < 16, error.StackOutOfBounds);
        verify(remaining >= 4, error.HeaderTooShort);
        prefix = pkt.lookahead<bit<32>>();
        value_bytes = prefix[15:0];
        verify(value_bytes <= remaining - 4, error.HeaderTooShort);
        value_bits = (bit<32>) value_bytes * 8;
        pkt.extract(tlvs.next, value_bits);
        tlv_meta.count = tlv_meta.count + 1;
        remaining = remaining - 4 - value_bytes;
        transition check_tlvs;
    }
}
*/

/**
 * P4 Parser Logic for One BGP-LS NLRI
 * The cursor points to a single NLRI prefix. The caller supplies AFI/SAFI
 * and its framed length, checks negotiated capabilities and message bounds,
 * and retains advertisement/withdrawal and connection context.
 * The headers struct contains bgp_ls_nlri_t ls_nlri, bgp_ls_vpn_rd_t ls_rd,
 * bgp_ls_base_t ls_base, bgp_ls_opaque_nlri_t ls_opaque and
 * bgp_ls_tlv_t[16] ls_descriptors. The descriptor stack is empty on entry.
 * Metadata contains bgp_ls_nlri_metadata_t ls_nlri and
 * bgp_ls_tlv_metadata_t ls_descriptors.
 *
 * Only types 1..4 use the common nine-octet prefix. Other NLRI bodies are
 * retained as opaque bytes, including types defined by later extensions.
 * No allowlist is imposed on the source protocol or TLV types.
 * Emit NLRI prefix, optional RD, base prefix and descriptors or opaque body.
 * Topology interpretation, propagation and path computation run in the
 * enclosing BGP application. A local parser rejection is not a BGP session
 * error response. The application handles errors and storage limits.
 */
/*
parser bgp_ls_nlri_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                          in bit<16> afi, in bit<8> safi,
                          in bit<32> nlri_length) {
    bgp_ls_tlv_parser() descriptors;
    bit<16> remaining;
    bit<32> opaque_bits;

    state start {
        hdr.ls_nlri.setInvalid();
        hdr.ls_rd.setInvalid();
        hdr.ls_base.setInvalid();
        hdr.ls_opaque.setInvalid();
        meta.ls_nlri.known_type = 0;
        meta.ls_nlri.vpn = 0;
        meta.ls_nlri.protocol_id = 0;
        meta.ls_nlri.identifier = 0;
        meta.ls_nlri.route_distinguisher = 0;
        meta.ls_descriptors.count = 0;
        verify(afi == BGP_LS_AFI
               && (safi == BGP_LS_SAFI || safi == BGP_LS_VPN_SAFI),
               error.NoMatch);
        verify(nlri_length >= 4, error.HeaderTooShort);
        pkt.extract(hdr.ls_nlri);
        verify((bit<32>) hdr.ls_nlri.length == nlri_length - 4, error.NoMatch);
        remaining = hdr.ls_nlri.length;
        transition select(safi) {
            BGP_LS_VPN_SAFI: parse_rd;
            default: identify_body;
        }
    }

    state parse_rd {
        verify(remaining >= 8, error.HeaderTooShort);
        pkt.extract(hdr.ls_rd);
        meta.ls_nlri.vpn = 1;
        meta.ls_nlri.route_distinguisher = hdr.ls_rd.route_distinguisher;
        remaining = remaining - 8;
        transition identify_body;
    }

    state identify_body {
        transition select(hdr.ls_nlri.type) {
            BGP_LS_NODE_NLRI: parse_base;
            BGP_LS_LINK_NLRI: parse_base;
            BGP_LS_IPV4_PREFIX_NLRI: parse_base;
            BGP_LS_IPV6_PREFIX_NLRI: parse_base;
            default: parse_opaque;
        }
    }

    state parse_base {
        verify(remaining >= 9, error.HeaderTooShort);
        pkt.extract(hdr.ls_base);
        meta.ls_nlri.known_type = 1;
        meta.ls_nlri.protocol_id = hdr.ls_base.protocol_id;
        meta.ls_nlri.identifier = hdr.ls_base.identifier;
        remaining = remaining - 9;
        descriptors.apply(pkt, hdr.ls_descriptors, meta.ls_descriptors, remaining);
        transition accept;
    }

    state parse_opaque {
        opaque_bits = (bit<32>) remaining * 8;
        pkt.extract(hdr.ls_opaque, opaque_bits);
        transition accept;
    }
}
*/

/**
 * P4 Match-Action Pipeline for BGP-LS NLRIs (v1model)
 * Send parsed NLRIs to an application handler without editing their contents.
 * handler_port is the fallback for all types, including unknown extensions.
 * The table can choose a handler for a known type and source protocol.
 */
/*
control bgp_ls_nlri_control(inout headers hdr, inout metadata meta,
                           inout standard_metadata_t standard_metadata,
                           in bit<9> handler_port) {
    action send_bgp_ls(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action send_default() {
        standard_metadata.egress_spec = handler_port;
    }

    action drop_bgp_ls() {
        mark_to_drop(standard_metadata);
    }

    table bgp_ls_handlers {
        key = {
            hdr.ls_nlri.type: exact;
            meta.ls_nlri.protocol_id: exact;
        }
        actions = {
            send_bgp_ls;
            send_default;
        }
        default_action = send_default();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.ls_nlri.isValid()) {
            drop_bgp_ls();
        } else if (meta.ls_nlri.known_type == 0) {
            send_default();
        } else {
            bgp_ls_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_BGP_LS_P4
