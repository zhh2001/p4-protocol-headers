/**
 * LLDP headers (IEEE 802.1AB-2016)
 * 标准 TLV、管理地址分段布局和有界 LLDPDU 解析示例
 */
#ifndef P4_PROTOCOL_HEADERS_LLDP_P4
#define P4_PROTOCOL_HEADERS_LLDP_P4

#include "ethernet.p4"

const bit<16> LLDP_ETHER_TYPE = 16w0x88cc;
const bit<48> LLDP_NEAREST_BRIDGE = 48w0x0180c200000e;
const bit<48> LLDP_NEAREST_NON_TPMR_BRIDGE = 48w0x0180c2000003;
const bit<48> LLDP_NEAREST_CUSTOMER_BRIDGE = 48w0x0180c2000000;

// Type occupies seven bits. Values 9 through 126 remain generic wire types.
enum bit<7> lldp_tlv_type {
    END_OF_LLDPDU = 0,
    CHASSIS_ID = 1,
    PORT_ID = 2,
    TIME_TO_LIVE = 3,
    PORT_DESCRIPTION = 4,
    SYSTEM_NAME = 5,
    SYSTEM_DESCRIPTION = 6,
    SYSTEM_CAPABILITIES = 7,
    MANAGEMENT_ADDRESS = 8,
    ORGANIZATION_SPECIFIC = 127
}

enum bit<8> lldp_chassis_subtype {
    CHASSIS_RESERVED = 0,
    CHASSIS_COMPONENT = 1,
    CHASSIS_IFALIAS = 2,
    CHASSIS_PORT = 3,
    CHASSIS_MAC = 4,
    CHASSIS_NETADDR = 5,
    CHASSIS_IFNAME = 6,
    CHASSIS_LOCAL = 7
}

enum bit<8> lldp_port_subtype {
    PORT_RESERVED = 0,
    PORT_IFALIAS = 1,
    PORT_COMPONENT = 2,
    PORT_MAC = 3,
    PORT_NETADDR = 4,
    PORT_IFNAME = 5,
    PORT_CIRCUIT = 6,
    PORT_LOCAL = 7
}

enum bit<8> lldp_interface_subtype {
    INTERFACE_UNKNOWN = 1,
    INTERFACE_IFINDEX = 2,
    INTERFACE_SYSTEM_PORT = 3
}

// All multioctet fields use network byte order. Length is the information
// string size in octets, excluding this two-octet prefix. TLVs have no
// alignment padding between them. A generic value can occupy 0..511 octets.
header lldp_tlv_prefix {
    bit<7> type;
    bit<9> length;
}

header lldp_tlv {
    bit<7> type;
    bit<9> length;
    varbit<4088> value;
}

// Complete End TLV. Type and length are both zero. It is optional in the
// 2016 LLDPDU format. When present, bytes after it are not further TLVs.
header lldp_end {
    bit<7> type;
    bit<9> length;
}

// Common prefix for looking ahead at either identifier TLV.
header lldp_id_prefix {
    bit<7> type;
    bit<9> length;
    bit<8> subtype;
}

// Complete identifier TLVs. length includes the subtype, so it is 2..256.
// Extract (length - 1) * 8 variable bits for the 1..255-octet identifier.
// MAC subtypes have a six-octet identifier. Network address subtypes begin
// with one IANA AddressFamilyNumbers octet followed by the address itself.
header lldp_chassis_id {
    bit<7> type; // 1
    bit<9> length;
    bit<8> subtype;
    varbit<2040> value;
}

header lldp_port_id {
    bit<7> type; // 2
    bit<9> length;
    bit<8> subtype;
    varbit<2040> value;
}

// Complete four-octet TLV. TTL is unsigned seconds, including zero for
// withdrawal. Maintaining neighbor lifetime and shutdown state belongs
// to the LLDP application.
header lldp_ttl {
    bit<7> type; // 3
    bit<9> length; // 2
    bit<16> ttl;
}

// Complete Port Description, System Name or System Description TLV.
// These information strings have 0..255 octets. Use length * 8 variable bits.
header lldp_text_tlv {
    bit<7> type; // 4, 5 or 6
    bit<9> length;
    varbit<2040> value;
}

// Complete six-octet TLV. Bit 0 is Other, followed by Repeater, Bridge,
// WLAN AP, Router, Telephone, DOCSIS cable device, Station Only, C-VLAN,
// S-VLAN and Two-port MAC Relay at bits 1..10. Bits 11..15 are reserved.
// The application validates the enabled bitmap against capabilities.
header lldp_sys_cap {
    bit<7> type; // 7
    bit<9> length; // 4
    bit<16> capabilities;
    bit<16> enabled;
}

// First segment of a Management Address TLV. A P4 header permits only one
// varbit, at its end, so the interface and OID use the following header.
// addr_len counts addr_subtype + addr, not the addr_len field itself.
// It is 2..32 for a 1..31-octet address. Extract (addr_len - 1) * 8 bits.
// addr_subtype is an IANA address family, with 1 for IPv4 and 2 for IPv6.
// length counts the entire information string, including the next segment.
header lldp_mgmt_addr {
    bit<7> type; // 8
    bit<9> length;
    bit<8> addr_len;
    bit<8> addr_subtype;
    varbit<248> addr;
}

// Immediately follows lldp_mgmt_addr on the wire. oid_len is 0..128 and
// specifies oid_len * 8 variable bits. The information string is 9..167
// octets, with length == addr_len + 7 + oid_len. Check this equality and
// both inner lengths against the containing TLV before extracting.
// OID encodings and address/interface semantics belong to the application.
header lldp_mgmt_interface {
    bit<8> if_subtype;
    bit<32> if_number;
    bit<8> oid_len;
    varbit<1024> oid;
}

// Complete organizational TLV. length is 4..511 and includes the three
// OUI octets and one subtype octet. Extract (length - 4) * 8 variable bits.
// Interpret the remaining data using that organization's subtype definition.
header lldp_org_tlv {
    bit<7> type; // 127
    bit<9> length;
    bit<24> oui;
    bit<8> subtype;
    varbit<4056> value;
}

// Full fourteen-octet Ethernet II header. A caller parses any VLAN tags
// separately and dispatches using the innermost EtherType. Destination
// scope and source MAC validation depend on the receiving LLDP agent.
typedef ethernet_header lldp_transport;

struct lldp_metadata_t {
    bit<16> optional_count; // Complete stored TLVs after the first three
    bit<32> parsed_bytes;
    bit<32> unparsed_bytes; // Padding, truncated optional tail or stack remainder
    bit<1> end_seen;
    bit<1> optional_truncated;
    bit<1> limit_reached;
}

/**
 * Bounded LLDPDU parser
 * The cursor starts at the first TLV, after a validated Ethernet/VLAN
 * envelope. link_type must be 0x88cc. payload_length is the physically
 * bounded link payload, excluding FCS and including any link padding.
 * Apply once with a fresh, invalid optional stack.
 *
 * headers contains lldp_chassis_id lldp_chassis, lldp_port_id lldp_port,
 * lldp_ttl lldp_ttl and lldp_tlv[32] lldp_optional. metadata contains
 * lldp_metadata_t lldp. Emit these headers in this order. No TLV is
 * extracted twice. Unparsed bytes stay unchanged after the emitted headers.
 *
 * The first three TLVs must be Chassis ID, Port ID and TTL in that order.
 * Identifier lengths/subtypes and the TTL length are checked. Address
 * family, text encoding and other identifier semantics belong above P4.
 * Optional values, including management and organizational data, stay raw.
 * The application validates optional TLVs and discards individual invalid
 * values rather than discarding otherwise usable mandatory information.
 *
 * A complete End TLV stops parsing and preserves any padding. An exact
 * payload boundary also accepts a message without End. With no End marker,
 * link padding and another TLV cannot always be distinguished. The caller
 * and application supply framing knowledge for that case. An incomplete
 * optional header/value is left unparsed and sets optional_truncated.
 * A nonzero End length is also left for the application with that flag.
 *
 * The 32-entry optional stack is an example storage limit, not a protocol
 * limit. If further bytes remain, limit_reached is set and the application
 * receives the untouched remainder. parsed_bytes excludes that remainder.
 * This is a parsing and delivery example, not a full LLDP receiver. Neighbor
 * database updates, TLV duplicate rules, scope selection, TTL expiry and
 * advertisement generation require LLDP state outside this pipeline.
 */
/*
parser lldp_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                   in bit<16> link_type, in bit<32> payload_length) {
    lldp_id_prefix id;
    lldp_tlv_prefix tlv;
    bit<32> remaining;
    bit<32> value_bytes;

    state start {
        hdr.lldp_chassis.setInvalid();
        hdr.lldp_port.setInvalid();
        hdr.lldp_ttl.setInvalid();
        remaining = payload_length;
        meta.lldp.optional_count = 0;
        meta.lldp.parsed_bytes = 0;
        meta.lldp.unparsed_bytes = payload_length;
        meta.lldp.end_seen = 0;
        meta.lldp.optional_truncated = 0;
        meta.lldp.limit_reached = 0;
        verify(link_type == LLDP_ETHER_TYPE, error.NoMatch);
        transition parse_chassis;
    }

    state parse_chassis {
        verify(remaining >= 3, error.HeaderTooShort);
        id = pkt.lookahead<lldp_id_prefix>();
        verify(id.type == 1 && id.length >= 2 && id.length <= 256,
               error.NoMatch);
        verify(id.subtype >= 1 && id.subtype <= 7, error.NoMatch);
        verify(id.subtype != 4 || id.length == 7, error.NoMatch);
        verify(id.subtype != 5 || id.length >= 3, error.NoMatch);
        value_bytes = (bit<32>)id.length - 1;
        verify((bit<32>)id.length <= remaining - 2, error.HeaderTooShort);
        pkt.extract(hdr.lldp_chassis, value_bytes * 8);
        remaining = remaining - 2 - (bit<32>)id.length;
        meta.lldp.parsed_bytes = payload_length - remaining;
        meta.lldp.unparsed_bytes = remaining;
        transition parse_port;
    }

    state parse_port {
        verify(remaining >= 3, error.HeaderTooShort);
        id = pkt.lookahead<lldp_id_prefix>();
        verify(id.type == 2 && id.length >= 2 && id.length <= 256,
               error.NoMatch);
        verify(id.subtype >= 1 && id.subtype <= 7, error.NoMatch);
        verify(id.subtype != 3 || id.length == 7, error.NoMatch);
        verify(id.subtype != 4 || id.length >= 3, error.NoMatch);
        value_bytes = (bit<32>)id.length - 1;
        verify((bit<32>)id.length <= remaining - 2, error.HeaderTooShort);
        pkt.extract(hdr.lldp_port, value_bytes * 8);
        remaining = remaining - 2 - (bit<32>)id.length;
        meta.lldp.parsed_bytes = payload_length - remaining;
        meta.lldp.unparsed_bytes = remaining;
        transition parse_ttl;
    }

    state parse_ttl {
        verify(remaining >= 4, error.HeaderTooShort);
        tlv = pkt.lookahead<lldp_tlv_prefix>();
        verify(tlv.type == 3 && tlv.length == 2, error.NoMatch);
        pkt.extract(hdr.lldp_ttl);
        remaining = remaining - 4;
        meta.lldp.parsed_bytes = payload_length - remaining;
        meta.lldp.unparsed_bytes = remaining;
        transition parse_optional;
    }

    state parse_optional {
        transition select(remaining, meta.lldp.optional_count) {
            (0, _): accept;
            (_, 32): optional_limit;
            (1, _): optional_incomplete;
            default: inspect_optional;
        }
    }

    state inspect_optional {
        tlv = pkt.lookahead<lldp_tlv_prefix>();
        value_bytes = (bit<32>)tlv.length;
        transition select(tlv.type, (bit<32>)tlv.length <= remaining - 2) {
            (0, _): inspect_end;
            (_, false): optional_incomplete;
            default: extract_optional;
        }
    }

    state inspect_end {
        transition select(tlv.length) {
            0: extract_end;
            default: optional_incomplete;
        }
    }

    state extract_optional {
        pkt.extract(hdr.lldp_optional.next, value_bytes * 8);
        meta.lldp.optional_count = meta.lldp.optional_count + 1;
        remaining = remaining - 2 - value_bytes;
        meta.lldp.parsed_bytes = payload_length - remaining;
        meta.lldp.unparsed_bytes = remaining;
        transition parse_optional;
    }

    state extract_end {
        pkt.extract(hdr.lldp_optional.next, 0);
        meta.lldp.optional_count = meta.lldp.optional_count + 1;
        remaining = remaining - 2;
        meta.lldp.parsed_bytes = payload_length - remaining;
        meta.lldp.unparsed_bytes = remaining;
        meta.lldp.end_seen = 1;
        transition accept;
    }

    state optional_incomplete {
        meta.lldp.optional_truncated = 1;
        transition accept;
    }

    state optional_limit {
        meta.lldp.limit_reached = 1;
        transition accept;
    }
}
*/

/**
 * Application delivery (v1model)
 * handler_port is the default local LLDP application destination. Scope
 * policy belongs to the outer Ethernet handler. Malformed mandatory TLVs
 * drop the packet. Parsed frames and any unparsed optional tail go to the
 * application unchanged. This table does not perform bridge forwarding.
 */
/*
control lldp_control(inout headers hdr, inout metadata meta,
                     inout standard_metadata_t standard_metadata,
                     in bit<9> handler_port) {
    action send_lldp(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action send_default() {
        standard_metadata.egress_spec = handler_port;
    }

    table lldp_handlers {
        key = {
            hdr.lldp_chassis.subtype: exact;
            hdr.lldp_port.subtype: exact;
            hdr.lldp_ttl.ttl: exact;
        }
        actions = {
            send_lldp;
            send_default;
        }
        default_action = send_default();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.lldp_chassis.isValid() || !hdr.lldp_port.isValid()
            || !hdr.lldp_ttl.isValid()) {
            mark_to_drop(standard_metadata);
        } else {
            lldp_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_LLDP_P4
