#ifndef P4_PROTOCOL_HEADERS_VXLAN_GPE_P4
#define P4_PROTOCOL_HEADERS_VXLAN_GPE_P4

/**
 * VXLAN-GPE header definitions
 * 通用协议扩展报头，支持多种载荷协议
 * Wire format: draft-ietf-nvo3-vxlan-gpe-13, Sections 3 and 6.
 * This expired Internet-Draft has not been published as an RFC.
 * Next Protocol values share the IANA LISP-GPE registry (RFC 9305).
 */

typedef bit<8> vxlan_gpe_protocol_t;

const bit<16> VXLAN_GPE_UDP_PORT = 4790;
const bit<2> VXLAN_GPE_VERSION = 0;

/* Registered payload protocols. Zero is reserved when P = 1. */
const vxlan_gpe_protocol_t VXLAN_GPE_IPV4     = 0x01;
const vxlan_gpe_protocol_t VXLAN_GPE_IPV6     = 0x02;
const vxlan_gpe_protocol_t VXLAN_GPE_ETHERNET = 0x03;
const vxlan_gpe_protocol_t VXLAN_GPE_NSH      = 0x04;

/* Experimentation and testing, not assigned payload formats. */
const vxlan_gpe_protocol_t VXLAN_GPE_EXPERIMENT_1      = 0x7E;
const vxlan_gpe_protocol_t VXLAN_GPE_EXPERIMENT_2      = 0x7F;
const vxlan_gpe_protocol_t VXLAN_GPE_SHIM_EXPERIMENT_1 = 0xFE;
const vxlan_gpe_protocol_t VXLAN_GPE_SHIM_EXPERIMENT_2 = 0xFF;

/**
 * VXLAN-GPE base header (8 bytes)
 * First byte: R R Ver Ver I P B O, from most to least significant bit.
 * Reserved fields are transmitted as zero and ignored on receipt.
 * Version 0 is supported. I must be set to indicate a valid VNI.
 * P = 1 identifies the payload through the 8-bit Next Protocol field.
 * P = 0 requires Next Protocol = 0 and an Ethernet payload.
 * B marks ingress-replicated broadcast, unknown unicast or multicast traffic.
 * O marks an OAM packet that requires OAM processing.
 */
header vxlan_gpe_t {
    bit<2> reserved_flags;
    bit<2> version;
    bit<1> instance;
    bit<1> next_protocol_present;
    bit<1> bum;
    bit<1> oam;
    bit<16> reserved1;
    vxlan_gpe_protocol_t next_protocol;
    bit<24> vni;
    bit<8> reserved2;
};

/**
 * Generic shim prefix (4 bytes), for Next Protocol values 0x80-0xFF.
 * The protocol owner defines Type, Reserved and the following value.
 * Length counts 4-byte units after this prefix, up to 1020 bytes.
 * Next Protocol uses the same registry. Shims precede the final payload.
 * This prefix alone does not define an IOAM or other extension format.
 */
header vxlan_gpe_shim_t {
    bit<8> shim_type;
    bit<8> length;
    bit<8> reserved;
    vxlan_gpe_protocol_t next_protocol;
};

struct vxlan_gpe_headers_t {
    vxlan_gpe_t base;
};

struct vxlan_gpe_metadata_t {
    vxlan_gpe_protocol_t payload_protocol;
    bit<16> payload_bytes;
    bool protocol_known;
};

/**
 * Bounded parsing and local delivery example (P4_16, v1model).
 * The cursor points to a VXLAN-GPE header received on UDP port 4790.
 * Pass the validated UDP payload length as gpe_bytes. The enclosing parser
 * checks IP/UDP lengths against the received packet, handles fragmentation
 * and verifies checksums before this endpoint example is used.
 *
 * This example parses only the base header. Payloads, OAM messages and shim
 * chains remain unchanged for their protocol owners. Unknown nonzero Next
 * Protocol values require an explicitly configured handler. No payload
 * format is inferred from an unassigned or experimental protocol number.
 * Inner bounds, VLAN policy, NSH service paths, OAM state and BUM replication
 * belong to those handlers. Handler ports are local delivery destinations.
 * The enclosing pipeline handles parser errors and egress framing.
 * UDP port 4789 requires the separate VXLAN format and receive path.
 */
/*
parser vxlan_gpe_parser(packet_in pkt, out vxlan_gpe_headers_t hdr,
                        out vxlan_gpe_metadata_t meta,
                        in bit<16> gpe_bytes) {
    state start {
        meta.payload_protocol = 0;
        meta.payload_bytes = 0;
        meta.protocol_known = false;
        verify(gpe_bytes >= 8, error.HeaderTooShort);
        pkt.extract(hdr.base);
        verify(hdr.base.version == VXLAN_GPE_VERSION, error.NoMatch);
        verify(hdr.base.instance == 1, error.NoMatch);
        meta.payload_bytes = gpe_bytes - 8;
        transition select(hdr.base.next_protocol_present) {
            0: ethernet_payload;
            default: typed_payload;
        }
    }

    state ethernet_payload {
        verify(hdr.base.next_protocol == 0, error.NoMatch);
        meta.payload_protocol = VXLAN_GPE_ETHERNET;
        meta.protocol_known = true;
        transition accept;
    }

    state typed_payload {
        verify(hdr.base.next_protocol != 0, error.NoMatch);
        meta.payload_protocol = hdr.base.next_protocol;
        meta.protocol_known = hdr.base.next_protocol == VXLAN_GPE_IPV4
                              || hdr.base.next_protocol == VXLAN_GPE_IPV6
                              || hdr.base.next_protocol == VXLAN_GPE_ETHERNET
                              || hdr.base.next_protocol == VXLAN_GPE_NSH;
        transition accept;
    }
}

control vxlan_gpe_control(inout vxlan_gpe_headers_t hdr,
                         in vxlan_gpe_metadata_t meta,
                         inout standard_metadata_t standard_metadata) {
    action deliver(bit<9> handler_port) {
        standard_metadata.egress_spec = handler_port;
    }

    action drop_vxlan_gpe() {
        mark_to_drop(standard_metadata);
    }

    table payload_handlers {
        key = {
            hdr.base.vni: exact;
            meta.payload_protocol: exact;
        }
        actions = {
            deliver;
            drop_vxlan_gpe;
        }
        default_action = drop_vxlan_gpe();
    }

    table oam_handlers {
        key = {
            hdr.base.vni: exact;
            meta.payload_protocol: exact;
        }
        actions = {
            deliver;
            drop_vxlan_gpe;
        }
        default_action = drop_vxlan_gpe();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.base.isValid()) {
            drop_vxlan_gpe();
        } else if (hdr.base.oam == 1) {
            oam_handlers.apply();
        } else {
            payload_handlers.apply();
        }
    }
}
*/

/**
 * Base header construction example. The payload already has its own format.
 * Supply a registered or explicitly negotiated experimental payload protocol.
 * ethernet_compatibility selects P = 0 on port 4790, for Ethernet only.
 * A legacy peer on port 4789 also requires B = 0 and O = 0 and the separate
 * VXLAN transmit path. The enclosing pipeline creates outer IP/UDP headers,
 * sets the IPv4 DF bit, checks MTU and computes lengths and checksums.
 * The deparser emits hdr.base before the unchanged payload.
 */
/*
control vxlan_gpe_encapsulation(inout vxlan_gpe_headers_t hdr,
                               inout standard_metadata_t standard_metadata,
                               in bit<24> vni,
                               in vxlan_gpe_protocol_t payload_protocol,
                               in bool ethernet_compatibility,
                               in bit<1> bum, in bit<1> oam) {
    action build_header() {
        hdr.base.setValid();
        hdr.base.reserved_flags = 0;
        hdr.base.version = VXLAN_GPE_VERSION;
        hdr.base.instance = 1;
        hdr.base.next_protocol_present = 1;
        hdr.base.bum = bum;
        hdr.base.oam = oam;
        hdr.base.reserved1 = 0;
        hdr.base.next_protocol = payload_protocol;
        hdr.base.vni = vni;
        hdr.base.reserved2 = 0;
    }

    apply {
        if (payload_protocol == 0
            || (ethernet_compatibility
                && payload_protocol != VXLAN_GPE_ETHERNET)) {
            mark_to_drop(standard_metadata);
        } else {
            build_header();
            if (ethernet_compatibility) {
                hdr.base.next_protocol_present = 0;
                hdr.base.next_protocol = 0;
            }
        }
    }
}
*/

#endif
