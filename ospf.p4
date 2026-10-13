/**
 * OSPFv2 (RFC 2328)
 * 标准报头、LSA 固定部分和有界报文解析示例
 */
#ifndef P4_PROTOCOL_HEADERS_OSPF_P4
#define P4_PROTOCOL_HEADERS_OSPF_P4

#include "ipv4.p4"

// IPv4 includes its Version/IHL, protocol and variable options fields.
// OSPFv2 uses protocol 89. OSPFv3 has different IPv6 and OSPF layouts.
typedef ipv4_header ospf_transport;
const bit<8> OSPF_IP_PROTOCOL = 89;
const bit<8> OSPF_VERSION = 2;
const bit<32> OSPF_ALL_ROUTERS = 32w0xe0000005;
const bit<32> OSPF_ALL_DR_ROUTERS = 32w0xe0000006;

enum bit<8> ospf_packet_type {
    HELLO = 1,
    DB_DESC = 2,
    LS_REQ = 3,
    LS_UPDATE = 4,
    LS_ACK = 5
}

// Local configuration choices, not fields or codepoints on the wire.
enum bit<8> ospf_area_type {
    NORMAL = 0,
    STUB = 1,
    NSSA = 2
}

enum bit<8> ospf_interface_type {
    BROADCAST = 1,
    POINT_TO_POINT = 2,
    NBMA = 3,
    POINT_TO_MULTIPOINT = 4,
    VIRTUAL = 5
}

const bit<8> OSPF_AUTH_NULL = 0;
const bit<8> OSPF_AUTH_SIMPLE = 1;
const bit<8> OSPF_AUTH_CRYPTO = 2; // RFC 2328 and RFC 5709
const bit<8> OSPF_AUTH_EXTENDED = 3; // RFC 7474
const bit<8> OSPF_OPTION_LLS = 8w0x10;
const bit<8> OSPF_DD_MS = 8w0x01;
const bit<8> OSPF_DD_MORE = 8w0x02;
const bit<8> OSPF_DD_INIT = 8w0x04;
const bit<8> OSPF_ROUTER_BORDER = 8w0x01;
const bit<8> OSPF_ROUTER_EXTERNAL = 8w0x02;
const bit<8> OSPF_ROUTER_VIRTUAL = 8w0x04;
const bit<24> OSPF_LS_INFINITY = 24w0xffffff;

// Twenty-four-octet header with the RFC 6549 Instance ID/AuType split.
// Instance zero has the same wire layout as the RFC 2328 base header.
// length covers this header and the OSPF body. It excludes appended
// cryptographic authentication data and LLS blocks. For AuType 0/1,
// checksum is the Internet checksum over length octets, excluding the
// eight-octet Authentication field. For AuType 2/3, checksum is zero.
header ospf_header {
    bit<8> version;
    bit<8> type;
    bit<16> length;
    bit<32> router_id;
    bit<32> area_id;
    bit<16> checksum;
    bit<8> instance_id;
    bit<8> auth_type;
    bit<64> auth_data;
}

// Alternative interpretations of ospf_header.auth_data, not extra headers
// following ospf_header. For AuType 0 it is unused, for 1 a 64-bit password.
// AuType 2 supports keyed MD5 and HMAC-SHA algorithms selected by the key.
header ospf_crypto_auth {
    bit<16> reserved;
    bit<8> key_id;
    bit<8> data_length;
    bit<32> sequence_number;
}

// AuType 3 moves its sequence number to the first eight authentication
// octets after the OSPF body. data_length includes that sequence and digest.
header ospf_extended_auth {
    bit<24> reserved;
    bit<8> data_length;
    bit<32> key_id;
}

header ospf_extended_sequence {
    bit<64> sequence_number;
}

// Twenty-octet Hello fixed body, followed by four-octet neighbor Router IDs.
// DR and BDR are interface IPv4 addresses, not their OSPF Router IDs.
header ospf_hello {
    bit<32> network_mask;
    bit<16> hello_interval;
    bit<8> options;
    bit<8> priority;
    bit<32> dead_interval;
    bit<32> designated_router;
    bit<32> backup_dr;
}

header ospf_neighbor {
    bit<32> router_id;
}

// Eight-octet Database Description fixed body, followed by LSA headers.
// Each entry is only twenty octets even when its LSA length is larger.
header ospf_db_desc {
    bit<16> mtu; // Zero on virtual links
    bit<8> options;
    bit<8> flags; // Low three bits: I, M, MS. Extensions define other bits.
    bit<32> dd_seq;
}

// One twelve-octet Link State Request entry. There is no count prefix.
// This LS type field is thirty-two bits, unlike the LSA header's type.
header ospf_ls_request {
    bit<32> type;
    bit<32> id;
    bit<32> adv_router;
}

// Four-octet Update prefix, followed by num_lsas complete LSAs.
header ospf_ls_update {
    bit<32> num_lsas;
}

// Twenty-octet LSA header. length covers this header and its full body.
// Fletcher checksum excludes the two-octet age, which changes in transit.
// DD and Ack carry this header alone, Update carries the full LSA.
header ospf_lsa_header {
    bit<16> age;
    bit<8> options;
    bit<8> type;
    bit<32> id;
    bit<32> adv_router;
    bit<32> seq_num;
    bit<16> checksum;
    bit<16> length;
}

// One acknowledgment entry. Ack has no separate fixed body or count.
typedef ospf_lsa_header ospf_ls_ack;

// Opaque body following one LSA header. The sixteen-bit LSA length permits
// at most 65515 body octets. Header and body must be emitted as a pair.
header ospf_lsa_body {
    varbit<524120> value;
}

// The following LSA body definitions exclude ospf_lsa_header.
// Router-LSA (1): four-octet prefix, then num_links link descriptions.
// flags contains V/E/B in its low three bits, plus standardized extensions.
// Each link has num_tos additional four-octet TOS metric entries.
header ospf_router_lsa {
    bit<8> flags;
    bit<8> reserved;
    bit<16> num_links;
}

header ospf_router_link {
    bit<32> link_id;
    bit<32> link_data;
    bit<8> type; // 1 P2P, 2 transit network, 3 stub network, 4 virtual link
    bit<8> num_tos;
    bit<16> metric;
}

header ospf_router_tos_metric {
    bit<8> tos;
    bit<8> reserved;
    bit<16> metric;
}

// Network-LSA (2): four-octet mask, then attached routers' four-octet IDs.
header ospf_network_lsa {
    bit<32> network_mask;
}

// Summary-LSA (3/4): eight-octet base body. Type 4's mask is zero.
// Additional four-octet TOS metrics can follow for RFC 2328 compatibility.
header ospf_summary_lsa {
    bit<32> network_mask;
    bit<8> reserved;
    bit<24> metric;
}

header ospf_summary_tos_metric {
    bit<8> tos;
    bit<24> metric;
}

// AS-external-LSA (5): sixteen-octet base body.
// external_type: 0 for external metric type 1, 1 for external metric type 2.
// Additional twelve-octet TOS descriptions can follow.
header ospf_external_lsa {
    bit<32> network_mask;
    bit<1> external_type;
    bit<7> reserved;
    bit<24> metric;
    bit<32> fwd_addr;
    bit<32> ext_route_tag;
}

header ospf_external_tos_metric {
    bit<1> external_type;
    bit<7> tos;
    bit<24> metric;
    bit<32> fwd_addr;
    bit<32> ext_route_tag;
}

struct ospf_metadata_t {
    bit<32> pdu_bytes;
    bit<32> parsed_bytes;
    bit<32> trailing_bytes; // Outside length, still inside the IPv4 payload
    bit<16> authentication_bytes; // Appended data for AuType 2/3
    bit<16> remaining;
    bit<32> pending_lsas;
    bit<8> entry_count;
}

/**
 * Single OSPFv2 packet parser
 * headers contains ospf_header ospf, ospf_hello ospf_hello,
 * ospf_db_desc ospf_dd, ospf_ls_update ospf_update,
 * ospf_neighbor[8] ospf_neighbors, ospf_ls_request[8] ospf_requests,
 * ospf_lsa_header[8] ospf_lsa_headers and ospf_lsa_body[8] ospf_lsa_bodies.
 * metadata contains ospf_metadata_t ospf.
 *
 * The enclosing parser handles IPv4 using ipv4_header/ospf_transport,
 * including options and total_length, verifies protocol 89, and supplies
 * physically bounded payload_bytes excluding IP headers and Ethernet
 * padding/FCS. The cursor starts at the OSPF version octet. IPv4 fragments
 * need reassembly by the upper layer before this parser is invoked.
 *
 * This example parses at most eight neighbors, requests, LSA headers or
 * complete LSAs per packet. Eight is a local capacity, not a protocol
 * limit. A parser error reports excess entries or inconsistent boundaries.
 * DD/Ack entries consume twenty octets regardless of their advertised LSA
 * length. Update entries consume that length and must match num_lsas.
 * LSA bodies retain their original bytes, including unknown LSA types.
 *
 * Emit ospf, the valid Hello/DD/Update prefix and the active entry stack.
 * Emit each LSA header immediately followed by its corresponding body,
 * in index order. DD/Ack bodies remain invalid. Emit the remaining bytes
 * unchanged. Authentication data and LLS stay outside the parsed OSPF body.
 * RFC 5613 places LLS after any appended authentication data and signals
 * its presence with the L-bit in Hello/DD. The handler checks its framing.
 *
 * AuTypes 0..3 are represented here. RFC 7474's appended extended sequence
 * is part of its authentication length. Other AuTypes need their own
 * profile. The handler validates the receiving interface's Instance ID,
 * checksums, authentication algorithms/lengths, replay protection, LSA
 * bodies, options, area/interface rules, neighbor state, LSDB and SPF.
 * This parser and the control below do not establish routing adjacencies.
 */
/*
parser ospf_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                   in bit<32> payload_bytes) {
    bit<32> body_bytes;

    state start {
        hdr.ospf.setInvalid();
        hdr.ospf_hello.setInvalid();
        hdr.ospf_dd.setInvalid();
        hdr.ospf_update.setInvalid();
        hdr.ospf_neighbors[0].setInvalid();
        hdr.ospf_neighbors[1].setInvalid();
        hdr.ospf_neighbors[2].setInvalid();
        hdr.ospf_neighbors[3].setInvalid();
        hdr.ospf_neighbors[4].setInvalid();
        hdr.ospf_neighbors[5].setInvalid();
        hdr.ospf_neighbors[6].setInvalid();
        hdr.ospf_neighbors[7].setInvalid();
        hdr.ospf_requests[0].setInvalid();
        hdr.ospf_requests[1].setInvalid();
        hdr.ospf_requests[2].setInvalid();
        hdr.ospf_requests[3].setInvalid();
        hdr.ospf_requests[4].setInvalid();
        hdr.ospf_requests[5].setInvalid();
        hdr.ospf_requests[6].setInvalid();
        hdr.ospf_requests[7].setInvalid();
        hdr.ospf_lsa_headers[0].setInvalid();
        hdr.ospf_lsa_headers[1].setInvalid();
        hdr.ospf_lsa_headers[2].setInvalid();
        hdr.ospf_lsa_headers[3].setInvalid();
        hdr.ospf_lsa_headers[4].setInvalid();
        hdr.ospf_lsa_headers[5].setInvalid();
        hdr.ospf_lsa_headers[6].setInvalid();
        hdr.ospf_lsa_headers[7].setInvalid();
        hdr.ospf_lsa_bodies[0].setInvalid();
        hdr.ospf_lsa_bodies[1].setInvalid();
        hdr.ospf_lsa_bodies[2].setInvalid();
        hdr.ospf_lsa_bodies[3].setInvalid();
        hdr.ospf_lsa_bodies[4].setInvalid();
        hdr.ospf_lsa_bodies[5].setInvalid();
        hdr.ospf_lsa_bodies[6].setInvalid();
        hdr.ospf_lsa_bodies[7].setInvalid();
        meta.ospf.pdu_bytes = 0;
        meta.ospf.parsed_bytes = 0;
        meta.ospf.trailing_bytes = payload_bytes;
        meta.ospf.authentication_bytes = 0;
        meta.ospf.remaining = 0;
        meta.ospf.pending_lsas = 0;
        meta.ospf.entry_count = 0;
        verify(payload_bytes >= 24, error.HeaderTooShort);
        pkt.extract(hdr.ospf);
        verify(hdr.ospf.version == OSPF_VERSION, error.NoMatch);
        verify(hdr.ospf.length >= 24, error.HeaderTooShort);
        meta.ospf.pdu_bytes = (bit<32>) hdr.ospf.length;
        verify(meta.ospf.pdu_bytes <= payload_bytes, error.HeaderTooShort);
        verify(hdr.ospf.auth_type <= OSPF_AUTH_EXTENDED, error.NoMatch);
        transition select(hdr.ospf.auth_type) {
            OSPF_AUTH_CRYPTO: check_crypto_auth;
            OSPF_AUTH_EXTENDED: check_extended_auth;
            default: dispatch_body;
        }
    }

    state check_crypto_auth {
        meta.ospf.authentication_bytes =
            (bit<16>) hdr.ospf.auth_data[39:32];
        verify(meta.ospf.pdu_bytes
               + (bit<32>) meta.ospf.authentication_bytes <= payload_bytes,
               error.HeaderTooShort);
        transition dispatch_body;
    }

    state check_extended_auth {
        meta.ospf.authentication_bytes =
            (bit<16>) hdr.ospf.auth_data[39:32];
        verify(meta.ospf.authentication_bytes >= 8, error.HeaderTooShort);
        verify(meta.ospf.pdu_bytes
               + (bit<32>) meta.ospf.authentication_bytes <= payload_bytes,
               error.HeaderTooShort);
        transition dispatch_body;
    }

    state dispatch_body {
        meta.ospf.remaining = hdr.ospf.length - 24;
        meta.ospf.parsed_bytes = 24;
        meta.ospf.trailing_bytes = payload_bytes - meta.ospf.pdu_bytes;
        transition select(hdr.ospf.type) {
            ospf_packet_type.HELLO: parse_hello;
            ospf_packet_type.DB_DESC: parse_dd;
            ospf_packet_type.LS_REQ: next_request;
            ospf_packet_type.LS_UPDATE: parse_update;
            ospf_packet_type.LS_ACK: next_lsa_header;
            default: unsupported_type;
        }
    }

    state parse_hello {
        verify(meta.ospf.remaining >= 20, error.HeaderTooShort);
        pkt.extract(hdr.ospf_hello);
        meta.ospf.remaining = meta.ospf.remaining - 20;
        meta.ospf.parsed_bytes = meta.ospf.parsed_bytes + 20;
        transition next_neighbor;
    }

    state next_neighbor {
        transition select(meta.ospf.remaining, meta.ospf.entry_count) {
            (0, _): accept;
            (_, 8): capacity_exceeded;
            default: parse_neighbor;
        }
    }

    state parse_neighbor {
        verify(meta.ospf.remaining >= 4, error.HeaderTooShort);
        pkt.extract(hdr.ospf_neighbors.next);
        meta.ospf.remaining = meta.ospf.remaining - 4;
        meta.ospf.parsed_bytes = meta.ospf.parsed_bytes + 4;
        meta.ospf.entry_count = meta.ospf.entry_count + 1;
        transition next_neighbor;
    }

    state parse_dd {
        verify(meta.ospf.remaining >= 8, error.HeaderTooShort);
        pkt.extract(hdr.ospf_dd);
        meta.ospf.remaining = meta.ospf.remaining - 8;
        meta.ospf.parsed_bytes = meta.ospf.parsed_bytes + 8;
        transition next_lsa_header;
    }

    state next_request {
        transition select(meta.ospf.remaining, meta.ospf.entry_count) {
            (0, _): accept;
            (_, 8): capacity_exceeded;
            default: parse_request;
        }
    }

    state parse_request {
        verify(meta.ospf.remaining >= 12, error.HeaderTooShort);
        pkt.extract(hdr.ospf_requests.next);
        meta.ospf.remaining = meta.ospf.remaining - 12;
        meta.ospf.parsed_bytes = meta.ospf.parsed_bytes + 12;
        meta.ospf.entry_count = meta.ospf.entry_count + 1;
        transition next_request;
    }

    state next_lsa_header {
        transition select(meta.ospf.remaining, meta.ospf.entry_count) {
            (0, _): accept;
            (_, 8): capacity_exceeded;
            default: parse_lsa_header;
        }
    }

    state parse_lsa_header {
        verify(meta.ospf.remaining >= 20, error.HeaderTooShort);
        pkt.extract(hdr.ospf_lsa_headers.next);
        verify(hdr.ospf_lsa_headers.last.length >= 20, error.HeaderTooShort);
        meta.ospf.remaining = meta.ospf.remaining - 20;
        meta.ospf.parsed_bytes = meta.ospf.parsed_bytes + 20;
        meta.ospf.entry_count = meta.ospf.entry_count + 1;
        transition next_lsa_header;
    }

    state parse_update {
        verify(meta.ospf.remaining >= 4, error.HeaderTooShort);
        pkt.extract(hdr.ospf_update);
        meta.ospf.remaining = meta.ospf.remaining - 4;
        meta.ospf.parsed_bytes = meta.ospf.parsed_bytes + 4;
        meta.ospf.pending_lsas = hdr.ospf_update.num_lsas;
        transition next_lsa;
    }

    state next_lsa {
        transition select(meta.ospf.pending_lsas, meta.ospf.remaining,
                          meta.ospf.entry_count) {
            (0, 0, _): accept;
            (0, _, _): inconsistent_count;
            (_, _, 8): capacity_exceeded;
            default: parse_lsa;
        }
    }

    state parse_lsa {
        verify(meta.ospf.remaining >= 20, error.HeaderTooShort);
        pkt.extract(hdr.ospf_lsa_headers.next);
        verify(hdr.ospf_lsa_headers.last.length >= 20, error.HeaderTooShort);
        verify(hdr.ospf_lsa_headers.last.length <= meta.ospf.remaining,
               error.HeaderTooShort);
        body_bytes = (bit<32>) hdr.ospf_lsa_headers.last.length - 20;
        pkt.extract(hdr.ospf_lsa_bodies.next, body_bytes * 8);
        meta.ospf.remaining = meta.ospf.remaining
                            - hdr.ospf_lsa_headers.last.length;
        meta.ospf.parsed_bytes = meta.ospf.parsed_bytes
                               + (bit<32>) hdr.ospf_lsa_headers.last.length;
        meta.ospf.pending_lsas = meta.ospf.pending_lsas - 1;
        meta.ospf.entry_count = meta.ospf.entry_count + 1;
        transition next_lsa;
    }

    state unsupported_type {
        verify(false, error.NoMatch);
        transition accept;
    }

    state inconsistent_count {
        verify(false, error.NoMatch);
        transition accept;
    }

    state capacity_exceeded {
        verify(false, error.StackOutOfBounds);
        transition accept;
    }
}
*/

/**
 * Local protocol delivery (v1model)
 * handler_port and table ports identify local OSPF applications. Deliver
 * the original frame with its IPv4 source/destination and ingress context.
 * Authentication and interface/neighbor checks precede any state changes.
 */
/*
control ospf_control(inout headers hdr,
                     inout standard_metadata_t standard_metadata,
                     in bit<9> handler_port) {
    action deliver(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action deliver_default() {
        standard_metadata.egress_spec = handler_port;
    }

    table packet_handlers {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.ospf.area_id: exact;
            hdr.ospf.instance_id: exact;
            hdr.ospf.type: exact;
        }
        actions = {
            deliver;
            deliver_default;
        }
        default_action = deliver_default();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.ospf.isValid()) {
            mark_to_drop(standard_metadata);
        } else {
            packet_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_OSPF_P4
