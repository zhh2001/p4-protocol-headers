/*
 * Path Computation Element Communication Protocol
 * PCEP 标准报头、基础对象和状态扩展定义
 * RFC 5440, RFC 8231 and RFC 8281
 */
#ifndef P4_PROTOCOL_HEADERS_PCEP_P4
#define P4_PROTOCOL_HEADERS_PCEP_P4

typedef bit<8> pcep_object_class_t;

const bit<16> PCEP_TCP_PORT = 4189;
const bit<3> PCEP_VERSION = 1;
const bit<8> PCEP_OPEN = 1;
const bit<8> PCEP_KEEPALIVE = 2;
const bit<8> PCEP_PCREQ = 3;
const bit<8> PCEP_PCREP = 4;
const bit<8> PCEP_PCNTF = 5;
const bit<8> PCEP_PCERR = 6;
const bit<8> PCEP_CLOSE = 7;
const bit<8> PCEP_PCRPT = 10;
const bit<8> PCEP_PCUPD = 11;
const bit<8> PCEP_PCINITIATE = 12;

const pcep_object_class_t PCEP_OPEN_OBJ = 1;
const pcep_object_class_t PCEP_RP_OBJ = 2;
const pcep_object_class_t PCEP_NO_PATH_OBJ = 3;
const pcep_object_class_t PCEP_END_POINTS_OBJ = 4;
const pcep_object_class_t PCEP_BANDWIDTH_OBJ = 5;
const pcep_object_class_t PCEP_METRIC_OBJ = 6;
const pcep_object_class_t PCEP_ERO_OBJ = 7;
const pcep_object_class_t PCEP_RRO_OBJ = 8;
const pcep_object_class_t PCEP_LSPA_OBJ = 9;
const pcep_object_class_t PCEP_IRO_OBJ = 10;
const pcep_object_class_t PCEP_SVEC_OBJ = 11;
const pcep_object_class_t PCEP_NOTIFICATION_OBJ = 12;
const pcep_object_class_t PCEP_ERROR_OBJ = 13;
const pcep_object_class_t PCEP_CLOSE_OBJ = 15;
const pcep_object_class_t PCEP_LSP_OBJ = 32;
const pcep_object_class_t PCEP_SRP_OBJ = 33;

const bit<16> PCEP_STATEFUL_CAPABILITY_TLV = 16;
const bit<16> PCEP_SYMBOLIC_PATH_NAME_TLV = 17;
const bit<16> PCEP_IPV4_LSP_IDENTIFIERS_TLV = 18;
const bit<16> PCEP_IPV6_LSP_IDENTIFIERS_TLV = 19;
const bit<32> PCEP_CAPABILITY_UPDATE = 32w0x00000001;
const bit<32> PCEP_CAPABILITY_INSTANTIATION = 32w0x00000004; // RFC 8281
const bit<12> PCEP_LSP_DELEGATE = 12w0x001;
const bit<12> PCEP_LSP_SYNC = 12w0x002;
const bit<12> PCEP_LSP_REMOVE = 12w0x004;
const bit<12> PCEP_LSP_ADMINISTRATIVE = 12w0x008;
const bit<12> PCEP_LSP_OPERATIONAL_MASK = 12w0x070; // flags[6:4], values 0..4
const bit<12> PCEP_LSP_CREATE = 12w0x080; // RFC 8281
const bit<32> PCEP_SRP_REMOVE = 32w0x00000001; // RFC 8281
const bit<8> PCEP_EXAMPLE_MAX_OBJECTS = 32; // Example storage, not a wire limit

// Four-octet common header. msg_length includes the header and all objects.
// Common flags are unassigned, zero on transmission and ignored on receipt.
// Session ID and stateful capabilities are carried in the OPEN object/TLVs.
// Keepalive consists only of this header and has msg_length 4.
header pcep_t {
    bit<3> version;
    bit<5> flags;
    bit<8> msg_type;
    bit<16> msg_length;
}

// Four-octet object prefix followed by its raw body, in wire order.
// object_length includes the prefix, is at least 4 and a multiple of 4.
// The largest aligned length is 65532, with 65528 body octets. The
// enclosing message further limits this. Reserved bits are ignored.
// P/I interpretation depends on message, request and negotiated extensions.
header pcep_object_t {
    pcep_object_class_t object_class;
    bit<4> object_type;
    bit<2> reserved;
    bit<1> processing_rule;
    bit<1> ignore;
    bit<16> object_length;
    varbit<524224> object_value;
}

// Optional object TLV. length counts value octets, excluding this prefix
// and alignment padding. Extract length * 8 bits for value, then separately
// extract (4 - (length & 3)) & 3 padding octets. Check object bounds first.
// This capacity represents the length field, not the enclosing object limit.
// Unknown TLVs are ignored by the handler. Values/padding stay unchanged.
header pcep_tlv_t {
    bit<16> type;
    bit<16> length;
    varbit<524280> value;
}

header pcep_tlv_padding_t {
    varbit<24> padding;
}

// The following headers are alternative object-body prefixes. They follow
// a common object prefix, not pcep_t directly. Optional TLVs follow the
// fixed body where permitted. Do not extract these in addition to the raw
// object_value field for the same object.

// OPEN, class 1/type 1, four-octet fixed body followed by optional TLVs.
// Keepalive/DeadTimer are seconds. session_id is eight bits and is local
// to one direction of the session. version is 1, flags are unassigned.
header pcep_open_object_t {
    bit<3> version;
    bit<5> flags;
    bit<8> keepalive;
    bit<8> dead_timer;
    bit<8> session_id;
}

// RP, class 2/type 1, eight-octet fixed body followed by optional TLVs.
// Base flags[2:0] are priority, bit 3 reoptimization, bit 4 bidirectional,
// bit 5 loose path. Other assigned flags depend on negotiated extensions.
// request_id is nonzero. Path endpoints are in a separate END-POINTS object.
header pcep_rp_object_t {
    bit<32> flags;
    bit<32> request_id;
}

// END-POINTS, class 4, fixed bodies for type 1 (IPv4) and type 2 (IPv6).
header pcep_ipv4_endpoints_t {
    bit<32> source;
    bit<32> destination;
}

header pcep_ipv6_endpoints_t {
    bit<128> source;
    bit<128> destination;
}

// BANDWIDTH, class 5/type 1 requested, type 2 existing LSP. This is the
// IEEE 754 binary32 bit pattern in bytes/second, not an integer rate.
header pcep_bandwidth_object_t {
    bit<32> bandwidth;
}

// LSPA, class 9/type 1. Sixteen fixed body octets, then optional TLVs.
// Priorities are eight-bit fields with values 0..7. flags bit 0 requests
// local protection. Unassigned flags and reserved are ignored on receipt.
header pcep_lspa_object_t {
    bit<32> exclude_any;
    bit<32> include_any;
    bit<32> include_all;
    bit<8> setup_priority;
    bit<8> holding_priority;
    bit<8> flags;
    bit<8> reserved;
}

// SVEC, class 11/type 1. Four fixed body octets, then 32-bit request IDs.
// flags bits 0/1/2 request link/node/SRLG diversity. There is no ID count
// on the wire. Extract object_length - 8 octets for request_ids after
// checking the common object length and its alignment.
header pcep_svec_object_t {
    bit<8> reserved;
    bit<24> flags;
    varbit<524192> request_ids;
}

// LSP, class 32/type 1 (RFC 8231). Four fixed body octets, then TLVs.
// PLSP-ID is a session-scoped identifier, not a network-wide LSP ID.
// flags retain all twelve bits, including extensions. Base low bits are
// D/S/R/A and the three-bit operational value, see masks above.
// The symbolic name is a TLV. Setup/holding priorities belong to LSPA.
header pcep_lsp_object_t {
    bit<20> plsp_id;
    bit<12> flags;
}

// SRP, class 33/type 1. Eight fixed body octets, then optional TLVs.
// srp_id correlates stateful operations and replies within one session.
// Special IDs and flag validity depend on the message and session state.
// In particular, reports may use zero when no PCE request caused them.
// RFC 8786 updates handling of unknown SRP flags. Preserve them here.
header pcep_srp_object_t {
    bit<32> flags;
    bit<32> srp_id;
}

// Values only, excluding the four-octet TLV prefix and any padding.
// Stateful capability TLV type 16 has length 4. U must be advertised by
// both peers to allow updates. Additional capability bits remain raw.
header pcep_stateful_capability_t {
    bit<32> flags;
}

// Symbolic name TLV type 17. length is the nonzero value length, excluding
// prefix/padding (RFC 8231 verified erratum 6289). No NUL terminator.
header pcep_symbolic_path_name_t {
    varbit<524280> name;
}

// LSP identifier TLV types 18/19 have value lengths 16/52 respectively.
// These RSVP identifiers are distinct from the twenty-bit PLSP-ID.
header pcep_ipv4_lsp_identifiers_t {
    bit<32> sender;
    bit<16> lsp_id;
    bit<16> tunnel_id;
    bit<32> extended_tunnel_id;
    bit<32> endpoint;
}

header pcep_ipv6_lsp_identifiers_t {
    bit<128> sender;
    bit<16> lsp_id;
    bit<16> tunnel_id;
    bit<128> extended_tunnel_id;
    bit<128> endpoint;
}

struct pcep_metadata_t {
    bit<32> message_bytes;
    bit<32> parsed_bytes;
    bit<32> remaining;
    bit<16> object_bytes;
    bit<8> object_count;
    bool objects_pending;
    bool opaque_message;
}

/*
 * One framed message, generic object parsing and local delivery example
 * headers contains pcep_t pcep and pcep_object_t[32] pcep_objects.
 * metadata contains pcep_metadata_t pcep. Invoke once with headers invalid.
 *
 * The cursor starts at the common header. message_bytes is the physically
 * available size of one complete, already framed PCEP message. The caller
 * handles TCP reassembly, stream offsets, retransmissions and separation
 * of coalesced messages. TCP port 4189 identifies a session, not message
 * boundaries. TCP PSH and Ethernet padding do not delimit PCEP messages.
 * Bytes beyond message_bytes are outside this message.
 *
 * Version 1 base messages and PCRpt/PCUpd/PCInitiate use the generic object
 * loop. Only object framing is checked. Keepalive is exactly four octets.
 * Unknown message types keep their whole body and set opaque_message, so
 * the session owner can apply the unknown-message procedure. This also
 * avoids inferring object layouts for future message types or STARTTLS.
 *
 * This example stores at most 32 objects. If more remain, objects_pending
 * is set and the cursor stays at the next object's prefix. The handler
 * completes parsing that tail and validates its framing before processing
 * the message. The storage bound is not a protocol limit or format error.
 * Object bodies, TLVs, padding and route subobjects remain raw. Emit pcep
 * and the valid pcep_objects stack, then the remaining payload unchanged.
 *
 * The session owner validates object class/type, fixed-body sizes,
 * mandatory objects, their order, request groups, P/I rules (including
 * RFC 9753 where negotiated), TLVs, capability negotiation and state.
 * Unknown optional objects must not prevent recognized requests from
 * being processed. Unknown mandatory objects need the appropriate PCErr,
 * with request-level handling where applicable. Unknown TLVs are ignored.
 * TCP checksum/security, timers, delegation, LSP updates and path computation
 * belong to that owner. Parsing a capability TLV does not negotiate it.
 * The surrounding application reports framing errors to the owner for
 * protocol error handling. This example does not establish a session or
 * generate PCEP replies, modify LSPs or install paths.
 */
/*
parser pcep_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                   in bit<32> message_bytes) {
    bit<32> object_prefix;

    state start {
        meta.pcep.message_bytes = message_bytes;
        meta.pcep.parsed_bytes = 0;
        meta.pcep.remaining = message_bytes;
        meta.pcep.object_bytes = 0;
        meta.pcep.object_count = 0;
        meta.pcep.objects_pending = false;
        meta.pcep.opaque_message = false;
        verify(message_bytes >= 4 && message_bytes <= 65535, error.NoMatch);
        pkt.extract(hdr.pcep);
        verify(hdr.pcep.version == PCEP_VERSION
               && (bit<32>)hdr.pcep.msg_length == message_bytes, error.NoMatch);
        meta.pcep.parsed_bytes = 4;
        meta.pcep.remaining = message_bytes - 4;
        transition select(hdr.pcep.msg_type) {
            PCEP_KEEPALIVE: keepalive;
            PCEP_OPEN: next_object;
            PCEP_PCREQ: next_object;
            PCEP_PCREP: next_object;
            PCEP_PCNTF: next_object;
            PCEP_PCERR: next_object;
            PCEP_CLOSE: next_object;
            PCEP_PCRPT: next_object;
            PCEP_PCUPD: next_object;
            PCEP_PCINITIATE: next_object;
            default: opaque;
        }
    }

    state keepalive {
        verify(meta.pcep.remaining == 0, error.NoMatch);
        transition accept;
    }

    state next_object {
        transition select(meta.pcep.remaining, meta.pcep.object_count) {
            (0, _): accept;
            (_, PCEP_EXAMPLE_MAX_OBJECTS): pending;
            default: object;
        }
    }

    state object {
        verify(meta.pcep.remaining >= 4, error.NoMatch);
        object_prefix = pkt.lookahead<bit<32>>();
        meta.pcep.object_bytes = object_prefix[15:0];
        verify(meta.pcep.object_bytes >= 4
               && meta.pcep.object_bytes[1:0] == 0
               && (bit<32>)meta.pcep.object_bytes <= meta.pcep.remaining,
               error.NoMatch);
        pkt.extract(hdr.pcep_objects.next,
                    ((bit<32>)meta.pcep.object_bytes - 4) * 8);
        meta.pcep.object_count = meta.pcep.object_count + 1;
        meta.pcep.parsed_bytes = meta.pcep.parsed_bytes
                                 + (bit<32>)meta.pcep.object_bytes;
        meta.pcep.remaining = meta.pcep.remaining - (bit<32>)meta.pcep.object_bytes;
        transition next_object;
    }

    state pending {
        meta.pcep.objects_pending = true;
        transition accept;
    }

    state opaque {
        meta.pcep.opaque_message = true;
        transition accept;
    }
}

// v1model example. Ports identify local PCEP processing endpoints.
control pcep_control(inout headers hdr, inout metadata meta,
                     inout standard_metadata_t standard_metadata,
                     in bit<9> handler_port) {
    action deliver(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action deliver_default() {
        standard_metadata.egress_spec = handler_port;
    }

    table message_handlers {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.pcep.msg_type: exact;
            meta.pcep.objects_pending: exact;
            meta.pcep.opaque_message: exact;
        }
        actions = { deliver; deliver_default; }
        default_action = deliver_default();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.pcep.isValid()) {
            mark_to_drop(standard_metadata);
        } else {
            message_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_PCEP_P4
