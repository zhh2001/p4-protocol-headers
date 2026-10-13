#ifndef P4_PROTOCOL_HEADERS_ERSPAN_P4
#define P4_PROTOCOL_HEADERS_ERSPAN_P4

/**
 * Encapsulated Remote Switch Port Analyzer definitions
 * ERSPAN 远程端口镜像报头，保留镜像内容及采集元数据
 * Format reference: draft-foschiano-erspan-03, sections 3-7.
 * This Cisco Internet-Draft is expired and has no published RFC.
 * RFC 7348 describes VXLAN, rather than ERSPAN.
 * Wire order: [outer Ethernet][IPv4 or IPv6][GRE][ERSPAN][mirrored bytes].
 * Type I has no ERSPAN feature header. Type II and III use GRE sequencing.
 */

const bit<8> ERSPAN_IP_PROTOCOL = 47;
const bit<16> GRE_PROTO_ERSPAN_I = 0x88BE;
const bit<16> GRE_PROTO_ERSPAN_II = 0x88BE;
const bit<16> GRE_PROTO_ERSPAN_III = 0x22EB;
const bit<16> ERSPAN_GRE_SEQUENCE = 0x1000;
const bit<4> ERSPAN_VERSION_II = 1;
const bit<4> ERSPAN_VERSION_III = 2;

enum bit<2> erspan_encapsulation {
    UNTAGGED = 0,
    ISL = 1,
    DOT1Q = 2,
    TAG_PRESERVED = 3
};

enum bit<2> erspan_frame_status {
    GOOD_OR_UNKNOWN = 0,
    SHORT = 1,
    OVERSIZED = 2,
    CRC_OR_ALIGNMENT_ERROR = 3
};

enum bit<5> erspan_frame_type {
    ETHERNET = 0,
    IP = 2
};

enum bit<2> erspan_timestamp_granularity {
    MICROSECONDS_100 = 0,
    NANOSECONDS_100 = 1,
    IEEE_1588 = 2,
    PLATFORM_DEFINED = 3
};

/* ERSPAN GRE prefix (4 bytes). Only S may be set, all other bits are zero. */
header erspan_gre_t {
    bit<16> flags_version;
    bit<16> protocol;
};

/* Present for Type II and III, increments per packet per session. */
header erspan_sequence_t {
    bit<32> sequence;
};

/**
 * Type II feature header (8 bytes), preceded by 8 bytes of GRE.
 * En describes the original trunk encapsulation. With En = 3, the tag stays
 * in the mirrored frame and vlan_id is undefined. Transmit reserved as zero.
 * Index is a platform-dependent port and direction identifier, not a clock.
 * The original Ethernet FCS is omitted for Type I and II.
 */
header erspan_type2_t {
    bit<4> version;
    bit<12> vlan_id;
    bit<3> cos;
    bit<2> en;
    bit<1> truncated;
    bit<10> session_id;
    bit<12> reserved;
    bit<20> index;
};

/**
 * Type III feature header (12 bytes), preceded by 8 bytes of GRE.
 * BSO reports the integrity of the mirrored frame, including bad captures.
 * P identifies an Ethernet protocol PDU. FT may describe stripped L2 framing.
 * Direction is 0 for ingress and 1 for egress. O adds an 8-byte subheader.
 * Timestamp units depend on Gra and the platform format. Gra = 2 uses the
 * nanoseconds field here and the seconds field in the platform subheader.
 * Timestamp rollover, clock synchronization and original FCS handling belong
 * to the capture owner. An outer good FCS does not establish original integrity.
 */
header erspan_type3_t {
    bit<4> version;
    bit<12> vlan_id;
    bit<3> cos;
    bit<2> bso;
    bit<1> truncated;
    bit<10> session_id;
    bit<32> timestamp;
    bit<16> sgt;
    bit<1> pdu;
    bit<5> frame_type;
    bit<6> hw_id;
    bit<1> direction;
    bit<2> gra;
    bit<1> optional;
};

/* Generic optional subheader (8 bytes). Unknown platform information is opaque. */
header erspan_platform_t {
    bit<6> platform_id;
    bit<58> info;
};

/* Alternative views of those same 8 bytes, not additional stacked headers. */
header erspan_platform1_t {
    bit<6> platform_id;       // 1, Gra = 0
    bit<14> reserved;
    bit<12> vsm_domain_id;
    bit<32> port_index;
};

header erspan_platform3_t {
    bit<6> platform_id;       // 3, Gra = 0, 1 or 3 (3 means nanoseconds)
    bit<12> reserved;
    bit<14> port_index;
    bit<32> timestamp_high;   // Upper half of a 64-bit timestamp
};

header erspan_platform4_t {
    bit<6> platform_id;       // 4, Gra = 0
    bit<58> reserved;
};

header erspan_platform5_6_t {
    bit<6> platform_id;       // 5 or 6, Gra = 2
    bit<10> switch_id;
    bit<16> port_index;
    bit<32> timestamp_seconds;
};

header erspan_platform7_t {
    bit<6> platform_id;       // 7, Gra = 3 (nanoseconds)
    bit<6> reserved;
    bit<20> source_index;     // Ingress: 12-bit port group and 8-bit port index
    bit<32> timestamp_high;
};

/* Platform ID 0 is reserved, but some devices use it as an alias for 7.
 * ID 2 and IDs 8-63 are reserved. Do not infer a format from an unknown ID.
 */

struct erspan_headers_t {
    erspan_gre_t gre;
    erspan_sequence_t sequence;
    erspan_type2_t type2;
    erspan_type3_t type3;
    erspan_platform_t platform;
};

struct erspan_metadata_t {
    bit<2> erspan_type;       // 1, 2 or 3, not the feature header's Version
    bit<10> session_id;       // Type I has no session field, use context instead
    bit<16> header_bytes;     // GRE plus feature and optional headers
    bit<16> mirrored_bytes;   // Remaining validated IP payload bytes
};

/**
 * Bounded parsing and local capture delivery example (P4_16, v1model).
 * The cursor points to the GRE prefix after outer IP protocol 47 validation.
 * erspan_bytes is the validated available IP payload length at this cursor.
 * The enclosing pipeline checks outer lengths and IPv4 checksum, handles
 * options and extensions, and applies its fragmentation and source policy.
 * Exclude outer Ethernet padding and FCS from erspan_bytes.
 *
 * GRE Protocol Type and S distinguish Type I from II. Type III requires S.
 * Only encapsulation headers are extracted. Mirrored bytes stay unchanged,
 * even for truncated captures, short or bad frames, preserved VLAN tags and
 * non-Ethernet FT values. There is no assumed minimum original frame length.
 * Received Type II reserved bits and all platform information are preserved.
 * The local owner interprets platform formats, timestamps, P, FT, BSO and T,
 * validates their combinations and manages any original FCS reconstruction.
 * The parser does not treat capture metadata as a forwarding instruction.
 *
 * context_id is configured for a validated outer source-destination pair.
 * Session numbers can be reused by different endpoint pairs. Type I uses
 * context_id with no session field. The table defaults to drop and delivers
 * the intact ERSPAN packet to a configured local capture handler.
 * The enclosing pipeline supplies outer framing and any decapsulation.
 * Emit gre, sequence, type2, type3, platform and remaining bytes in that order.
 */
/*
parser erspan_parser(packet_in pkt, out erspan_headers_t hdr,
                     out erspan_metadata_t meta, in bit<16> erspan_bytes) {
    state start {
        meta.erspan_type = 0;
        meta.session_id = 0;
        meta.header_bytes = 0;
        meta.mirrored_bytes = 0;
        verify(erspan_bytes >= 4, error.HeaderTooShort);
        pkt.extract(hdr.gre);
        verify(hdr.gre.flags_version == 0
               || hdr.gre.flags_version == ERSPAN_GRE_SEQUENCE, error.NoMatch);
        transition select(hdr.gre.protocol, hdr.gre.flags_version) {
            (GRE_PROTO_ERSPAN_I, 0): parse_type1;
            (GRE_PROTO_ERSPAN_II, ERSPAN_GRE_SEQUENCE): parse_type2;
            (GRE_PROTO_ERSPAN_III, ERSPAN_GRE_SEQUENCE): parse_type3;
            default: unsupported_gre;
        }
    }

    state unsupported_gre {
        verify(false, error.NoMatch);
        transition accept;
    }

    state parse_type1 {
        meta.erspan_type = 1;
        meta.header_bytes = 4;
        transition finish;
    }

    state parse_type2 {
        verify(erspan_bytes >= 16, error.HeaderTooShort);
        pkt.extract(hdr.sequence);
        pkt.extract(hdr.type2);
        verify(hdr.type2.version == ERSPAN_VERSION_II, error.NoMatch);
        meta.erspan_type = 2;
        meta.session_id = hdr.type2.session_id;
        meta.header_bytes = 16;
        transition finish;
    }

    state parse_type3 {
        verify(erspan_bytes >= 20, error.HeaderTooShort);
        pkt.extract(hdr.sequence);
        pkt.extract(hdr.type3);
        verify(hdr.type3.version == ERSPAN_VERSION_III, error.NoMatch);
        meta.erspan_type = 3;
        meta.session_id = hdr.type3.session_id;
        meta.header_bytes = 20;
        transition select(hdr.type3.optional) {
            1: parse_platform;
            default: finish;
        }
    }

    state parse_platform {
        verify(erspan_bytes >= 28, error.HeaderTooShort);
        pkt.extract(hdr.platform);
        meta.header_bytes = 28;
        transition finish;
    }

    state finish {
        meta.mirrored_bytes = erspan_bytes - meta.header_bytes;
        transition accept;
    }
}

control erspan_control(inout erspan_headers_t hdr,
                       in erspan_metadata_t meta, in bit<32> context_id,
                       inout standard_metadata_t standard_metadata) {
    action deliver_erspan(bit<9> handler_port) {
        standard_metadata.egress_spec = handler_port;
    }

    action drop_erspan() {
        mark_to_drop(standard_metadata);
    }

    table erspan_handlers {
        key = {
            context_id: exact;
            meta.erspan_type: exact;
            meta.session_id: exact;
        }
        actions = {
            deliver_erspan;
            drop_erspan;
        }
        default_action = drop_erspan();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.gre.isValid() || meta.erspan_type == 0) {
            mark_to_drop(standard_metadata);
        } else {
            erspan_handlers.apply();
        }
    }
}
*/

#endif
