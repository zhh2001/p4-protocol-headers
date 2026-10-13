#ifndef P4_PROTOCOL_HEADERS_BFD_P4
#define P4_PROTOCOL_HEADERS_BFD_P4

/**
 * Bidirectional Forwarding Detection control packets (RFC 5880)
 * BFD 控制报头、认证区和点到点解析示例
 * UDP single-hop and multihop bindings are RFC 5881 and RFC 5883.
 * RFC 8562 assigns the M bit to multipoint BFD. The example below handles
 * point-to-point control packets only. Echo payloads have no common format.
 */

const bit<3> BFD_VERSION = 1;
const bit<16> BFD_CONTROL_PORT = 3784;
const bit<16> BFD_ECHO_PORT = 3785;
const bit<16> BFD_MULTIHOP_CONTROL_PORT = 4784;

/* Diagnostic codes registered by IANA. Unknown values remain available to
 * the session owner. Code 9 is defined by RFC 6428 for MPLS-TP CC/CV.
 */
const bit<5> BFD_DIAG_NONE = 0;
const bit<5> BFD_DIAG_CTRL_EXPIRED = 1;
const bit<5> BFD_DIAG_ECHO_FAILED = 2;
const bit<5> BFD_DIAG_NEIGH_DOWN = 3;
const bit<5> BFD_DIAG_FWD_RESET = 4;
const bit<5> BFD_DIAG_PATH_DOWN = 5;
const bit<5> BFD_DIAG_CONCAT_DOWN = 6;
const bit<5> BFD_DIAG_ADMIN_DOWN = 7;
const bit<5> BFD_DIAG_REVERSE_CONCAT_DOWN = 8;
const bit<5> BFD_DIAG_MISCONNECTIVITY = 9;

const bit<2> BFD_STATE_ADMIN_DOWN = 0;
const bit<2> BFD_STATE_DOWN = 1;
const bit<2> BFD_STATE_INIT = 2;
const bit<2> BFD_STATE_UP = 3;

enum bit<8> bfd_auth_type {
    RESERVED = 0,
    SIMPLE_PASSWORD = 1,
    KEYED_MD5 = 2,
    METICULOUS_KEYED_MD5 = 3,
    KEYED_SHA1 = 4,
    METICULOUS_KEYED_SHA1 = 5,
    NULL_AUTH = 6,
    OPTIMIZED_MD5_ISAAC = 7,
    OPTIMIZED_SHA1_ISAAC = 8
};

/* Experimental RFC 9985 modes for the RFC 9986 optimized auth types. */
const bit<8> BFD_AUTH_MODE_MCI = 1;
const bit<8> BFD_AUTH_MODE_LCI = 2;

/* Mandatory control section (24 bytes).
 * Length counts this section and the optional Authentication Section.
 * Detect Mult and My Discriminator are nonzero. Your Discriminator echoes
 * the peer's My Discriminator. Zero is allowed during session establishment.
 * All three interval fields are in microseconds, not timestamp values.
 * Required Min RX = 0 requests no periodic control packets. Required Min
 * Echo RX = 0 indicates that the sender cannot receive Echo packets.
 * Poll and Final must not both be set. Their processing needs session state.
 * Demand and Control Plane Independent have the RFC 5880 meanings.
 * M = 0 for point-to-point BFD, M = 1 for RFC 8562 multipoint packets.
 */
header bfd_t {
    bit<3> version;
    bit<5> diag;
    bit<2> state;
    bit<1> poll;
    bit<1> final_;
    bit<1> ctrl_plane_indep;
    bit<1> auth_present;
    bit<1> demand;
    bit<1> multipoint;
    bit<8> detect_mult;
    bit<8> length;
    bit<32> my_discriminator;
    bit<32> your_discriminator;
    bit<32> desired_min_tx;
    bit<32> required_min_rx;
    bit<32> required_min_echo;
}

/* Auth Len counts Auth Type, Auth Len and all authentication data. */
header bfd_auth_prefix_t {
    bit<8> auth_type;
    bit<8> auth_len;
}

/* Complete generic authentication section. The one-byte BFD Length caps it
 * at 231 bytes, leaving at most 229 bytes after the two-byte prefix.
 */
header bfd_auth_t {
    bit<8> auth_type;
    bit<8> auth_len;
    varbit<1832> data;
}

/* Complete typed alternatives replace bfd_auth_t, not its data field.
 * Simple Password (type 1): Auth Len = 3 + password bytes, 4-19 in total.
 * Password is a binary string of 1-16 bytes and is carried on the wire.
 */
header bfd_password_auth_t {
    bit<8> auth_type;
    bit<8> auth_len;
    bit<8> key_id;
    varbit<128> password;
}

/* Keyed/Meticulous Keyed MD5 (types 2/3), Auth Len = 24.
 * Reserved is zero on transmit and ignored on receipt. MD5 authentication
 * is retained for wire compatibility and is discouraged by RFC 5880.
 * The digest covers the complete BFD packet with the selected key padded
 * to 16 bytes in the digest field during calculation, not an HMAC.
 * A received digest is retained unchanged. The secret key is not emitted.
 */
header bfd_md5_auth_t {
    bit<8> auth_type;
    bit<8> auth_len;
    bit<8> key_id;
    bit<8> reserved;
    bit<32> sequence_number;
    bit<128> digest;
}

/* Keyed/Meticulous Keyed SHA1 (types 4/5), Auth Len = 28.
 * Reserved has the same rules as MD5. The complete BFD packet is hashed
 * with the selected key padded to 20 bytes in the hash field, not an HMAC.
 * Authentication sequence arithmetic and replay checks belong to the owner.
 */
header bfd_sha1_auth_t {
    bit<8> auth_type;
    bit<8> auth_len;
    bit<8> key_id;
    bit<8> reserved;
    bit<32> sequence_number;
    bit<160> hash;
}

/* Experimental RFC 9978 NULL authentication (type 6), Auth Len = 8.
 * This format measures loss and provides no cryptographic authentication.
 * Key ID and Reserved are zero on transmit and ignored on receipt.
 */
header bfd_null_auth_t {
    bit<8> auth_type;
    bit<8> auth_len;
    bit<8> key_id;
    bit<8> reserved;
    bit<32> sequence_number;
}

/* Experimental RFC 9985 common optimized prefix. The fourth byte is a mode,
 * not a reserved byte. Type 7/8 mode 1 uses the MD5/SHA1 format below.
 * Mode 2 uses ISAAC and can maintain Up state, not signal state changes.
 */
header bfd_optimized_auth_prefix_t {
    bit<8> auth_type;
    bit<8> auth_len;
    bit<8> key_id;
    bit<8> mode;
    bit<32> sequence_number;
}

/* Experimental RFC 9986 type 7, mode 1, Auth Len = 24. */
header bfd_optimized_md5_auth_t {
    bit<8> auth_type;
    bit<8> auth_len;
    bit<8> key_id;
    bit<8> mode;
    bit<32> sequence_number;
    bit<128> digest;
}

/* Experimental RFC 9986 type 8, mode 1, Auth Len = 28.
 * The SHA1 value occupies 20 bytes as in RFC 5880 section 6.7.4.
 */
header bfd_optimized_sha1_auth_t {
    bit<8> auth_type;
    bit<8> auth_len;
    bit<8> key_id;
    bit<8> mode;
    bit<32> sequence_number;
    bit<160> hash;
}

/* Experimental RFC 9986 type 7/8, mode 2, Auth Len = 16.
 * Auth Key carries a 32-bit ISAAC output, not the shared secret key.
 * Seed and sequence validation require per-session ISAAC state.
 */
header bfd_isaac_auth_t {
    bit<8> auth_type;
    bit<8> auth_len;
    bit<8> key_id;
    bit<8> mode;
    bit<32> sequence_number;
    bit<32> seed;
    bit<32> auth_key;
}

/* Storage for unparsed bytes within BFD Length, not a defined extension.
 * Bytes beyond BFD Length remain in the enclosing packet payload.
 */
header bfd_control_tail_t {
    varbit<1848> data;
}

struct bfd_headers_t {
    bfd_t base;
    bfd_auth_t auth;
    bfd_control_tail_t tail;
};

struct bfd_metadata_t {
    bit<32> message_bytes;
    bit<32> auth_bytes;
    bit<32> unparsed_bytes;
    bit<32> outer_trailing_bytes;
};

/**
 * Point-to-point control parsing and local delivery example (P4_16, v1model).
 * The cursor points to one complete BFD control packet. outer_bytes is the
 * validated enclosing payload length. For UDP this excludes the UDP header,
 * IP headers and link padding. The caller classifies the BFD application and
 * handles enclosing lengths, IP reassembly, UDP checksums and hop-limit policy.
 * RFC 5881 single-hop control uses UDP 3784 and source ports 49152-65535.
 * Unauthenticated single-hop sessions require a received TTL/Hop Limit of
 * 255. Authenticated sessions may enforce the same check by local policy.
 * RFC 5883 multihop control uses UDP 4784 and separate path policy.
 * Echo, multipoint and seamless BFD require their own application procedures.
 *
 * The parser checks version, control/authentication framing and the RFC 5880
 * point-to-point invariants. It retains the complete authentication section,
 * including unknown types, and any additional bytes within BFD Length.
 * The length may be smaller than outer_bytes. The outer trailing bytes stay
 * unchanged and are not part of the BFD authentication calculation.
 * Type-specific lengths, keys, digests, sequences, optimized modes and any
 * residual bytes are checked by the configured BFD owner. Parsing an auth
 * section does not authenticate it. NULL authentication does not verify keys.
 *
 * context_id identifies a configured local endpoint and application context.
 * A nonzero Your Discriminator selects a configured local discriminator.
 * An entry with Your Discriminator = 0 delivers initial Down/AdminDown packets
 * to the owner for application-specific session selection. Point-to-point
 * RFC 5881 links do not identify sessions by the remote IP source address.
 * The table does not create sessions or infer that a path is Up. The owner
 * validates authentication before updating session state or detection timers,
 * and implements Poll/Final responses, Demand mode, interval negotiation and
 * Echo handling. Emit base, auth and tail, then the untouched outer payload.
 */
/*
parser bfd_parser(packet_in pkt, out bfd_headers_t hdr,
                  out bfd_metadata_t meta, in bit<32> outer_bytes) {
    bit<32> remaining;
    bit<32> auth_bytes;

    state start {
        meta.message_bytes = 0;
        meta.auth_bytes = 0;
        meta.unparsed_bytes = 0;
        meta.outer_trailing_bytes = 0;
        verify(outer_bytes >= 24, error.HeaderTooShort);
        pkt.extract(hdr.base);
        verify(hdr.base.version == BFD_VERSION, error.NoMatch);
        verify(hdr.base.length >= 24, error.HeaderTooShort);
        meta.message_bytes = (bit<32>)hdr.base.length;
        verify(meta.message_bytes <= outer_bytes, error.HeaderTooShort);
        verify(hdr.base.detect_mult != 0 && hdr.base.multipoint == 0
               && hdr.base.my_discriminator != 0, error.NoMatch);
        verify(hdr.base.your_discriminator != 0
               || hdr.base.state == BFD_STATE_DOWN
               || hdr.base.state == BFD_STATE_ADMIN_DOWN, error.NoMatch);
        verify(hdr.base.poll == 0 || hdr.base.final_ == 0, error.NoMatch);
        remaining = meta.message_bytes - 24;
        meta.outer_trailing_bytes = outer_bytes - meta.message_bytes;
        transition select(hdr.base.auth_present) {
            1: parse_auth;
            default: parse_tail;
        }
    }

    state parse_auth {
        bit<16> prefix;
        verify(remaining >= 2, error.HeaderTooShort);
        prefix = pkt.lookahead<bit<16>>();
        auth_bytes = (bit<32>)prefix[7:0];
        verify(auth_bytes >= 2, error.NoMatch);
        verify(auth_bytes <= remaining, error.HeaderTooShort);
        pkt.extract(hdr.auth, (auth_bytes - 2) * 8);
        meta.auth_bytes = auth_bytes;
        remaining = remaining - auth_bytes;
        transition parse_tail;
    }

    state parse_tail {
        meta.unparsed_bytes = remaining;
        pkt.extract(hdr.tail, remaining * 8);
        transition accept;
    }
}

control bfd_control(inout bfd_headers_t hdr,
                    inout standard_metadata_t standard_metadata,
                    in bit<32> context_id) {
    action deliver_bfd(bit<9> handler_port) {
        standard_metadata.egress_spec = handler_port;
    }

    action drop_bfd() {
        mark_to_drop(standard_metadata);
    }

    table bfd_handlers {
        key = {
            context_id: exact;
            hdr.base.your_discriminator: exact;
        }
        actions = {
            deliver_bfd;
            drop_bfd;
        }
        default_action = drop_bfd();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.base.isValid()) {
            mark_to_drop(standard_metadata);
        } else {
            bfd_handlers.apply();
        }
    }
}
*/

#endif
