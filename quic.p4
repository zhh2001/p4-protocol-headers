/*
 * QUIC packet headers and cleartext prefix parsing
 * QUIC 报头与明文前缀解析
 * RFC 8999, RFC 9000, RFC 9001, RFC 9287 and RFC 9369
 */
#ifndef P4_PROTOCOL_HEADERS_QUIC_P4
#define P4_PROTOCOL_HEADERS_QUIC_P4

const bit<32> QUIC_VERSION_NEGOTIATION = 32w0;
const bit<32> QUIC_VERSION_1 = 32w0x00000001;
const bit<32> QUIC_VERSION_2 = 32w0x6b3343cf;
const bit<8> QUIC_V1_V2_MAX_CID_BYTES = 8w20;
const bit<32> QUIC_EXAMPLE_MAX_TOKEN_BYTES = 32w65535;

// The first octet is common to long and short headers. Only header_form
// is version independent. Preserve the other seven bits until the version
// and packet type are known. Version Negotiation ignores all seven bits.
header quic_t {
    bit<1> header_form;
    bit<7> version_specific;
};

// Alternative first-octet views for v1/v2. Extract instead of quic_t.
// Long type-specific bits are protected for Initial/0-RTT/Handshake,
// but unused for Retry. Their low two bits encode PN length minus one
// only after header protection is removed. Reserved bits are checked
// only after both header and packet protection have been removed.
header quic_long_first_t {
    bit<1> header_form;
    bit<1> fixed_bit;
    bit<2> packet_type;
    bit<4> type_specific;
};

// Short low five bits contain reserved(2), key phase(1) and PN length(2).
// All five are header protected. Spin and the QUIC bit are not protected.
// fixed_bit may be zero under the locally supported RFC 9287 extension.
header quic_short_first_t {
    bit<1> header_form;
    bit<1> fixed_bit;
    bit<1> spin_bit;
    bit<5> protected_bits;
};

// Long-header fields after the first octet, in their actual wire order.
// Each connection ID follows its own one-octet length. RFC 8999 permits
// lengths 0..255 for the invariant layout and Version Negotiation.
// Known v1/v2 packets restrict each ID to 0..20 octets.
header quic_long_t {
    bit<32> version;
    bit<8> dcid_length;
    varbit<2040> dcid;
};

header quic_source_cid_t {
    bit<8> scid_length;
    varbit<2040> scid;
};

// The short header carries a destination ID only. Its length is supplied
// by the connection or deployment configuration, with no wire length byte.
// This type covers v1/v2. Other versions require their own context/type.
header quic_short_cid_t {
    varbit<160> dcid;
};

// QUIC integers use 1, 2, 4 or 8 octets, including a two-bit length code.
// Versions, CID lengths and truncated packet numbers use other encodings.
// Token Length and Length permit nonminimal encodings. A decrypted Frame
// Type uses this encoding too, but MUST use the shortest representation.
header quic_varint8_t {
    bit<2> length_code; // 0
    bit<6> value;
};

header quic_varint16_t {
    bit<2> length_code; // 1
    bit<14> value;
};

header quic_varint32_t {
    bit<2> length_code; // 2
    bit<30> value;
};

header quic_varint64_t {
    bit<2> length_code; // 3
    bit<62> value;
};

struct quic_varint_headers_t {
    quic_varint8_t one;
    quic_varint16_t two;
    quic_varint32_t four;
    quic_varint64_t eight;
};

// Initial Token follows Token Length. Retry Token has no length field:
// it occupies the bytes before the final 16-octet Retry Integrity Tag.
// This storage capacity is an example choice, not a QUIC token limit.
header quic_token_t {
    varbit<524280> token;
};

header quic_retry_integrity_t {
    bit<128> tag;
};

// Version Negotiation ends with one or more 32-bit Supported Version
// values. It has no Length or Packet Number and occupies the datagram.
header quic_supported_version_t {
    bit<32> version;
};

// Alternative truncated packet numbers, extracted after removing header
// protection. Wire widths are 1..4 octets, including three octets.
// Reconstruct the full number (0..2^62-1) using connection state.
// Frame Type and frames follow packet decryption, not the visible header.
header quic_packet_number8_t { bit<8> truncated; };
header quic_packet_number16_t { bit<16> truncated; };
header quic_packet_number24_t { bit<24> truncated; };
header quic_packet_number32_t { bit<32> truncated; };

// Unprotected long-header type bits are version specific (RFC 9369).
const bit<2> QUIC_V1_INITIAL = 2w0;
const bit<2> QUIC_V1_ZERO_RTT = 2w1;
const bit<2> QUIC_V1_HANDSHAKE = 2w2;
const bit<2> QUIC_V1_RETRY = 2w3;
const bit<2> QUIC_V2_RETRY = 2w0;
const bit<2> QUIC_V2_INITIAL = 2w1;
const bit<2> QUIC_V2_ZERO_RTT = 2w2;
const bit<2> QUIC_V2_HANDSHAKE = 2w3;

// Local classification, not the two-bit wire packet type.
enum bit<3> quic_packet_kind_t {
    QUIC_INITIAL = 0,
    QUIC_ZERO_RTT = 1,
    QUIC_HANDSHAKE = 2,
    QUIC_RETRY = 3,
    QUIC_NEGOTIATION = 4,
    QUIC_SHORT = 5,
    QUIC_UNKNOWN = 6
};

// The caller obtains short-header context from connection/deployment state.
// short_context_known includes knowledge of the version and ID length.
// accept_zero_fixed_bit records local support advertised under RFC 9287,
// or configured acceptance for tokens from previously supported sessions.
// It is never inferred from an untrusted packet's QUIC bit.
struct quic_context_t {
    bit<32> short_version;
    bit<8> short_dcid_bytes;
    bool short_context_known;
    bool accept_zero_fixed_bit;
};

struct quic_integer_metadata_t {
    bit<62> value;
    bit<4> encoded_bytes;
};

struct quic_metadata_t {
    quic_packet_kind_t kind;
    bit<32> version;
    bool version_known;
    bool cid_known;
    bool opaque_body;
    bit<8> dcid_bytes;
    bit<8> scid_bytes;
    bit<32> datagram_bytes;
    bit<32> parsed_bytes;
    bit<32> remaining;
    bit<32> packet_bytes;
    bit<32> coalesced_bytes;
    quic_integer_metadata_t token_length;
    quic_integer_metadata_t length;
};

// Example storage for exactly one visible prefix. The encrypted tail and
// any coalesced packets remain in packet_in and are emitted unchanged.
struct quic_headers_t {
    quic_t common;
    quic_long_t long_header;
    quic_source_cid_t source;
    quic_short_cid_t short_cid;
    quic_varint_headers_t token_length;
    quic_token_t token;
    quic_varint_headers_t length;
};

/*
 * Visible-prefix and local delivery example
 * Pass the validated UDP payload length as datagram_bytes. The cursor
 * points to the first QUIC packet. The parsers initialize their output headers.
 * The caller identifies candidate QUIC traffic from configured services or
 * connections. QUIC has no mandatory UDP port and is not limited to HTTP/3.
 *
 * Parse invariant long fields for any version, and v1/v2 Token Length,
 * Token and Length where present. Length counts the protected packet number
 * plus payload, not the entire packet or UDP datagram. Compare the full
 * 62-bit value before narrowing it. Known protected long packets require
 * at least 20 bytes after the Length field for the header-protection sample.
 * Larger tokens than the example storage stay raw for the local owner.
 * Unknown versions and short headers without context also stay opaque.
 * Version Negotiation and Retry consume the entire datagram. Validate their
 * list/token boundaries, leaving version values and integrity checking to
 * the owner. Retry low bits and all Version Negotiation unused bits stay raw.
 *
 * Short prefixes use configured CID length. The remaining bytes stay raw,
 * even when too short for a normal protected packet with that CID length.
 * A Stateless Reset can look like a short packet without its usual CID.
 * Preserve such candidates for the owner's reset-token check. Known v1/v2
 * short packets and Stateless Resets have a minimum total size of 21 bytes.
 *
 * Route the whole datagram using the first packet. The owner processes each
 * coalesced packet, checks CID consistency, authenticates and decrypts,
 * reconstructs packet numbers, checks reserved bits and parses frames. It
 * also enforces role/session rules, Initial datagram size and Retry/VN state.
 * parsed_bytes is the consumed prefix, remaining is the untouched UDP tail.
 * packet_bytes/coalesced_bytes are known only when opaque_body is false.
 *
 * Emit common, long_header, source, short_cid, token_length.one/two/four/eight,
 * token and length.one/two/four/eight in that order, then the untouched tail.
 * Emit only these wire fields, without serializing decoded metadata. The
 * local handlers receive the complete original datagram and its UDP/IP
 * context. This example does not rewrite protected bytes or reply to peers.
 */
/*
parser quic_varint_parser(packet_in pkt, out quic_varint_headers_t hdr,
                          out quic_integer_metadata_t value,
                          in bit<32> available_bytes) {
    state start {
        value.value = 0;
        value.encoded_bytes = 0;
        verify(available_bytes >= 1, error.HeaderTooShort);
        transition select(pkt.lookahead<bit<2>>()) {
            0: one;
            1: two;
            2: four;
            3: eight;
        }
    }

    state one {
        pkt.extract(hdr.one);
        value.value = (bit<62>)hdr.one.value;
        value.encoded_bytes = 1;
        transition accept;
    }

    state two {
        verify(available_bytes >= 2, error.HeaderTooShort);
        pkt.extract(hdr.two);
        value.value = (bit<62>)hdr.two.value;
        value.encoded_bytes = 2;
        transition accept;
    }

    state four {
        verify(available_bytes >= 4, error.HeaderTooShort);
        pkt.extract(hdr.four);
        value.value = (bit<62>)hdr.four.value;
        value.encoded_bytes = 4;
        transition accept;
    }

    state eight {
        verify(available_bytes >= 8, error.HeaderTooShort);
        pkt.extract(hdr.eight);
        value.value = hdr.eight.value;
        value.encoded_bytes = 8;
        transition accept;
    }
}

parser quic_parser(packet_in pkt, out quic_headers_t hdr,
                   out quic_metadata_t meta, in quic_context_t context,
                   in bit<32> datagram_bytes) {
    quic_varint_parser() integer;

    state start {
        meta.kind = quic_packet_kind_t.QUIC_UNKNOWN;
        meta.version = 0;
        meta.version_known = false;
        meta.cid_known = false;
        meta.opaque_body = false;
        meta.dcid_bytes = 0;
        meta.scid_bytes = 0;
        meta.datagram_bytes = datagram_bytes;
        meta.parsed_bytes = 0;
        meta.remaining = datagram_bytes;
        meta.packet_bytes = 0;
        meta.coalesced_bytes = 0;
        meta.token_length.value = 0;
        meta.token_length.encoded_bytes = 0;
        meta.length.value = 0;
        meta.length.encoded_bytes = 0;
        verify(meta.remaining >= 1, error.HeaderTooShort);
        pkt.extract(hdr.common);
        meta.parsed_bytes = 1;
        meta.remaining = meta.remaining - 1;
        transition select(hdr.common.header_form) {
            1: long_header;
            default: short_header;
        }
    }

    state long_header {
        verify(meta.remaining >= 5, error.HeaderTooShort);
        meta.version = pkt.lookahead<bit<40>>()[39:8];
        meta.dcid_bytes = pkt.lookahead<bit<40>>()[7:0];
        meta.version_known = meta.version == QUIC_VERSION_1
                             || meta.version == QUIC_VERSION_2;
        verify(!meta.version_known || meta.dcid_bytes <= QUIC_V1_V2_MAX_CID_BYTES,
               error.NoMatch);
        verify((bit<32>)meta.dcid_bytes + 5 <= meta.remaining,
               error.HeaderTooShort);
        pkt.extract(hdr.long_header, (bit<32>)meta.dcid_bytes * 8);
        meta.parsed_bytes = meta.parsed_bytes + (bit<32>)meta.dcid_bytes + 5;
        meta.remaining = meta.remaining - (bit<32>)meta.dcid_bytes - 5;
        transition source_cid;
    }

    state source_cid {
        verify(meta.remaining >= 1, error.HeaderTooShort);
        meta.scid_bytes = pkt.lookahead<bit<8>>();
        verify(!meta.version_known || meta.scid_bytes <= QUIC_V1_V2_MAX_CID_BYTES,
               error.NoMatch);
        verify((bit<32>)meta.scid_bytes + 1 <= meta.remaining,
               error.HeaderTooShort);
        pkt.extract(hdr.source, (bit<32>)meta.scid_bytes * 8);
        meta.parsed_bytes = meta.parsed_bytes + (bit<32>)meta.scid_bytes + 1;
        meta.remaining = meta.remaining - (bit<32>)meta.scid_bytes - 1;
        meta.cid_known = true;
        verify(!meta.version_known || context.accept_zero_fixed_bit
               || hdr.common.version_specific[6:6] == 1, error.NoMatch);
        transition select(meta.version, hdr.common.version_specific[5:4]) {
            (QUIC_VERSION_NEGOTIATION, _): negotiation;
            (QUIC_VERSION_1, QUIC_V1_INITIAL): initial;
            (QUIC_VERSION_1, QUIC_V1_ZERO_RTT): zero_rtt;
            (QUIC_VERSION_1, QUIC_V1_HANDSHAKE): handshake;
            (QUIC_VERSION_1, QUIC_V1_RETRY): retry;
            (QUIC_VERSION_2, QUIC_V2_INITIAL): initial;
            (QUIC_VERSION_2, QUIC_V2_ZERO_RTT): zero_rtt;
            (QUIC_VERSION_2, QUIC_V2_HANDSHAKE): handshake;
            (QUIC_VERSION_2, QUIC_V2_RETRY): retry;
            default: opaque_body;
        }
    }

    state initial {
        meta.kind = quic_packet_kind_t.QUIC_INITIAL;
        integer.apply(pkt, hdr.token_length, meta.token_length, meta.remaining);
        meta.parsed_bytes = meta.parsed_bytes + (bit<32>)meta.token_length.encoded_bytes;
        meta.remaining = meta.remaining - (bit<32>)meta.token_length.encoded_bytes;
        verify(meta.remaining >= 21
               && meta.token_length.value <= (bit<62>)(meta.remaining - 21),
               error.HeaderTooShort);
        transition select(meta.token_length.value) {
            62w0 .. 62w65535: token;
            default: opaque_body;
        }
    }

    state token {
        pkt.extract(hdr.token, (bit<32>)meta.token_length.value * 8);
        meta.parsed_bytes = meta.parsed_bytes + (bit<32>)meta.token_length.value;
        meta.remaining = meta.remaining - (bit<32>)meta.token_length.value;
        transition packet_length;
    }

    state zero_rtt {
        meta.kind = quic_packet_kind_t.QUIC_ZERO_RTT;
        transition packet_length;
    }

    state handshake {
        meta.kind = quic_packet_kind_t.QUIC_HANDSHAKE;
        transition packet_length;
    }

    state packet_length {
        integer.apply(pkt, hdr.length, meta.length, meta.remaining);
        meta.parsed_bytes = meta.parsed_bytes + (bit<32>)meta.length.encoded_bytes;
        meta.remaining = meta.remaining - (bit<32>)meta.length.encoded_bytes;
        verify(meta.length.value >= 20 && meta.length.value <= (bit<62>)meta.remaining,
               error.HeaderTooShort);
        meta.packet_bytes = meta.parsed_bytes + (bit<32>)meta.length.value;
        meta.coalesced_bytes = meta.datagram_bytes - meta.packet_bytes;
        transition accept;
    }

    state negotiation {
        meta.kind = quic_packet_kind_t.QUIC_NEGOTIATION;
        verify(meta.remaining >= 4 && meta.remaining[1:0] == 0, error.NoMatch);
        meta.packet_bytes = meta.datagram_bytes;
        transition accept;
    }

    state retry {
        meta.kind = quic_packet_kind_t.QUIC_RETRY;
        verify(meta.remaining >= 17, error.HeaderTooShort);
        meta.packet_bytes = meta.datagram_bytes;
        transition accept;
    }

    state short_header {
        meta.kind = quic_packet_kind_t.QUIC_SHORT;
        meta.version = context.short_version;
        meta.version_known = context.short_context_known
                             && (meta.version == QUIC_VERSION_1
                                 || meta.version == QUIC_VERSION_2);
        transition select(meta.version_known) {
            true: short_cid;
            default: opaque_body;
        }
    }

    state short_cid {
        verify(context.accept_zero_fixed_bit
               || hdr.common.version_specific[6:6] == 1, error.NoMatch);
        verify(context.short_dcid_bytes <= QUIC_V1_V2_MAX_CID_BYTES, error.NoMatch);
        verify(meta.datagram_bytes >= 21
               && (bit<32>)context.short_dcid_bytes <= meta.remaining,
               error.HeaderTooShort);
        meta.dcid_bytes = context.short_dcid_bytes;
        pkt.extract(hdr.short_cid, (bit<32>)meta.dcid_bytes * 8);
        meta.parsed_bytes = meta.parsed_bytes + (bit<32>)meta.dcid_bytes;
        meta.remaining = meta.remaining - (bit<32>)meta.dcid_bytes;
        meta.cid_known = true;
        meta.packet_bytes = meta.datagram_bytes;
        transition accept;
    }

    state opaque_body {
        meta.opaque_body = true;
        transition accept;
    }
}

// Handler ports are local protocol owners, not forwarding destinations.
control quic_control(inout quic_headers_t hdr, in quic_metadata_t meta,
                      inout standard_metadata_t standard_metadata,
                      in bit<9> handler_port, in bit<9> opaque_port) {
    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.common.isValid()) {
            mark_to_drop(standard_metadata);
        } else if (meta.opaque_body) {
            standard_metadata.egress_spec = opaque_port;
        } else {
            standard_metadata.egress_spec = handler_port;
        }
    }
}
*/

#endif
