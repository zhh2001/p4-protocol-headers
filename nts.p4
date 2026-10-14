#ifndef P4_PROTOCOL_HEADERS_NTS_P4
#define P4_PROTOCOL_HEADERS_NTS_P4

#include "ntp.p4"

/**
 * Network Time Security (RFC 8915)
 * NTS-KE 记录与 NTPv4 安全扩展字段
 * NTS-KE uses TLS 1.3+ application data on TCP 4460 with ALPN "ntske/1".
 * NTPv4 uses negotiated UDP endpoints, with default server port 123.
 */

const bit<16> NTS_KE_TCP_PORT = 4460;
typedef bit<15> nts_ke_record_type_t;
const nts_ke_record_type_t NTS_KE_END = 0;
const nts_ke_record_type_t NTS_KE_NEXT_PROTOCOL = 1;
const nts_ke_record_type_t NTS_KE_ERROR = 2;
const nts_ke_record_type_t NTS_KE_WARNING = 3;
const nts_ke_record_type_t NTS_KE_AEAD = 4;
const nts_ke_record_type_t NTS_KE_COOKIE = 5;
const nts_ke_record_type_t NTS_KE_SERVER = 6;
const nts_ke_record_type_t NTS_KE_PORT = 7;

const bit<16> NTS_NEXT_PROTOCOL_NTPV4 = 0;
const bit<16> NTS_AEAD_AES_SIV_CMAC_256 = 15;
const bit<16> NTS_ERROR_UNKNOWN_CRITICAL = 0;
const bit<16> NTS_ERROR_BAD_REQUEST = 1;
const bit<16> NTS_ERROR_INTERNAL = 2;

const bit<16> NTS_EF_UNIQUE_IDENTIFIER = 0x0104;
const bit<16> NTS_EF_COOKIE = 0x0204;
const bit<16> NTS_EF_COOKIE_PLACEHOLDER = 0x0304;
const bit<16> NTS_EF_AUTHENTICATOR = 0x0404;
const bit<32> NTS_KOD_NTSN = 0x4E54534E;

/* NTS-KE record prefix, four bytes. C is the most significant bit.
 * Body Length counts only the body, which has no alignment requirement.
 * End of Message has C = 1, an empty body and is last in the message.
 * Next Protocol, Error and Warning require C = 1. AEAD permits either C.
 * Server/Port response records may be critical. New Cookie should be
 * noncritical. Types outside 0-7 are passed to the extension handler.
 */
header nts_ke_record_prefix_t {
    bit<1> critical;
    nts_ke_record_type_t record_type;
    bit<16> body_length;
}

header nts_ke_record_t {
    bit<1> critical;
    nts_ke_record_type_t record_type;
    bit<16> body_length;
    varbit<524280> body;
}

/* Two-byte values within record bodies. Next Protocol and AEAD contain
 * lists of these values. Error, Warning and Port contain exactly one.
 * The containing record supplies the meaning and number of entries.
 */
header nts_ke_value_t {
    bit<16> value;
}

/* NTP extension prefix. Length includes prefix, value and padding, and
 * is a multiple of four. ntp_extension supplies the complete generic field.
 * Unique Identifier values have at least 32 bytes. Cookies are opaque,
 * implementation-defined values. Placeholder bodies match the cookie size,
 * should be zero-filled and are otherwise ignored by the server.
 * A returned cookie is inside the authenticated ciphertext of the response.
 */
header nts_extension_prefix_t {
    bit<16> field_type;
    bit<16> length;
}

typedef ntp_extension nts_cookie_t;

/* Authenticator prefix, eight bytes including the NTP extension prefix.
 * Nonce Length and Ciphertext Length exclude their separate zero-padding
 * to four-byte boundaries. Additional zero-padding can follow ciphertext.
 * The AEAD algorithm defines the ciphertext, including its authentication
 * tag. padded_value retains nonce, ciphertext and every padding region.
 */
header nts_authenticator_prefix_t {
    bit<16> field_type;
    bit<16> length;
    bit<16> nonce_length;
    bit<16> ciphertext_length;
}

header nts_authenticator_t {
    bit<16> field_type;
    bit<16> length;
    bit<16> nonce_length;
    bit<16> ciphertext_length;
    varbit<524192> padded_value;
}

enum bit<8> nts_message_kind {
    KEY_ESTABLISHMENT = 0,
    NTPV4 = 1
};

struct nts_headers_t {
    ntp_header ntp;
    nts_ke_record_t[16] ke_records;
    ntp_extension[12] extensions;
    nts_authenticator_t authenticator;
}

struct nts_metadata_t {
    nts_message_kind kind;
    bit<32> remaining_bytes;
    bool framing_complete;
    bit<5> parsed_records;
    bool non_base_critical;
    bit<4> parsed_extensions;
    bit<4> unique_identifiers;
    bit<4> clear_cookies;
    bit<4> clear_placeholders;
    bool authenticator_present;
    bit<32> associated_data_bytes;
    bit<32> authenticator_offset;
    bit<32> nonce_offset;
    bit<32> ciphertext_offset;
    bit<32> nonce_padded_bytes;
    bit<32> ciphertext_padded_bytes;
    bit<32> additional_padding_bytes;
    bool nts_nak;
}

/**
 * Bounded framing and local delivery (P4_16, v1model).
 * The caller supplies the message kind and its validated byte count.
 * KEY_ESTABLISHMENT receives a complete NTS-KE message from the TLS owner
 * after decryption and stream reassembly. NTPV4 starts at the NTP header in
 * a complete UDP payload. The caller validates transport bounds, checksums
 * and reassembly. message_bytes excludes transport headers and link padding.
 *
 * Up to 16 KE records or 12 clear NTP extensions are framed. If the limit
 * is reached, remaining_bytes identifies the untouched remainder and
 * framing_complete is false. KE End of Message is checked when reached.
 * NTP parsing stops after the first Authenticator. Nonce/ciphertext offsets
 * are relative to the NTP header. associated_data_bytes ends just before the
 * Authenticator prefix. remaining_bytes then counts the untrusted tail.
 * Emit ntp, ke_records, extensions and authenticator, then the remainder.
 *
 * context_id selects the TLS session or NTP association handler. KE handlers
 * process record roles, cardinality, critical types and negotiation. NTP
 * handlers validate required fields, UID, cookie/placeholder lengths, nonce
 * and padding, authenticate with the negotiated AEAD and direction key,
 * and parse encrypted fields.
 * They discard the untrusted tail and enforce the absence of a traditional
 * NTP MAC. Replies, key export, NTS NAKs and time samples use handler state.
 */
/*
parser nts_parser(packet_in pkt, out nts_headers_t hdr,
                  out nts_metadata_t meta, in bit<32> message_bytes,
                  in nts_message_kind kind) {
    bit<32> remaining;
    bit<32> field_bytes;
    bit<32> consumed;

    state start {
        meta.kind = kind;
        meta.remaining_bytes = message_bytes;
        meta.framing_complete = false;
        meta.parsed_records = 0;
        meta.non_base_critical = false;
        meta.parsed_extensions = 0;
        meta.unique_identifiers = 0;
        meta.clear_cookies = 0;
        meta.clear_placeholders = 0;
        meta.authenticator_present = false;
        meta.associated_data_bytes = 0;
        meta.authenticator_offset = 0;
        meta.nonce_offset = 0;
        meta.ciphertext_offset = 0;
        meta.nonce_padded_bytes = 0;
        meta.ciphertext_padded_bytes = 0;
        meta.additional_padding_bytes = 0;
        meta.nts_nak = false;
        remaining = message_bytes;
        consumed = 0;
        transition select(kind) {
            nts_message_kind.KEY_ESTABLISHMENT: check_ke_record;
            nts_message_kind.NTPV4: parse_ntp;
            default: unsupported;
        }
    }

    state unsupported {
        verify(false, error.NoMatch);
        transition accept;
    }

    state check_ke_record {
        meta.remaining_bytes = remaining;
        verify(remaining >= 4, error.HeaderTooShort);
        transition select(meta.parsed_records) {
            16: accept;
            default: parse_ke_record;
        }
    }

    state parse_ke_record {
        nts_ke_record_prefix_t prefix;
        prefix = pkt.lookahead<nts_ke_record_prefix_t>();
        field_bytes = 4 + (bit<32>)prefix.body_length;
        verify(field_bytes <= remaining, error.HeaderTooShort);
        verify(prefix.record_type > NTS_KE_WARNING || prefix.critical == 1,
               error.NoMatch);
        verify((prefix.record_type != NTS_KE_NEXT_PROTOCOL
                && prefix.record_type != NTS_KE_AEAD)
               || (prefix.body_length & 1) == 0, error.NoMatch);
        verify((prefix.record_type != NTS_KE_ERROR
                && prefix.record_type != NTS_KE_WARNING
                && prefix.record_type != NTS_KE_PORT)
               || prefix.body_length == 2, error.NoMatch);
        transition select(prefix.record_type) {
            NTS_KE_END: end_ke;
            default: extract_ke_record;
        }
    }

    state end_ke {
        verify(field_bytes == 4 && remaining == 4, error.NoMatch);
        pkt.extract(hdr.ke_records.next, 0);
        meta.parsed_records = meta.parsed_records + 1;
        meta.remaining_bytes = 0;
        meta.framing_complete = true;
        transition accept;
    }

    state extract_ke_record {
        pkt.extract(hdr.ke_records.next, (field_bytes - 4) * 8);
        if (hdr.ke_records.last.record_type > NTS_KE_PORT
            && hdr.ke_records.last.critical == 1) {
            meta.non_base_critical = true;
        }
        meta.parsed_records = meta.parsed_records + 1;
        remaining = remaining - field_bytes;
        transition check_ke_record;
    }

    state parse_ntp {
        verify(remaining >= 48, error.HeaderTooShort);
        pkt.extract(hdr.ntp);
        verify(hdr.ntp.version == 4
               && (hdr.ntp.mode == 3 || hdr.ntp.mode == 4), error.NoMatch);
        meta.nts_nak = hdr.ntp.mode == 4 && hdr.ntp.stratum == 0
                       && hdr.ntp.reference_id == NTS_KOD_NTSN;
        remaining = remaining - 48;
        consumed = 48;
        transition check_extension;
    }

    state check_extension {
        meta.remaining_bytes = remaining;
        transition select(remaining, meta.parsed_extensions) {
            (0, _): end_ntp;
            (_, 12): accept;
            default: parse_extension;
        }
    }

    state end_ntp {
        meta.framing_complete = true;
        transition accept;
    }

    state parse_extension {
        nts_extension_prefix_t prefix;
        verify(remaining >= 4, error.HeaderTooShort);
        prefix = pkt.lookahead<nts_extension_prefix_t>();
        field_bytes = (bit<32>)prefix.length;
        verify(field_bytes >= 16 && (field_bytes & 3) == 0, error.NoMatch);
        verify(field_bytes <= remaining, error.HeaderTooShort);
        verify(field_bytes != remaining || field_bytes >= 28, error.NoMatch);
        transition select(prefix.field_type) {
            NTS_EF_AUTHENTICATOR: parse_authenticator;
            NTS_EF_UNIQUE_IDENTIFIER: check_identifier;
            NTS_EF_COOKIE_PLACEHOLDER: check_placeholder;
            default: extract_extension;
        }
    }

    state check_identifier {
        verify(field_bytes >= 36, error.HeaderTooShort);
        meta.unique_identifiers = meta.unique_identifiers + 1;
        transition extract_extension;
    }

    state check_placeholder {
        verify(hdr.ntp.mode == 3, error.NoMatch);
        meta.clear_placeholders = meta.clear_placeholders + 1;
        transition extract_extension;
    }

    state extract_extension {
        pkt.extract(hdr.extensions.next, (field_bytes - 4) * 8);
        if (hdr.extensions.last.field_type == NTS_EF_COOKIE) {
            meta.clear_cookies = meta.clear_cookies + 1;
        }
        meta.parsed_extensions = meta.parsed_extensions + 1;
        remaining = remaining - field_bytes;
        consumed = consumed + field_bytes;
        transition check_extension;
    }

    state parse_authenticator {
        nts_authenticator_prefix_t prefix;
        prefix = pkt.lookahead<nts_authenticator_prefix_t>();
        meta.nonce_padded_bytes = ((bit<32>)prefix.nonce_length + 3) & 0xFFFFFFFC;
        meta.ciphertext_padded_bytes = ((bit<32>)prefix.ciphertext_length + 3)
                                       & 0xFFFFFFFC;
        verify(8 + meta.nonce_padded_bytes + meta.ciphertext_padded_bytes
               <= field_bytes, error.HeaderTooShort);
        meta.additional_padding_bytes = field_bytes - 8 - meta.nonce_padded_bytes
                                        - meta.ciphertext_padded_bytes;
        pkt.extract(hdr.authenticator, (field_bytes - 8) * 8);
        meta.authenticator_present = true;
        meta.authenticator_offset = consumed;
        meta.associated_data_bytes = consumed;
        meta.nonce_offset = consumed + 8;
        meta.ciphertext_offset = meta.nonce_offset + meta.nonce_padded_bytes;
        meta.remaining_bytes = remaining - field_bytes;
        meta.framing_complete = true;
        transition accept;
    }
}

control nts_control(inout nts_headers_t hdr, in nts_metadata_t meta,
                    inout standard_metadata_t standard_metadata,
                    in bit<32> context_id) {
    action deliver_nts(bit<9> handler_port) {
        standard_metadata.egress_spec = handler_port;
    }

    action drop_nts() {
        mark_to_drop(standard_metadata);
    }

    table nts_handlers {
        key = {
            context_id: exact;
            meta.kind: exact;
        }
        actions = {
            deliver_nts;
            drop_nts;
        }
        default_action = drop_nts();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError) {
            drop_nts();
        } else {
            nts_handlers.apply();
        }
    }
}
*/

#endif
