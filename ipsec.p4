#ifndef P4_PROTOCOL_HEADERS_IPSEC_P4
#define P4_PROTOCOL_HEADERS_IPSEC_P4

/**
 * AH (RFC 4302), ESP (RFC 4303) and IKEv2 (RFC 7296)
 * IPsec 报头、IKEv2 载荷链和本地分流示例
 * UDP encapsulation follows RFC 3948, IKEv2 fragments follow RFC 7383.
 */

const bit<8> IPSEC_AH_PROTOCOL = 51;
const bit<8> IPSEC_ESP_PROTOCOL = 50;
const bit<16> IKEV2_PORT = 500;
const bit<16> IPSEC_NAT_PORT = 4500;
const bit<4> IKEV2_MAJOR_VERSION = 2;
const bit<4> IKEV2_MINOR_VERSION = 0;
const bit<8> IKEV2_FLAG_INITIATOR = 0x08;
const bit<8> IKEV2_FLAG_VERSION = 0x10;
const bit<8> IKEV2_FLAG_RESPONSE = 0x20;

const bit<8> IKEV2_EXCHANGE_SA_INIT = 34;
const bit<8> IKEV2_EXCHANGE_AUTH = 35;
const bit<8> IKEV2_EXCHANGE_CREATE_CHILD_SA = 36;
const bit<8> IKEV2_EXCHANGE_INFORMATIONAL = 37;

/* RFC 7296 payload identifiers, plus the RFC 7383 fragment identifier.
 * Each identifier describes the following payload, not its own header.
 */
const bit<8> IKEV2_PAYLOAD_NONE = 0;
const bit<8> IKEV2_PAYLOAD_SA = 33;
const bit<8> IKEV2_PAYLOAD_KE = 34;
const bit<8> IKEV2_PAYLOAD_IDI = 35;
const bit<8> IKEV2_PAYLOAD_IDR = 36;
const bit<8> IKEV2_PAYLOAD_CERT = 37;
const bit<8> IKEV2_PAYLOAD_CERTREQ = 38;
const bit<8> IKEV2_PAYLOAD_AUTH = 39;
const bit<8> IKEV2_PAYLOAD_NONCE = 40;
const bit<8> IKEV2_PAYLOAD_NOTIFY = 41;
const bit<8> IKEV2_PAYLOAD_DELETE = 42;
const bit<8> IKEV2_PAYLOAD_VENDOR = 43;
const bit<8> IKEV2_PAYLOAD_TSI = 44;
const bit<8> IKEV2_PAYLOAD_TSR = 45;
const bit<8> IKEV2_PAYLOAD_SK = 46;
const bit<8> IKEV2_PAYLOAD_CP = 47;
const bit<8> IKEV2_PAYLOAD_EAP = 48;
const bit<8> IKEV2_PAYLOAD_SKF = 53;

/* Complete AH header: 12 fixed bytes followed by ICV and explicit padding.
 * Total bytes = (Payload Len + 2) * 4, up to 1028. IPv6 requires eight-byte
 * alignment. Reserved is zero on transmit and normally ignored on receive,
 * while still covered by the ICV. SPI zero is not transmitted, 1-255 are
 * reserved by IANA. Sequence Number carries the low 32 bits. With ESN the
 * high 32 bits come from the SA and are authenticated but not transmitted.
 */
header ipsec_ah_t {
    bit<8> next_header;
    bit<8> payload_length;
    bit<16> reserved;
    bit<32> spi;
    bit<32> sequence_number;
    varbit<8128> icv_and_padding;
}

/* ESP cleartext prefix, eight bytes. SPI and sequence rules match AH.
 * The SA determines the IV, cipher, ICV/tag and payload layout after it.
 */
header ipsec_esp_t {
    bit<32> spi;
    bit<32> sequence_number;
}

/* Final two bytes of the decrypted ESP trailer. Pad Length counts the
 * preceding 0-255 padding bytes. Next Header identifies the protected
 * payload, or 59 for a dummy packet. The ICV/tag follows the encrypted region.
 */
header ipsec_esp_trailer_t {
    bit<8> pad_length;
    bit<8> next_header;
}

/* UDP 4500 IKE prefix, four zero bytes. It is outside IKE Length. */
header ipsec_non_esp_marker_t {
    bit<32> marker;
}

/* UDP 4500 NAT keepalive is exactly one byte with value 0xff. */
header ipsec_nat_keepalive_t {
    bit<8> value;
}

/* IKEv2 fixed header, 28 bytes. Initiator SPI is nonzero. Responder SPI is
 * zero in the first initial-exchange request. Length counts this header and
 * every payload, excluding any Non-ESP Marker. Major Version = 2, Minor = 0
 * on transmit. Received Minor Version, V and reserved flags are ignored.
 * Flags I identifies the original initiator, R marks a response, V indicates
 * higher-version capability. Message ID and both SPIs need exchange state.
 */
header ikev2_t {
    bit<64> initiator_spi;
    bit<64> responder_spi;
    bit<8> next_payload;
    bit<4> major_version;
    bit<4> minor_version;
    bit<8> exchange_type;
    bit<8> flags;
    bit<32> message_id;
    bit<32> length;
}

/* Generic payload prefix, four bytes. Payload Length includes this prefix.
 * C applies to the current payload. Unsupported critical payloads require
 * owner processing. Reserved is zero on transmit and ignored on receive.
 */
header ikev2_payload_prefix_t {
    bit<8> next_payload;
    bit<1> critical;
    bit<7> reserved;
    bit<16> payload_length;
}

header ikev2_payload_t {
    bit<8> next_payload;
    bit<1> critical;
    bit<7> reserved;
    bit<16> payload_length;
    varbit<524248> value;
}

/* SKF cleartext prefix, eight bytes, replacing the generic prefix.
 * Fragment Number and Total Fragments are nonzero, Number <= Total.
 * Next Payload identifies the first inner payload in fragment 1 and is zero
 * in later fragments. Payload Length includes this prefix and encrypted data.
 */
header ikev2_fragment_prefix_t {
    bit<8> next_payload;
    bit<1> critical;
    bit<7> reserved;
    bit<16> payload_length;
    bit<16> fragment_number;
    bit<16> total_fragments;
}

enum bit<8> ipsec_transport {
    AH = 0,
    ESP = 1,
    IKE_UDP = 2,
    NAT_UDP = 3
};

enum bit<8> ipsec_packet_kind {
    AH = 0,
    ESP = 1,
    IKEV2 = 2,
    NAT_KEEPALIVE = 3
};

struct ipsec_headers_t {
    ipsec_non_esp_marker_t marker;
    ipsec_nat_keepalive_t keepalive;
    ipsec_ah_t ah;
    ipsec_esp_t esp;
    ikev2_t ike;
    ikev2_payload_t[8] payloads;
};

struct ipsec_metadata_t {
    ipsec_packet_kind packet_kind;
    bit<32> envelope_bytes;
    bit<32> header_bytes;
    bit<32> message_bytes;
    bit<32> remaining_bytes;
    bit<4> parsed_payloads;
    bit<8> next_payload;
    bit<8> encrypted_payload_type;
    bit<16> fragment_number;
    bit<16> total_fragments;
    bool outer_payloads_complete;
};

/**
 * Bounded parsing and local delivery example (P4_16, v1model).
 * The caller supplies the transport after validating IP/UDP lengths and
 * checksums and completing IP reassembly. outer_bytes excludes those headers
 * and link padding. is_ipv6 selects AH alignment. Native protocols are AH 51
 * and ESP 50. UDP 500 carries IKE, UDP 4500 carries marked IKE, ESP or a
 * one-byte NAT keepalive. A UDP datagram contains one complete IKE message.
 *
 * AH parsing retains the complete ICV area and leaves its protected payload
 * unchanged. ESP parsing extracts the cleartext prefix and retains the rest.
 * IKE parsing frames up to eight outer payloads. An unparsed remainder is
 * indicated by outer_payloads_complete = false. SK and SKF are last in the
 * outer chain. Their Next Payload refers to inner plaintext, so parsing
 * stops there and preserves their values, including IV, ciphertext and tag.
 *
 * context_id identifies a configured local endpoint. The handler selects the
 * SA using SPI and peer context, validates authentication and replay state,
 * decrypts content, checks critical payload support and handles IKE exchanges
 * and SKF reassembly. Received NAT keepalives are ignored. Emit marker,
 * keepalive, ah, esp, ike and payloads, then the untouched outer payload.
 */
/*
parser ipsec_parser(packet_in pkt, out ipsec_headers_t hdr,
                    out ipsec_metadata_t meta, in bit<32> outer_bytes,
                    in ipsec_transport transport, in bool is_ipv6) {
    bit<32> body_bytes;
    bit<32> remaining;
    bit<32> payload_bytes;
    bit<8> payload_type;

    state start {
        meta.packet_kind = ipsec_packet_kind.AH;
        meta.envelope_bytes = 0;
        meta.header_bytes = 0;
        meta.message_bytes = 0;
        meta.remaining_bytes = 0;
        meta.parsed_payloads = 0;
        meta.next_payload = 0;
        meta.encrypted_payload_type = 0;
        meta.fragment_number = 0;
        meta.total_fragments = 0;
        meta.outer_payloads_complete = false;
        body_bytes = outer_bytes;
        transition select(transport) {
            ipsec_transport.AH: parse_ah;
            ipsec_transport.ESP: parse_esp;
            ipsec_transport.IKE_UDP: parse_ike;
            ipsec_transport.NAT_UDP: classify_nat;
            default: unsupported;
        }
    }

    state unsupported {
        verify(false, error.NoMatch);
        transition accept;
    }

    state parse_ah {
        bit<16> prefix;
        verify(body_bytes >= 12, error.HeaderTooShort);
        prefix = pkt.lookahead<bit<16>>();
        meta.header_bytes = ((bit<32>)prefix[7:0] + 2) * 4;
        verify(meta.header_bytes >= 12, error.NoMatch);
        verify(meta.header_bytes <= body_bytes, error.HeaderTooShort);
        verify(!is_ipv6 || (meta.header_bytes & 7) == 0, error.NoMatch);
        pkt.extract(hdr.ah, (meta.header_bytes - 12) * 8);
        verify(hdr.ah.spi != 0, error.NoMatch);
        meta.message_bytes = body_bytes;
        meta.remaining_bytes = body_bytes - meta.header_bytes;
        transition accept;
    }

    state parse_esp {
        verify(body_bytes >= 8, error.HeaderTooShort);
        pkt.extract(hdr.esp);
        verify(hdr.esp.spi != 0, error.NoMatch);
        meta.packet_kind = ipsec_packet_kind.ESP;
        meta.header_bytes = 8;
        meta.message_bytes = body_bytes;
        meta.remaining_bytes = body_bytes - 8;
        transition accept;
    }

    state classify_nat {
        verify(body_bytes >= 1, error.HeaderTooShort);
        transition select(body_bytes) {
            1: parse_keepalive;
            default: classify_nat_prefix;
        }
    }

    state parse_keepalive {
        pkt.extract(hdr.keepalive);
        verify(hdr.keepalive.value == 0xff, error.NoMatch);
        meta.packet_kind = ipsec_packet_kind.NAT_KEEPALIVE;
        meta.header_bytes = 1;
        meta.message_bytes = 1;
        transition accept;
    }

    state classify_nat_prefix {
        verify(body_bytes >= 4, error.HeaderTooShort);
        transition select(pkt.lookahead<bit<32>>()) {
            0: parse_marker;
            default: parse_esp;
        }
    }

    state parse_marker {
        pkt.extract(hdr.marker);
        meta.envelope_bytes = 4;
        body_bytes = body_bytes - 4;
        transition parse_ike;
    }

    state parse_ike {
        verify(body_bytes >= 28, error.HeaderTooShort);
        pkt.extract(hdr.ike);
        verify(hdr.ike.major_version == IKEV2_MAJOR_VERSION
               && hdr.ike.initiator_spi != 0, error.NoMatch);
        verify(hdr.ike.length >= 28, error.HeaderTooShort);
        verify(hdr.ike.length == body_bytes, error.NoMatch);
        meta.packet_kind = ipsec_packet_kind.IKEV2;
        meta.header_bytes = 28;
        meta.message_bytes = hdr.ike.length;
        remaining = meta.message_bytes - 28;
        payload_type = hdr.ike.next_payload;
        transition check_payload;
    }

    state check_payload {
        meta.remaining_bytes = remaining;
        meta.next_payload = payload_type;
        verify(payload_type == IKEV2_PAYLOAD_NONE || remaining >= 4,
               error.HeaderTooShort);
        transition select(payload_type, meta.parsed_payloads) {
            (IKEV2_PAYLOAD_NONE, _): end_ike;
            (_, 8): accept;
            default: parse_payload;
        }
    }

    state end_ike {
        verify(remaining == 0, error.NoMatch);
        meta.outer_payloads_complete = true;
        transition accept;
    }

    state parse_payload {
        ikev2_payload_prefix_t prefix;
        prefix = pkt.lookahead<ikev2_payload_prefix_t>();
        payload_bytes = (bit<32>)prefix.payload_length;
        verify(payload_bytes >= 4, error.NoMatch);
        verify(payload_bytes <= remaining, error.HeaderTooShort);
        transition select(payload_type) {
            IKEV2_PAYLOAD_SK: check_encrypted;
            IKEV2_PAYLOAD_SKF: check_fragment;
            default: extract_payload;
        }
    }

    state check_fragment {
        ikev2_fragment_prefix_t prefix;
        verify(payload_bytes >= 8, error.HeaderTooShort);
        prefix = pkt.lookahead<ikev2_fragment_prefix_t>();
        verify(prefix.fragment_number != 0 && prefix.total_fragments != 0
               && prefix.fragment_number <= prefix.total_fragments,
               error.NoMatch);
        verify(prefix.fragment_number == 1 || prefix.next_payload == 0,
               error.NoMatch);
        meta.fragment_number = prefix.fragment_number;
        meta.total_fragments = prefix.total_fragments;
        transition check_encrypted;
    }

    state check_encrypted {
        verify(payload_bytes == remaining, error.NoMatch);
        pkt.extract(hdr.payloads.next, (payload_bytes - 4) * 8);
        meta.parsed_payloads = meta.parsed_payloads + 1;
        meta.encrypted_payload_type = payload_type;
        meta.next_payload = 0;
        meta.remaining_bytes = 0;
        meta.outer_payloads_complete = true;
        transition accept;
    }

    state extract_payload {
        pkt.extract(hdr.payloads.next, (payload_bytes - 4) * 8);
        remaining = remaining - payload_bytes;
        payload_type = hdr.payloads.last.next_payload;
        meta.parsed_payloads = meta.parsed_payloads + 1;
        transition check_payload;
    }
}

control ipsec_control(inout ipsec_headers_t hdr,
                      in ipsec_metadata_t meta,
                      inout standard_metadata_t standard_metadata,
                      in bit<32> context_id) {
    action deliver_ipsec(bit<9> handler_port) {
        standard_metadata.egress_spec = handler_port;
    }

    action drop_ipsec() {
        mark_to_drop(standard_metadata);
    }

    table ipsec_handlers {
        key = {
            context_id: exact;
            meta.packet_kind: exact;
        }
        actions = {
            deliver_ipsec;
            drop_ipsec;
        }
        default_action = drop_ipsec();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || meta.packet_kind == ipsec_packet_kind.NAT_KEEPALIVE
            || (!hdr.ah.isValid() && !hdr.esp.isValid() && !hdr.ike.isValid())) {
            mark_to_drop(standard_metadata);
        } else {
            ipsec_handlers.apply();
        }
    }
}
*/

#endif
