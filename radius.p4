#ifndef P4_PROTOCOL_HEADERS_RADIUS_P4
#define P4_PROTOCOL_HEADERS_RADIUS_P4

/**
 * RADIUS packet and attribute formats (RFC 2865, RFC 6929, RFC 9765)
 * RADIUS 固定报头、顶层属性与有界解析示例
 */
const bit<16> RADIUS_AUTH_PORT = 1812;
const bit<16> RADIUS_ACCOUNTING_PORT = 1813;
const bit<16> RADIUS_DYNAMIC_AUTH_PORT = 3799;
const bit<16> RADIUS_TLS_PORT = 2083;
const bit<16> RADIUS_PACKET_MIN_LENGTH = 20;
const bit<16> RADIUS_PACKET_MAX_LENGTH = 4096;
const bit<16> RADIUS_ACCOUNTING_MAX_LENGTH = 4095; // RFC 2866, Section 3
const bit<16> RADIUS_LARGE_PACKET_MAX_LENGTH = 65535; // RFC 7930

// Selected registered packet and attribute codes. Other values stay opaque.
enum bit<8> radius_code {
    ACCESS_REQUEST = 1,
    ACCESS_ACCEPT = 2,
    ACCESS_REJECT = 3,
    ACCOUNTING_REQUEST = 4,
    ACCOUNTING_RESPONSE = 5,
    ACCESS_CHALLENGE = 11,
    STATUS_SERVER = 12,
    DISCONNECT_REQUEST = 40,
    DISCONNECT_ACK = 41,
    DISCONNECT_NAK = 42,
    COA_REQUEST = 43,
    COA_ACK = 44,
    COA_NAK = 45,
    PROTOCOL_ERROR = 52
}

enum bit<8> radius_attr {
    USER_NAME = 1,
    USER_PASSWORD = 2,
    CHAP_PASSWORD = 3,
    NAS_IP_ADDRESS = 4,
    NAS_PORT = 5,
    FRAMED_IP_ADDRESS = 8,
    REPLY_MESSAGE = 18,
    STATE = 24,
    CLASS = 25,
    VENDOR_SPECIFIC = 26,
    PROXY_STATE = 33,
    ACCT_STATUS_TYPE = 40,
    ACCT_SESSION_ID = 44,
    EAP_MESSAGE = 79,
    MESSAGE_AUTHENTICATOR = 80,
    EXTENDED_1 = 241,
    EXTENDED_2 = 242,
    EXTENDED_3 = 243,
    EXTENDED_4 = 244,
    LONG_EXTENDED_1 = 245,
    LONG_EXTENDED_2 = 246
}

/* Classic packet header, 20 bytes. Length includes this header and all
 * attributes. Identifier matches a response to its request. Authenticator
 * interpretation depends on the packet Code and request/response role.
 * Attributes follow the fixed header and have no alignment padding.
 */
header radius {
    bit<8> code;
    bit<8> identifier;
    bit<16> length;
    bit<128> authenticator;
}

/* RADIUS/1.1 header, 20 bytes (RFC 9765, Experimental).
 * Use only after ALPN "radius/1.1" negotiation over TLS/DTLS 1.3+.
 * Token is an opaque request/response key. Both reserved fields are sent
 * as zero and ignored on reception. There is no RADIUS Authenticator.
 */
header radius_1_1_t {
    bit<8> code;
    bit<8> reserved1;
    bit<16> length;
    bit<32> token;
    bit<96> reserved2;
}

/* Generic top-level attribute. Length includes Type, Length and Value,
 * so framing permits 2..255 bytes. Each attribute definition determines
 * its minimum value length and encoding. Strings have no NUL terminator.
 * RFC 6929 extensions retain this outer prefix. The value is kept intact,
 * including Extended-Type, flags, vendor fields or nested TLVs.
 */
header radius_attribute_prefix_t {
    bit<8> type;
    bit<8> length;
}

header radius_attribute_t {
    bit<8> type;
    bit<8> length;
    varbit<2024> value;
}

// IPv4 address attributes such as NAS-IP-Address have Length = 6.
header radius_ipv4_attribute_t {
    bit<8> type;
    bit<8> length;
    bit<32> address;
}

// Message-Authenticator (80) has Length = 18 and a 16-byte HMAC-MD5 value.
// It is not sent, and is ignored on reception, in the RADIUS/1.1 profile.
header radius_message_authenticator_t {
    bit<8> type;
    bit<8> length;
    bit<128> authenticator;
}

/* Vendor-Specific (26), Length >= 7. Vendor-Id is the full 32-bit PEN
 * (RFC 6929, Section 2.4). Vendor data can have its own internal format.
 */
header radius_vendor_attribute_t {
    bit<8> type;
    bit<8> length;
    bit<32> vendor_id;
    varbit<1992> vendor_data;
}

// Extended attributes (241..244), Length >= 4, one-byte Extended-Type.
header radius_extended_attribute_t {
    bit<8> type;
    bit<8> length;
    bit<8> extended_type;
    varbit<2016> value;
}

/* Long Extended attributes (245..246), Length >= 5. M indicates another
 * fragment of the same attribute and requires Length = 255 when set.
 * The seven reserved bits are sent as zero and ignored on reception.
 * Interpret value after fragment reassembly (RFC 6929, Section 2.2).
 */
header radius_long_extended_attribute_t {
    bit<8> type;
    bit<8> length;
    bit<8> extended_type;
    bit<1> more;
    bit<7> reserved;
    varbit<2008> value;
}

/* Extended-Type 26 carries an EVS value with this five-byte prefix.
 * It has no Vendor-Length. In a long attribute, the prefix occurs only
 * at the start of the value and can be read after fragment reassembly.
 */
header radius_evs_value_prefix_t {
    bit<32> vendor_id;
    bit<8> vendor_type;
}

enum bit<8> radius_format {
    CLASSIC = 0,
    RADIUS_1_1 = 1
}

struct radius_headers_t {
    radius base;
    radius_1_1_t base_1_1;
    radius_attribute_t[16] attributes;
}

struct radius_metadata_t {
    radius_format format;
    bit<8> code;
    bit<32> message_id;
    bit<16> packet_bytes;
    bit<16> remaining_bytes;
    bit<32> trailing_bytes;
    bit<5> parsed_attributes;
    bool framing_complete;
    bool eap_present;
    bit<5> message_authenticators;
    bit<16> first_message_authenticator_offset;
}

/**
 * Bounded parsing and local delivery (P4_16, v1model).
 * The cursor starts at a complete RADIUS packet. payload_bytes is the
 * validated transport payload size, excluding transport headers and link
 * padding. TCP/TLS/DTLS owners supply reassembled, decrypted packet data.
 * The caller selects format from configuration or ALPN, and maximum_length
 * from the transport profile: 4096 for RFC 2865, 4095 for classic RFC 2866
 * Accounting, or up to 65535 for RFC 7930 large packets. Stream framing
 * supplies exactly one packet. UDP octets beyond Length are padding,
 * counted in trailing_bytes.
 *
 * Up to 16 attributes are extracted. framing_complete marks the end of the
 * declared packet. At the limit, remaining_bytes counts unparsed attributes.
 * Emit base, base_1_1 and attributes, followed by the original remainder.
 *
 * context_id identifies the peer or secure session. Its handler validates
 * packet codes, roles, attribute values and cardinality, reassembles EAP and
 * long attributes, and checks classic authenticators and password encoding.
 * RADIUS/1.1 handlers use Token and the TLS state. Unknown attributes and
 * RFC 6929 invalid attributes are handled there without altering their bytes.
 */
/*
parser radius_parser(packet_in pkt, out radius_headers_t hdr,
                     out radius_metadata_t meta, in bit<32> payload_bytes,
                     in bit<16> maximum_length, in radius_format format) {
    bit<16> remaining;
    bit<16> consumed;

    state start {
        meta.format = format;
        meta.code = 0;
        meta.message_id = 0;
        meta.packet_bytes = 0;
        meta.remaining_bytes = 0;
        meta.trailing_bytes = 0;
        meta.parsed_attributes = 0;
        meta.framing_complete = false;
        meta.eap_present = false;
        meta.message_authenticators = 0;
        meta.first_message_authenticator_offset = 0;
        verify(payload_bytes >= (bit<32>)RADIUS_PACKET_MIN_LENGTH,
               error.HeaderTooShort);
        verify(maximum_length >= RADIUS_PACKET_MIN_LENGTH, error.NoMatch);
        transition select(format) {
            radius_format.CLASSIC: parse_classic;
            radius_format.RADIUS_1_1: parse_1_1;
            default: unsupported;
        }
    }

    state unsupported {
        verify(false, error.NoMatch);
        transition accept;
    }

    state parse_classic {
        pkt.extract(hdr.base);
        meta.code = hdr.base.code;
        meta.message_id = (bit<32>)hdr.base.identifier;
        meta.packet_bytes = hdr.base.length;
        transition check_packet;
    }

    state parse_1_1 {
        pkt.extract(hdr.base_1_1);
        meta.code = hdr.base_1_1.code;
        meta.message_id = hdr.base_1_1.token;
        meta.packet_bytes = hdr.base_1_1.length;
        transition check_packet;
    }

    state check_packet {
        verify(meta.packet_bytes >= RADIUS_PACKET_MIN_LENGTH
               && meta.packet_bytes <= maximum_length, error.NoMatch);
        verify((bit<32>)meta.packet_bytes <= payload_bytes, error.HeaderTooShort);
        remaining = meta.packet_bytes - RADIUS_PACKET_MIN_LENGTH;
        consumed = RADIUS_PACKET_MIN_LENGTH;
        meta.trailing_bytes = payload_bytes - (bit<32>)meta.packet_bytes;
        transition check_attribute;
    }

    state check_attribute {
        meta.remaining_bytes = remaining;
        transition select(remaining, meta.parsed_attributes) {
            (0, _): end_packet;
            (_, 16): accept;
            default: parse_attribute;
        }
    }

    state end_packet {
        meta.framing_complete = true;
        transition accept;
    }

    state parse_attribute {
        radius_attribute_prefix_t prefix;
        verify(remaining >= 2, error.HeaderTooShort);
        prefix = pkt.lookahead<radius_attribute_prefix_t>();
        verify(prefix.length >= 2, error.NoMatch);
        verify((bit<16>)prefix.length <= remaining, error.HeaderTooShort);
        pkt.extract(hdr.attributes.next, ((bit<32>)prefix.length - 2) * 8);
        if (prefix.type == radius_attr.EAP_MESSAGE) {
            meta.eap_present = true;
        }
        if (prefix.type == radius_attr.MESSAGE_AUTHENTICATOR) {
            if (meta.message_authenticators == 0) {
                meta.first_message_authenticator_offset = consumed;
            }
            meta.message_authenticators = meta.message_authenticators + 1;
        }
        meta.parsed_attributes = meta.parsed_attributes + 1;
        remaining = remaining - (bit<16>)prefix.length;
        consumed = consumed + (bit<16>)prefix.length;
        transition check_attribute;
    }
}

control radius_control(inout radius_headers_t hdr, in radius_metadata_t meta,
                       inout standard_metadata_t standard_metadata,
                       in bit<32> context_id) {
    action deliver_radius(bit<9> handler_port) {
        standard_metadata.egress_spec = handler_port;
    }

    action drop_radius() {
        mark_to_drop(standard_metadata);
    }

    table radius_handlers {
        key = {
            context_id: exact;
            meta.format: exact;
            meta.code: exact;
        }
        actions = {
            deliver_radius;
            drop_radius;
        }
        default_action = drop_radius();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError) {
            drop_radius();
        } else {
            radius_handlers.apply();
        }
    }
}
*/

#endif
