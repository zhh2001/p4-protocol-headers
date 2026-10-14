#ifndef P4_PROTOCOL_HEADERS_CAPWAP_P4
#define P4_PROTOCOL_HEADERS_CAPWAP_P4

/**
 * Control And Provisioning of Wireless Access Points (RFC 5415)
 * CAPWAP 传输头、控制消息、数据保活和有界解析示例
 * IEEE 802.11 binding fields are defined by RFC 5416.
 */

typedef bit<32> capwap_message_type_t;

const bit<4> CAPWAP_VERSION = 0;
const bit<4> CAPWAP_PREAMBLE_HEADER = 0;
const bit<4> CAPWAP_PREAMBLE_DTLS = 1;
const bit<16> CAPWAP_CONTROL_PORT = 5246;
const bit<16> CAPWAP_DATA_PORT = 5247;
const bit<5> CAPWAP_WBID_IEEE80211 = 1;
const bit<5> CAPWAP_WBID_EPCGLOBAL = 3;

/* Base control message types. Odd values are requests, even values responses.
 * The high 24 bits identify an enterprise, the low eight its message type.
 * Enterprise zero is the base protocol. IEEE 802.11 uses enterprise 13277.
 */
const capwap_message_type_t CAPWAP_DISCOVERY_REQUEST = 1;
const capwap_message_type_t CAPWAP_DISCOVERY_RESPONSE = 2;
const capwap_message_type_t CAPWAP_JOIN_REQUEST = 3;
const capwap_message_type_t CAPWAP_JOIN_RESPONSE = 4;
const capwap_message_type_t CAPWAP_CONFIGURATION_STATUS_REQUEST = 5;
const capwap_message_type_t CAPWAP_CONFIGURATION_STATUS_RESPONSE = 6;
const capwap_message_type_t CAPWAP_CONFIGURATION_UPDATE_REQUEST = 7;
const capwap_message_type_t CAPWAP_CONFIGURATION_UPDATE_RESPONSE = 8;
const capwap_message_type_t CAPWAP_WTP_EVENT_REQUEST = 9;
const capwap_message_type_t CAPWAP_WTP_EVENT_RESPONSE = 10;
const capwap_message_type_t CAPWAP_CHANGE_STATE_EVENT_REQUEST = 11;
const capwap_message_type_t CAPWAP_CHANGE_STATE_EVENT_RESPONSE = 12;
const capwap_message_type_t CAPWAP_ECHO_REQUEST = 13;
const capwap_message_type_t CAPWAP_ECHO_RESPONSE = 14;
const capwap_message_type_t CAPWAP_IMAGE_DATA_REQUEST = 15;
const capwap_message_type_t CAPWAP_IMAGE_DATA_RESPONSE = 16;
const capwap_message_type_t CAPWAP_RESET_REQUEST = 17;
const capwap_message_type_t CAPWAP_RESET_RESPONSE = 18;
const capwap_message_type_t CAPWAP_PRIMARY_DISCOVERY_REQUEST = 19;
const capwap_message_type_t CAPWAP_PRIMARY_DISCOVERY_RESPONSE = 20;
const capwap_message_type_t CAPWAP_DATA_TRANSFER_REQUEST = 21;
const capwap_message_type_t CAPWAP_DATA_TRANSFER_RESPONSE = 22;
const capwap_message_type_t CAPWAP_CLEAR_CONFIGURATION_REQUEST = 23;
const capwap_message_type_t CAPWAP_CLEAR_CONFIGURATION_RESPONSE = 24;
const capwap_message_type_t CAPWAP_STATION_CONFIGURATION_REQUEST = 25;
const capwap_message_type_t CAPWAP_STATION_CONFIGURATION_RESPONSE = 26;
const capwap_message_type_t CAPWAP_DOT11_WLAN_CONFIGURATION_REQUEST = 3398913;
const capwap_message_type_t CAPWAP_DOT11_WLAN_CONFIGURATION_RESPONSE = 3398914;

const bit<16> CAPWAP_ELEMENT_SESSION_ID = 35;
const bit<16> CAPWAP_SESSION_ID_BYTES = 16;

/* Both transport forms start with this one-byte preamble. */
header capwap_preamble_t {
    bit<4> version;
    bit<4> type;
}

/* Complete DTLS wrapper (four bytes), replacing the ordinary CAPWAP header.
 * Type = 1. Reserved is zero on transmit and ignored on receipt.
 * The DTLS record immediately follows. This is not a DTLS record header.
 */
header capwap_dtls_t {
    bit<4> version;
    bit<4> type;
    bit<24> reserved;
}

/* Fixed common transport header (eight bytes), Type = 0.
 * HLEN includes the optional fields and is in four-byte words, 2-31.
 * RID identifies a radio (1-31) where applicable. Keepalives use zero.
 * T = 0 carries an IEEE 802.3 frame, T = 1 a native WBID frame.
 * F marks fragments. L and Fragment Offset are meaningful only with F = 1.
 * Fragment Offset is in eight-byte units. Fragment ID is per direction and
 * WTP/AC pair. Reassembly must reject overlapping fragments.
 * W and M indicate Wireless Specific Information and Radio MAC Address.
 * K indicates a data-channel keepalive, not an ordinary data frame.
 * Flags and Reserved are zero on transmit and ignored on receipt.
 */
header capwap_t {
    bit<4> version;
    bit<4> type;
    bit<5> hlen;
    bit<5> radio_id;
    bit<5> wireless_binding_id;
    bit<1> native_frame;
    bit<1> fragment;
    bit<1> last_fragment;
    bit<1> wireless_info_present;
    bit<1> radio_mac_present;
    bit<1> keepalive;
    bit<3> flags;
    bit<16> fragment_id;
    bit<13> fragment_offset;
    bit<3> reserved;
}

/* M optional field. Length counts only the EUI-48/EUI-64 address (6/8).
 * The complete field is rounded up to four bytes with zero transmit padding.
 * The raw data includes the address and one/three alignment bytes.
 */
header capwap_radio_mac_t {
    bit<8> length;
    varbit<88> address_and_padding;
}

/* W optional field follows M. Length counts only binding data, not padding.
 * The complete field is rounded up to four bytes with zero transmit padding.
 * The one-byte length allows 255 data bytes. HLEN further limits space in
 * an actual transport header. Received data and padding remain unchanged.
 */
header capwap_wireless_info_t {
    bit<8> length;
    varbit<2040> data_and_padding;
}

/* Value-only RFC 5416 alternatives for Wireless Specific Information.
 * The sender's direction, not WBID alone, selects the value format.
 * WTP -> AC: RSSI in dBm, SNR in dB, Data Rate in units of 0.1 Mbps.
 */
header capwap_dot11_frame_info_t {
    int<8> rssi;
    int<8> snr;
    bit<16> data_rate;
}

/* AC -> WTP: broadcast/multicast destination WLANs, WLAN 1 at the least
 * significant bit and WLAN 16 at the most significant bit. Reserved is
 * zero on transmit and ignored on receipt. Unicast uses a zero bitmap.
 * The bitmap is unused when the WTP does not provide IEEE 802.11 encryption.
 */
header capwap_dot11_destination_wlans_t {
    bit<16> wlan_bitmap;
    bit<16> reserved;
}

/* Complete fixed control header (eight bytes), after the transport header.
 * Message Element Length counts all bytes after Sequence Number, including
 * its own two bytes and Flags. Minimum = 3, total control bytes = 5 + length.
 * Sequence Number matches requests/responses and wraps after 255.
 * Flags is zero on transmit. The owner checks control-message semantics.
 */
header capwap_control_t {
    capwap_message_type_t message_type;
    bit<8> sequence_number;
    bit<16> message_element_length;
    bit<8> flags;
}

/* K = 1 data-channel payload prefix. Length includes its own two bytes and
 * all message elements, minimum 2. A Session ID element is mandatory.
 * A transmitted keepalive sets all common header fields to zero except HLEN
 * and K. Binding, session checks and identical replies belong to the owner.
 */
header capwap_keepalive_t {
    bit<16> message_element_length;
}

/* Generic message elements have no alignment padding. Length counts only
 * Value. Element-specific lengths, mandatory elements and nested/vendor
 * data are checked by the owner, including unrecognized-element responses.
 */
header capwap_message_element_prefix_t {
    bit<16> type;
    bit<16> length;
}

header capwap_message_element_t {
    bit<16> type;
    bit<16> length;
    varbit<524280> value;
}

/* Complete Session ID element, replacing the generic element. Type = 35,
 * Length = 16. Session ID is a randomly generated 128-bit value.
 */
header capwap_session_id_element_t {
    bit<16> type;
    bit<16> length;
    bit<128> session_id;
}

/* Raw storage for any residual bytes within HLEN, not another wire field.
 * The owner validates these bytes. The fixed header leaves at most 116 bytes.
 */
header capwap_header_tail_t {
    varbit<928> data;
}

enum bit<8> capwap_packet_kind {
    DTLS = 0,
    FRAGMENT = 1,
    CONTROL = 2,
    KEEPALIVE = 3,
    DATA = 4
};

struct capwap_headers_t {
    capwap_dtls_t dtls;
    capwap_t base;
    capwap_radio_mac_t radio_mac;
    capwap_wireless_info_t wireless_info;
    capwap_header_tail_t header_tail;
    capwap_control_t control_message;
    capwap_keepalive_t keepalive;
    capwap_message_element_t[8] elements;
};

struct capwap_metadata_t {
    capwap_packet_kind packet_kind;
    bit<32> header_bytes;
    bit<32> header_tail_bytes;
    bit<32> payload_bytes;
    bit<32> message_bytes;
    bit<32> element_bytes;
    bit<32> unparsed_element_bytes;
    bit<32> outer_trailing_bytes;
    bit<4> parsed_elements;
    bool elements_complete;
};

/**
 * Bounded parsing and local delivery example (P4_16, v1model).
 * The cursor points to a complete CAPWAP transport payload. outer_bytes
 * excludes UDP/UDP-Lite, IP headers and link padding. The caller validates
 * enclosing lengths/checksums, performs IP reassembly, and supplies the
 * configured control/data channel. The AC defaults to ports 5246/5247 but
 * these can be configured and WTP ports can differ. UDP-Lite is also defined
 * by RFC 5415, with checksum coverage of the eight-byte transport header.
 *
 * authenticated_plaintext is trusted context from the DTLS owner, not a
 * received flag. It is true only for authenticated, decrypted inner CAPWAP
 * with the matching outer/inner preamble version. Otherwise cleartext control
 * permits only Discovery Request/Response. DTLS wrappers and all CAPWAP
 * fragments are delivered intact without interpreting the encrypted or
 * fragmented payload, even when Fragment Offset = 0. The reassembly owner
 * checks offsets, overlap, endpoints, fragment IDs and completion before
 * parsing an assembled message. Channel, authentication and binding policy
 * remain applicable after reassembly.
 *
 * The parser handles M before W and bounds each aligned field by HLEN.
 * Control and keepalive message lengths bound a shared loop of eight TLVs.
 * Further elements stay in the unextracted payload. elements_complete is
 * false until every element has been framed. The owner must validate the
 * remainder, message types/flags, required elements and Session ID before
 * acting on a message. An empty keepalive TLV area is only a framing result,
 * not a valid session keepalive. Unknown types and values remain available
 * for protocol-specific validation. Raw header tails also need validation.
 *
 * Ordinary data starts immediately after HLEN, with no extra data header.
 * Data frames, encrypted records, fragment payloads, unparsed elements and
 * bytes outside the declared control/keepalive message remain unchanged.
 * The table selects configured local handlers by context and packet kind.
 * It does not configure radios, encrypt packets, generate replies or update
 * session timers. Emit dtls, base, radio_mac, wireless_info, header_tail,
 * control_message, keepalive and elements in order, then the untouched payload.
 */
/*
parser capwap_parser(packet_in pkt, out capwap_headers_t hdr,
                     out capwap_metadata_t meta, in bit<32> outer_bytes,
                     in bool control_channel, in bool authenticated_plaintext) {
    bit<32> header_remaining;
    bit<32> remaining;
    bit<32> field_bytes;
    bit<32> value_bytes;

    state start {
        capwap_preamble_t preamble;
        meta.packet_kind = capwap_packet_kind.DATA;
        meta.header_bytes = 0;
        meta.header_tail_bytes = 0;
        meta.payload_bytes = 0;
        meta.message_bytes = 0;
        meta.element_bytes = 0;
        meta.unparsed_element_bytes = 0;
        meta.outer_trailing_bytes = 0;
        meta.parsed_elements = 0;
        meta.elements_complete = false;
        verify(outer_bytes >= 1, error.HeaderTooShort);
        preamble = pkt.lookahead<capwap_preamble_t>();
        verify(preamble.version == CAPWAP_VERSION, error.NoMatch);
        transition select(preamble.type) {
            CAPWAP_PREAMBLE_HEADER: parse_header;
            CAPWAP_PREAMBLE_DTLS: parse_dtls;
            default: unsupported;
        }
    }

    state unsupported {
        verify(false, error.NoMatch);
        transition accept;
    }

    state parse_dtls {
        verify(outer_bytes >= 4, error.HeaderTooShort);
        pkt.extract(hdr.dtls);
        meta.packet_kind = capwap_packet_kind.DTLS;
        meta.header_bytes = 4;
        meta.payload_bytes = outer_bytes - 4;
        transition accept;
    }

    state parse_header {
        verify(outer_bytes >= 8, error.HeaderTooShort);
        pkt.extract(hdr.base);
        verify(hdr.base.hlen >= 2, error.HeaderTooShort);
        meta.header_bytes = (bit<32>)hdr.base.hlen * 4;
        verify(meta.header_bytes <= outer_bytes, error.HeaderTooShort);
        meta.payload_bytes = outer_bytes - meta.header_bytes;
        header_remaining = meta.header_bytes - 8;
        transition select(hdr.base.radio_mac_present) {
            1: parse_radio_mac;
            default: check_wireless_info;
        }
    }

    state parse_radio_mac {
        bit<8> length;
        verify(header_remaining >= 4, error.HeaderTooShort);
        length = pkt.lookahead<bit<8>>();
        verify(length == 6 || length == 8, error.NoMatch);
        field_bytes = ((bit<32>)length + 4) & 32w0xfffffffc;
        verify(field_bytes <= header_remaining, error.HeaderTooShort);
        pkt.extract(hdr.radio_mac, (field_bytes - 1) * 8);
        header_remaining = header_remaining - field_bytes;
        transition check_wireless_info;
    }

    state check_wireless_info {
        transition select(hdr.base.wireless_info_present) {
            1: parse_wireless_info;
            default: parse_header_tail;
        }
    }

    state parse_wireless_info {
        bit<8> length;
        verify(header_remaining >= 4, error.HeaderTooShort);
        length = pkt.lookahead<bit<8>>();
        field_bytes = ((bit<32>)length + 4) & 32w0xfffffffc;
        verify(field_bytes <= header_remaining, error.HeaderTooShort);
        pkt.extract(hdr.wireless_info, (field_bytes - 1) * 8);
        header_remaining = header_remaining - field_bytes;
        transition parse_header_tail;
    }

    state parse_header_tail {
        meta.header_tail_bytes = header_remaining;
        pkt.extract(hdr.header_tail, header_remaining * 8);
        transition select(hdr.base.fragment, control_channel,
                          hdr.base.keepalive) {
            (1, _, _): deliver_fragment;
            (0, true, _): parse_control;
            (0, false, 1): parse_keepalive;
            default: accept;
        }
    }

    state deliver_fragment {
        meta.packet_kind = capwap_packet_kind.FRAGMENT;
        transition accept;
    }

    state parse_control {
        verify(hdr.base.keepalive == 0, error.NoMatch);
        verify(meta.payload_bytes >= 8, error.HeaderTooShort);
        pkt.extract(hdr.control_message);
        verify(authenticated_plaintext
               || hdr.control_message.message_type == CAPWAP_DISCOVERY_REQUEST
               || hdr.control_message.message_type == CAPWAP_DISCOVERY_RESPONSE,
               error.NoMatch);
        verify(hdr.control_message.message_element_length >= 3, error.HeaderTooShort);
        meta.packet_kind = capwap_packet_kind.CONTROL;
        meta.message_bytes = 5 + (bit<32>)hdr.control_message.message_element_length;
        verify(meta.message_bytes <= meta.payload_bytes, error.HeaderTooShort);
        remaining = meta.message_bytes - 8;
        meta.element_bytes = remaining;
        meta.outer_trailing_bytes = meta.payload_bytes - meta.message_bytes;
        transition check_element;
    }

    state parse_keepalive {
        verify(meta.payload_bytes >= 2, error.HeaderTooShort);
        pkt.extract(hdr.keepalive);
        verify(hdr.keepalive.message_element_length >= 2, error.HeaderTooShort);
        meta.packet_kind = capwap_packet_kind.KEEPALIVE;
        meta.message_bytes = (bit<32>)hdr.keepalive.message_element_length;
        verify(meta.message_bytes <= meta.payload_bytes, error.HeaderTooShort);
        remaining = meta.message_bytes - 2;
        meta.element_bytes = remaining;
        meta.outer_trailing_bytes = meta.payload_bytes - meta.message_bytes;
        transition check_element;
    }

    state check_element {
        meta.unparsed_element_bytes = remaining;
        meta.elements_complete = remaining == 0;
        transition select(remaining, meta.parsed_elements) {
            (0, _): accept;
            (_, 8): accept;
            default: parse_element;
        }
    }

    state parse_element {
        capwap_message_element_prefix_t prefix;
        verify(remaining >= 4, error.HeaderTooShort);
        prefix = pkt.lookahead<capwap_message_element_prefix_t>();
        value_bytes = (bit<32>)prefix.length;
        field_bytes = 4 + value_bytes;
        verify(field_bytes <= remaining, error.HeaderTooShort);
        pkt.extract(hdr.elements.next, value_bytes * 8);
        remaining = remaining - field_bytes;
        meta.parsed_elements = meta.parsed_elements + 1;
        transition check_element;
    }
}

control capwap_control(inout capwap_headers_t hdr,
                       in capwap_metadata_t meta,
                       inout standard_metadata_t standard_metadata,
                       in bit<32> context_id) {
    action deliver_capwap(bit<9> handler_port) {
        standard_metadata.egress_spec = handler_port;
    }

    action drop_capwap() {
        mark_to_drop(standard_metadata);
    }

    table capwap_handlers {
        key = {
            context_id: exact;
            meta.packet_kind: exact;
        }
        actions = {
            deliver_capwap;
            drop_capwap;
        }
        default_action = drop_capwap();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || (!hdr.base.isValid() && !hdr.dtls.isValid())) {
            mark_to_drop(standard_metadata);
        } else {
            capwap_handlers.apply();
        }
    }
}
*/

#endif
