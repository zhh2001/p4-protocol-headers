#ifndef P4_PROTOCOL_HEADERS_LWAPP_P4
#define P4_PROTOCOL_HEADERS_LWAPP_P4

/**
 * Lightweight Access Point Protocol wire formats (Historic RFC 5412)
 * LWAPP 传输头、控制消息和有界解析示例
 * The layouts below follow RFC 5412, including its IEEE 802.11 binding.
 */

typedef bit<8> lwapp_message_type_t;

const bit<2> LWAPP_VERSION = 0;
const bit<16> LWAPP_ETHERTYPE = 0x88bb;
const bit<16> LWAPP_DATA_PORT = 12222;
const bit<16> LWAPP_CONTROL_PORT = 12223;
const bit<32> LWAPP_CCM_MIC_BYTES = 12;

/* Message types listed in RFC 5412 Section 4.2.1.1. Request/response numbering
 * varies between operations. Unlisted values remain available to the owner.
 * The RFC describes Key Update ACK/Confirm/Trigger without assigning their
 * message numbers in this table.
 */
const lwapp_message_type_t LWAPP_DISCOVERY_REQUEST = 1;
const lwapp_message_type_t LWAPP_DISCOVERY_RESPONSE = 2;
const lwapp_message_type_t LWAPP_JOIN_REQUEST = 3;
const lwapp_message_type_t LWAPP_JOIN_RESPONSE = 4;
const lwapp_message_type_t LWAPP_JOIN_ACK = 5;
const lwapp_message_type_t LWAPP_JOIN_CONFIRM = 6;
const lwapp_message_type_t LWAPP_CONFIGURE_REQUEST = 10;
const lwapp_message_type_t LWAPP_CONFIGURE_RESPONSE = 11;
const lwapp_message_type_t LWAPP_CONFIGURATION_UPDATE_REQUEST = 12;
const lwapp_message_type_t LWAPP_CONFIGURATION_UPDATE_RESPONSE = 13;
const lwapp_message_type_t LWAPP_WTP_EVENT_REQUEST = 14;
const lwapp_message_type_t LWAPP_WTP_EVENT_RESPONSE = 15;
const lwapp_message_type_t LWAPP_CHANGE_STATE_EVENT_REQUEST = 16;
const lwapp_message_type_t LWAPP_CHANGE_STATE_EVENT_RESPONSE = 17;
const lwapp_message_type_t LWAPP_ECHO_REQUEST = 22;
const lwapp_message_type_t LWAPP_ECHO_RESPONSE = 23;
const lwapp_message_type_t LWAPP_IMAGE_DATA_REQUEST = 24;
const lwapp_message_type_t LWAPP_IMAGE_DATA_RESPONSE = 25;
const lwapp_message_type_t LWAPP_RESET_REQUEST = 26;
const lwapp_message_type_t LWAPP_RESET_RESPONSE = 27;
const lwapp_message_type_t LWAPP_KEY_UPDATE_REQUEST = 30;
const lwapp_message_type_t LWAPP_KEY_UPDATE_RESPONSE = 31;
const lwapp_message_type_t LWAPP_PRIMARY_DISCOVERY_REQUEST = 32;
const lwapp_message_type_t LWAPP_PRIMARY_DISCOVERY_RESPONSE = 33;
const lwapp_message_type_t LWAPP_DATA_TRANSFER_REQUEST = 34;
const lwapp_message_type_t LWAPP_DATA_TRANSFER_RESPONSE = 35;
const lwapp_message_type_t LWAPP_CLEAR_CONFIG_INDICATION = 36;
const lwapp_message_type_t LWAPP_WLAN_CONFIG_REQUEST = 37;
const lwapp_message_type_t LWAPP_WLAN_CONFIG_RESPONSE = 38;
const lwapp_message_type_t LWAPP_MOBILE_CONFIG_REQUEST = 39;
const lwapp_message_type_t LWAPP_MOBILE_CONFIG_RESPONSE = 40;

const bit<8> LWAPP_ELEMENT_SESSION_ID = 45;
const bit<8> LWAPP_ELEMENT_VENDOR_SPECIFIC = 104;

/* Common transport header, six bytes. C = 0 carries a binding-specific data
 * frame, C = 1 a control message. Length counts payload bytes, excluding this
 * header and any link padding. An encrypted control payload includes its MIC.
 * F marks Layer 2 fragments. L = 1 means NOT LAST, L = 0 means LAST, and L
 * is meaningful only with F = 1. There is no fragment-offset field. A frame
 * has at most two LWAPP fragments, both with this header and the same Frag ID.
 * Frag ID is an eight-bit counter per WTP/AC pair and wraps after 255.
 * With IPv4/IPv6 UDP transport, F, L and Frag ID must all be zero. IP handles
 * fragmentation/reassembly. Status/WLANs depends on binding and direction.
 */
header lwapp_t {
    bit<2> version;
    bit<3> radio_id;
    bit<1> control_message;
    bit<1> fragment;
    bit<1> not_last;
    bit<8> fragment_id;
    bit<16> length;
    bit<16> status_or_wlans;
}

/* Value-only alternatives for Status/WLANs, replacing the final two bytes
 * of lwapp_t, not additional fields after it. WTP -> AC data carries signed
 * RSSI (dBm) and signed SNR (dB). WTP -> AC control transmits this field as zero.
 */
header lwapp_dot11_status_t {
    int<8> rssi;
    int<8> snr;
}

/* AC -> WTP data carries a WLAN bitmap for broadcast/multicast replication
 * when needed for encryption. The bitmap is unused for unicast frames.
 */
header lwapp_dot11_wlans_t {
    bit<16> wlan_bitmap;
}

/* Complete control header, eight bytes, immediately after lwapp_t.
 * Message Element Length counts bytes after Session ID, excluding these
 * eight bytes. It includes the 12-byte AES-CCM MIC when encrypted.
 * Sequence Number matches request/response exchanges and wraps after 255.
 * Session ID identifies the security context and is a random 32-bit value
 * unique between a given AC and its WTPs. Session checks belong to the owner.
 * Encryption begins after this header. These eight bytes remain in cleartext.
 */
header lwapp_control_t {
    lwapp_message_type_t message_type;
    bit<8> sequence_number;
    bit<16> message_element_length;
    bit<32> session_id;
}

/* Message elements use an eight-bit Type, a 16-bit Length, and Value bytes.
 * Length excludes the three-byte prefix. No alignment padding is inserted.
 * Type-specific lengths, required elements and vendor contents need validation.
 */
header lwapp_message_element_prefix_t {
    bit<8> type;
    bit<16> length;
}

header lwapp_message_element_t {
    bit<8> type;
    bit<16> length;
    varbit<524280> value;
}

/* Complete Session ID element (Type = 45, Length = 4), replacing a generic
 * element. This is distinct from the Session ID in the fixed control header.
 */
header lwapp_session_id_element_t {
    bit<8> type;
    bit<16> length;
    bit<32> session_id;
}

/* Fixed prefix inside Vendor Specific Value (Type = 104, Length >= 7).
 * Element ID is vendor-defined. At least one byte of vendor data follows.
 */
header lwapp_vendor_value_prefix_t {
    bit<32> vendor_identifier;
    bit<16> element_id;
}

/* Fixed AES-CCM authentication trailer. Extract only at the end of the
 * declared encrypted control message. It is not a message-element TLV.
 * Keys, IV state, authentication and decryption belong to the session owner.
 */
header lwapp_ccm_mic_t {
    bit<96> mic;
}

enum bit<8> lwapp_packet_kind {
    DATA = 0,
    FRAGMENT = 1,
    CONTROL_ELEMENTS = 2,
    CONTROL_OPAQUE = 3
};

struct lwapp_headers_t {
    lwapp_t base;
    lwapp_control_t control_header;
    lwapp_message_element_t[8] elements;
};

struct lwapp_metadata_t {
    lwapp_packet_kind packet_kind;
    bit<32> message_bytes;
    bit<32> payload_bytes;
    bit<32> element_area_bytes;
    bit<32> unparsed_element_bytes;
    bit<32> outer_trailing_bytes;
    bit<4> parsed_elements;
    bool elements_complete;
};

/**
 * Bounded parsing and local delivery example (P4_16, v1model).
 * The cursor points to the common LWAPP header. outer_bytes is the validated
 * enclosing payload length. With Layer 2 EtherType 0x88bb it may include link
 * padding but excludes FCS. With UDP it excludes IP/UDP headers and link
 * padding. UDP ports at the AC are 12222 for data and 12223 for control. The
 * caller checks enclosing lengths, UDP checksums, endpoint/channel policy
 * and complete IP reassembly before invoking this parser. UDP transport uses
 * the same six-byte header without an additional AP identity prefix.
 *
 * udp_transport is trusted enclosing context. With UDP the parser requires
 * zero F, L and Frag ID. With Layer 2 all fragments remain unparsed, including
 * the first one. The owner combines the two fragments using peer context,
 * Frag ID and L before parsing a complete message. Frames and all bytes
 * beyond the declared common Length are preserved unchanged.
 *
 * plaintext_elements is trusted session context, not a received header bit.
 * It is false for encrypted or unclassified control bodies, which remain
 * opaque, including the MIC. Discovery and join bodies are unencrypted.
 * After the join phase, control bodies use AES-CCM. There is no encryption
 * flag. The owner selects the policy for the current session and operation.
 * For a decrypted input, the owner first verifies/removes the MIC and updates
 * both length fields to describe the plaintext representation. Set the flag
 * only when the element area can be interpreted as plaintext TLVs.
 *
 * Common Length equals eight plus Message Element Length for an unfragmented
 * control message. The parser frames up to eight TLVs within that area.
 * elements_complete is false if a remainder has not been framed. Further
 * elements stay in the unextracted payload for the owner to validate. Unknown
 * types and values remain unchanged. A single TLV can hold at most 65524
 * value bytes in a control payload capped by the 16-bit common Length.
 *
 * The table delivers configured packet kinds to local handlers. Parsing does
 * not authenticate a message or create a session. The owner checks message
 * types, required elements, binding data, keys/IVs and sequence state before
 * processing configuration, key updates, Echo replies or timers. There is
 * no separate generic data header or keepalive header before the frame.
 * Emit base, control_header and elements, then the untouched payload.
 */
/*
parser lwapp_parser(packet_in pkt, out lwapp_headers_t hdr,
                    out lwapp_metadata_t meta, in bit<32> outer_bytes,
                    in bool udp_transport, in bool plaintext_elements) {
    bit<32> remaining;
    bit<32> element_bytes;
    bit<32> value_bytes;

    state start {
        meta.packet_kind = lwapp_packet_kind.DATA;
        meta.message_bytes = 0;
        meta.payload_bytes = 0;
        meta.element_area_bytes = 0;
        meta.unparsed_element_bytes = 0;
        meta.outer_trailing_bytes = 0;
        meta.parsed_elements = 0;
        meta.elements_complete = false;
        verify(outer_bytes >= 6, error.HeaderTooShort);
        pkt.extract(hdr.base);
        verify(hdr.base.version == LWAPP_VERSION, error.NoMatch);
        verify(!udp_transport || (hdr.base.fragment == 0
               && hdr.base.not_last == 0 && hdr.base.fragment_id == 0),
               error.NoMatch);
        meta.payload_bytes = (bit<32>)hdr.base.length;
        meta.message_bytes = 6 + meta.payload_bytes;
        verify(meta.message_bytes <= outer_bytes, error.HeaderTooShort);
        meta.outer_trailing_bytes = outer_bytes - meta.message_bytes;
        transition select(hdr.base.fragment, hdr.base.control_message) {
            (1, _): deliver_fragment;
            (0, 1): parse_control;
            default: accept;
        }
    }

    state deliver_fragment {
        meta.packet_kind = lwapp_packet_kind.FRAGMENT;
        transition accept;
    }

    state parse_control {
        verify(meta.payload_bytes >= 8, error.HeaderTooShort);
        pkt.extract(hdr.control_header);
        remaining = (bit<32>)hdr.control_header.message_element_length;
        verify(8 + remaining == meta.payload_bytes, error.NoMatch);
        meta.element_area_bytes = remaining;
        meta.unparsed_element_bytes = remaining;
        meta.packet_kind = lwapp_packet_kind.CONTROL_OPAQUE;
        transition select(plaintext_elements) {
            true: start_elements;
            default: accept;
        }
    }

    state start_elements {
        meta.packet_kind = lwapp_packet_kind.CONTROL_ELEMENTS;
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
        lwapp_message_element_prefix_t prefix;
        verify(remaining >= 3, error.HeaderTooShort);
        prefix = pkt.lookahead<lwapp_message_element_prefix_t>();
        value_bytes = (bit<32>)prefix.length;
        element_bytes = 3 + value_bytes;
        verify(element_bytes <= remaining, error.HeaderTooShort);
        pkt.extract(hdr.elements.next, value_bytes * 8);
        remaining = remaining - element_bytes;
        meta.parsed_elements = meta.parsed_elements + 1;
        transition check_element;
    }
}

control lwapp_control(inout lwapp_headers_t hdr,
                      in lwapp_metadata_t meta,
                      inout standard_metadata_t standard_metadata,
                      in bit<32> context_id) {
    action deliver_lwapp(bit<9> handler_port) {
        standard_metadata.egress_spec = handler_port;
    }

    action drop_lwapp() {
        mark_to_drop(standard_metadata);
    }

    table lwapp_handlers {
        key = {
            context_id: exact;
            meta.packet_kind: exact;
        }
        actions = {
            deliver_lwapp;
            drop_lwapp;
        }
        default_action = drop_lwapp();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.base.isValid()) {
            mark_to_drop(standard_metadata);
        } else {
            lwapp_handlers.apply();
        }
    }
}
*/

#endif
