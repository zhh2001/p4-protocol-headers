/**
 * EAP and EAPOL headers (RFC 3748 and IEEE 802.1X-2020, Clause 11)
 * 标准 EAP 公共头、方法类型和 EAPOL 封装解析示例
 */
#ifndef P4_PROTOCOL_HEADERS_EAP_P4
#define P4_PROTOCOL_HEADERS_EAP_P4

#include "ethernet.p4"

const bit<16> ETHERTYPE_DOT1X = 16w0x888e;
const bit<8> DOT1X_VERSION_1 = 1;
const bit<8> DOT1X_VERSION_2 = 2;
const bit<8> DOT1X_VERSION_3 = 3; // IEEE 802.1X-2010 and 802.1X-2020

// EAPOL packet types from IEEE 802.1X, Table 11-3.
const bit<8> DOT1X_EAP_PACKET = 0;
const bit<8> DOT1X_EAPOL_START = 1;
const bit<8> DOT1X_EAPOL_LOGOFF = 2;
const bit<8> DOT1X_EAPOL_KEY = 3;
const bit<8> DOT1X_EAPOL_ASF_ALERT = 4;
const bit<8> DOT1X_EAPOL_MKA = 5;
const bit<8> DOT1X_EAPOL_ANNOUNCEMENT = 6; // Generic
const bit<8> DOT1X_EAPOL_ANNOUNCEMENT_SPECIFIC = 7;
const bit<8> DOT1X_EAPOL_ANNOUNCEMENT_REQ = 8;

const bit<8> EAP_CODE_REQUEST = 1;
const bit<8> EAP_CODE_RESPONSE = 2;
const bit<8> EAP_CODE_SUCCESS = 3;
const bit<8> EAP_CODE_FAILURE = 4;
const bit<8> EAP_CODE_INITIATE = 5; // ERP, RFC 6696
const bit<8> EAP_CODE_FINISH = 6; // ERP, RFC 6696

// Selected registered method types. Unknown types are passed to the EAP
// implementation for method negotiation. Type 26 is registered by IANA as
// MS-EAP-Authentication and is commonly used for EAP-MSCHAPv2.
const bit<8> EAP_TYPE_IDENTITY = 1;
const bit<8> EAP_TYPE_NOTIFICATION = 2;
const bit<8> EAP_TYPE_NAK = 3; // Legacy Nak, Response only
const bit<8> EAP_TYPE_MD5 = 4;
const bit<8> EAP_TYPE_OTP = 5;
const bit<8> EAP_TYPE_GTC = 6;
const bit<8> EAP_TYPE_TLS = 13;
const bit<8> EAP_TYPE_PEAP = 25;
const bit<8> EAP_TYPE_MSCHAPV2 = 26;
const bit<8> EAP_TYPE_EXPANDED = 254;
const bit<8> EAP_TYPE_EXPERIMENTAL = 255;

// Four-octet EAPOL prefix. length counts only the following Packet Body,
// excluding this header, Ethernet padding and FCS. All multioctet integers
// in these headers use network byte order. Version 3 is the transmit value
// for IEEE 802.1X-2020. Receive processing supports older versions and
// interprets later versions using the supported fields (11.5).
header dot1x_t {
    bit<8> version;
    bit<8> type;
    bit<16> length;
}

// Four-octet EAP common header. length includes this header and any Data.
// Success and Failure have length 4 and carry no Type or Data fields.
// EAP is also carried by protocols other than EAPOL, such as PPP and RADIUS.
header eap_t {
    bit<8> code;
    bit<8> identifier;
    bit<16> length;
}

// Request/Response Type immediately follows eap_t. The method's Type-Data
// occupies (length - 5) octets. Do not extract this for Success or Failure.
// ERP codes 5/6 have their own code-specific Data formats (RFC 6696).
header eap_method_t {
    bit<8> type;
}

// Seven-octet Expanded Type prefix following an eap_method_t with type 254.
// The complete Request/Response prefix is twelve octets, including eap_t
// and eap_method_t. Vendor-Id is an IANA SMI enterprise number, not an OUI.
// Vendor-Id zero extends the IETF method namespace. Remaining Vendor-Data
// is defined by that method, including the distinct Expanded Nak format.
header eap_expanded_t {
    bit<24> vendor_id;
    bit<32> vendor_type;
}

// Ethernet II carrier. Destination acceptance depends on packet type,
// recipient role and application scenario, including group/individual
// addresses. The enclosing link handler applies IEEE 802.1X, 11.1 and 11.4
// address policy, retains peer identity and handles VLAN tags and FCS.
typedef ethernet_header dot1x_transport;

struct eap_metadata_t {
    bit<32> parsed_bytes;
    bit<32> unparsed_bytes;
    bit<32> eap_data_bytes; // Unparsed EAP Data after the extracted prefix
    bit<32> padding_bytes; // Octets beyond EAP/EAPOL declared lengths
}

/**
 * Bounded EAPOL and EAP prefix parser
 * The cursor starts at the EAPOL version. headers contains dot1x_t dot1x,
 * eap_t eap, eap_method_t eap_method and eap_expanded_t eap_expanded.
 * metadata contains eap_metadata_t eap. Emit valid headers in that order.
 * link_type is the validated innermost EtherType. payload_length is the
 * physically bounded link payload, including retained pad but excluding FCS.
 *
 * Common EAPOL validation bounds the Packet Body within the received frame
 * (11.4). Start and Logoff are not required to carry a zero body length on
 * receipt. Legacy Start and Logoff ignore body content. Version 3 Start can
 * carry an announcement-request bit and announcement TLVs. These bodies,
 * Key descriptors, MKA and announcements remain opaque for their clients.
 *
 * For EAPOL-EAP, check EAP length against the EAPOL body before extracting
 * any method fields. RFC 3748 treats octets beyond EAP length as padding.
 * Method Type-Data, ERP Data and all padding remain unparsed and unchanged.
 * Known ERP codes are delivered with only their common EAP prefix decoded.
 * Their complete format, authentication and replay checks belong to ERP.
 *
 * The application validates method-specific data, matches Identifiers to
 * outstanding requests and handles authentication state. A Success code
 * alone does not authorize a port or establish cryptographic key state.
 */
/*
parser eap_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                  in bit<16> link_type, in bit<32> payload_length) {
    state start {
        hdr.dot1x.setInvalid();
        hdr.eap.setInvalid();
        hdr.eap_method.setInvalid();
        hdr.eap_expanded.setInvalid();
        meta.eap.parsed_bytes = 0;
        meta.eap.unparsed_bytes = payload_length;
        meta.eap.eap_data_bytes = 0;
        meta.eap.padding_bytes = 0;
        verify(link_type == ETHERTYPE_DOT1X, error.NoMatch);
        verify(payload_length >= 4, error.HeaderTooShort);
        pkt.extract(hdr.dot1x);
        verify(hdr.dot1x.version >= DOT1X_VERSION_1, error.NoMatch);
        verify(hdr.dot1x.type <= DOT1X_EAPOL_ANNOUNCEMENT_REQ, error.NoMatch);
        verify((bit<32>) hdr.dot1x.length <= payload_length - 4,
               error.HeaderTooShort);
        meta.eap.parsed_bytes = 4;
        meta.eap.unparsed_bytes = payload_length - 4;
        meta.eap.padding_bytes = payload_length - 4
                                 - (bit<32>) hdr.dot1x.length;
        transition select(hdr.dot1x.type) {
            DOT1X_EAP_PACKET: parse_eap;
            default: accept;
        }
    }

    state parse_eap {
        verify(hdr.dot1x.length >= 4, error.HeaderTooShort);
        pkt.extract(hdr.eap);
        verify(hdr.eap.length >= 4, error.NoMatch);
        verify(hdr.eap.length <= hdr.dot1x.length, error.HeaderTooShort);
        meta.eap.parsed_bytes = 8;
        meta.eap.unparsed_bytes = payload_length - 8;
        meta.eap.eap_data_bytes = (bit<32>) hdr.eap.length - 4;
        meta.eap.padding_bytes = payload_length - 4
                                 - (bit<32>) hdr.eap.length;
        transition select(hdr.eap.code) {
            EAP_CODE_REQUEST: parse_method;
            EAP_CODE_RESPONSE: parse_method;
            EAP_CODE_SUCCESS: parse_result;
            EAP_CODE_FAILURE: parse_result;
            EAP_CODE_INITIATE: accept;
            EAP_CODE_FINISH: accept;
            default: unsupported_code;
        }
    }

    state parse_method {
        verify(hdr.eap.length >= 5, error.HeaderTooShort);
        pkt.extract(hdr.eap_method);
        meta.eap.parsed_bytes = 9;
        meta.eap.unparsed_bytes = payload_length - 9;
        meta.eap.eap_data_bytes = (bit<32>) hdr.eap.length - 5;
        transition select(hdr.eap_method.type) {
            EAP_TYPE_EXPANDED: parse_expanded;
            default: accept;
        }
    }

    state parse_expanded {
        verify(hdr.eap.length >= 12, error.HeaderTooShort);
        pkt.extract(hdr.eap_expanded);
        meta.eap.parsed_bytes = 16;
        meta.eap.unparsed_bytes = payload_length - 16;
        meta.eap.eap_data_bytes = (bit<32>) hdr.eap.length - 12;
        transition accept;
    }

    state parse_result {
        verify(hdr.eap.length == 4, error.NoMatch);
        transition accept;
    }

    state unsupported_code {
        verify(false, error.NoMatch);
        transition accept;
    }
}
*/

/**
 * Local EAPOL application delivery (v1model)
 * The table selects a recipient by receiving port and EAPOL packet type.
 * Only install entries for protocol entities supported on that port.
 * handler_port and action ports are application endpoints, such as a CPU
 * port. The default handler dispatches to the appropriate supported client
 * or discards the message. Parser errors drop the packet.
 * Peer addressing and tag context from the enclosing parser must accompany
 * application delivery. Authentication, key exchange, session timers and
 * Controlled Port state are maintained by the application.
 */
/*
control eap_control(inout headers hdr,
                    inout standard_metadata_t standard_metadata,
                    in bit<9> handler_port) {
    action send_eapol(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action send_default() {
        standard_metadata.egress_spec = handler_port;
    }

    table eapol_handlers {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.dot1x.type: exact;
        }
        actions = {
            send_eapol;
            send_default;
        }
        default_action = send_default();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.dot1x.isValid()) {
            mark_to_drop(standard_metadata);
        } else {
            eapol_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_EAP_P4
