#ifndef P4_PROTOCOL_HEADERS_GTP_U_P4
#define P4_PROTOCOL_HEADERS_GTP_U_P4

/**
 * GTPv1-U Header Definition in P4 (3GPP TS 29.281)
 * 4G/5G 用户面隧道报头
 */

const bit<16> GTP_U_UDP_PORT = 2152;

/* GTP-U message types */
const bit<8> GTP_U_ECHO_REQUEST = 1;
const bit<8> GTP_U_ECHO_RESPONSE = 2;
const bit<8> GTP_U_ERROR_INDICATION = 26;
const bit<8> GTP_U_SUPPORTED_EXTENSIONS = 31;
const bit<8> GTP_U_TUNNEL_STATUS = 253;
const bit<8> GTP_U_END_MARKER = 254;
const bit<8> GTP_U_G_PDU = 255;

/**
 * GTP-U Base Header (8 bytes)
 * Length counts all bytes after this header, including optional fields
 * and extension headers.
 */
header gtp_u_t {
    bit<3>  version;       // Version 1
    bit<1>  pt;            // 1: GTP, 0: GTP'
    bit<1>  spare;         // Transmit zero, ignore on receipt
    bit<1>  e_bit;         // Next extension type is meaningful
    bit<1>  s_bit;         // Sequence number is meaningful
    bit<1>  pn_bit;        // N-PDU number is meaningful
    bit<8>  message_type;
    bit<16> length;        // Bytes after the mandatory 8-byte header
    bit<32> teid;          // Tunnel Endpoint Identifier
};

/**
 * GTP-U Optional Fields (4 bytes)
 * E、S、PN 任意一位为 1 时，整组字段均出现
 * Evaluate each field only when its corresponding flag is set.
 */
header gtp_u_optional_t {
    bit<16> seq_number;
    bit<8>  n_pdu_number;
    bit<8>  next_ext_type;
};

/**
 * GTP-U Extension Length and Content
 * The complete extension is 4-1020 bytes. Its final byte is parsed separately.
 */
header gtp_u_extension_t {
    bit<8> length;            // Complete extension length in 4-byte units (1-255)
    varbit<8144> content;     // Complete length minus length byte and next-type byte
};

/* Final byte of each extension */
header gtp_u_extension_next_t {
    bit<8> next_ext_type;     // 0 ends the extension chain
};

/* Extension types from TS 29.281 */
const bit<8> GTP_EXT_LONG_PDCP_PDU_NUMBER = 0x03;
const bit<8> GTP_EXT_PDU_SET_INFORMATION = 0x04;
const bit<8> GTP_EXT_SERVICE_CLASS = 0x20;
const bit<8> GTP_EXT_UDP_PORT = 0x40;
const bit<8> GTP_EXT_RAN_CONTAINER = 0x81;
const bit<8> GTP_EXT_LONG_PDCP_PDU_NUMBER_LEGACY = 0x82;
const bit<8> GTP_EXT_XW_RAN_CONTAINER = 0x83;
const bit<8> GTP_EXT_NR_RAN_CONTAINER = 0x84;
const bit<8> GTP_EXT_PDU_SESSION = 0x85;
const bit<8> GTP_EXT_PDU_SET_INFORMATION_LEGACY = 0x86;
const bit<8> GTP_EXT_PDCP_PDU_NUMBER = 0xC0;

/**
 * PDU Session Container Content Prefixes (2 bytes, TS 38.415 V19.1.0)
 * These fields start after the extension length byte for type 0x85.
 * PDU Type selects the DL/UL frame format, not the T-PDU payload protocol.
 * Optional fields, future extensions and padding follow these prefixes.
 * Parse them according to the flags before reading the next-extension byte.
 */
header gtp_u_pdu_session_dl_t {
    bit<4> pdu_type;       // 0: DL PDU Session Information
    bit<1> qmp;            // QoS monitoring timestamps present
    bit<1> snp;            // DL QFI sequence number present
    bit<1> msnp;           // DL MBS QFI sequence number present
    bit<1> spare;          // Transmit zero, ignore on receipt
    bit<1> ppp;            // Paging policy information present
    bit<1> rqi;            // Reflective QoS Indicator
    bit<6> qfi;            // QoS Flow Identifier
};

header gtp_u_pdu_session_ul_t {
    bit<4> pdu_type;       // 1: UL PDU Session Information
    bit<1> qmp;            // QoS monitoring timestamps present
    bit<1> dl_delay_ind;   // DL delay result present
    bit<1> ul_delay_ind;   // UL delay result present
    bit<1> snp;            // UL QFI sequence number present
    bit<1> n3_n9_delay_ind; // N3/N9 delay result present
    bit<1> new_ie_flag;    // New IE flags octet present
    bit<6> qfi;            // QoS Flow Identifier
};

/**
 * P4 Parser Logic for GTP-U
 * The packet cursor must point to the GTP-U base header.
 * Pass the validated UDP payload length as gtp_length.
 * This example requires the GTP message length to match the UDP payload.
 * The headers struct contains gtp_u_t gtp_u, gtp_u_optional_t gtp_optional,
 * gtp_u_extension_t[16] extensions and gtp_u_extension_next_t[16] ext_next.
 * Both stacks must be empty on entry. More than 16 extensions cause a parser error.
 *
 * This parser checks framing and leaves extension contents and the message
 * body opaque. The enclosing pipeline handles parser errors, IP/UDP bounds,
 * checksums, sequence tracking, message-specific rules and extension semantics.
 * Unknown extensions require handling according to their comprehension bits
 * and the node's role before the packet is forwarded or decapsulated.
 * Select the T-PDU parser from the session configuration. The T-PDU may contain
 * IP, Ethernet or unstructured data. G-PDUs may also have an empty T-PDU.
 */
/*
parser gtp_u_parser(packet_in pkt, inout headers hdr,
                    in bit<16> gtp_length) {
    bit<16> message_left;
    bit<8> next_ext_type;
    bit<8> extension_length;
    bit<16> extension_bytes;
    bit<32> content_bits;

    state start {
        hdr.gtp_optional.setInvalid();
        verify(gtp_length >= 8, error.HeaderTooShort);
        pkt.extract(hdr.gtp_u);
        verify(hdr.gtp_u.version == 1 && hdr.gtp_u.pt == 1, error.NoMatch);
        verify(hdr.gtp_u.length == gtp_length - 8, error.HeaderTooShort);
        message_left = hdr.gtp_u.length;
        transition select(hdr.gtp_u.e_bit, hdr.gtp_u.s_bit, hdr.gtp_u.pn_bit) {
            (0, 0, 0): accept;
            default: parse_optional;
        }
    }

    state parse_optional {
        verify(message_left >= 4, error.HeaderTooShort);
        pkt.extract(hdr.gtp_optional);
        message_left = message_left - 4;
        transition select(hdr.gtp_u.e_bit) {
            1: check_extensions;
            default: accept;
        }
    }

    state check_extensions {
        next_ext_type = hdr.gtp_optional.next_ext_type;
        transition select(next_ext_type) {
            0: accept;
            default: parse_extension;
        }
    }

    state parse_extension {
        verify(message_left >= 4, error.HeaderTooShort);
        extension_length = pkt.lookahead<bit<8>>();
        verify(extension_length != 0, error.HeaderTooShort);
        extension_bytes = (bit<16>) extension_length * 4;
        verify(extension_bytes <= message_left, error.HeaderTooShort);
        content_bits = ((bit<32>) extension_bytes - 2) * 8;
        pkt.extract(hdr.extensions.next, content_bits);
        pkt.extract(hdr.ext_next.next);
        message_left = message_left - extension_bytes;
        next_ext_type = hdr.ext_next.last.next_ext_type;
        transition select(next_ext_type) {
            0: accept;
            default: parse_extension;
        }
    }
}
*/

/**
 * P4 Match-Action Pipeline for GTP-U (v1model)
 * Select data ports by TEID after message and extension validation.
 * Send signalling messages, including End Marker, to a configured control port.
 * The enclosing pipeline handles decapsulation and egress framing.
 */
/*
control gtp_u_control(inout headers hdr,
                      inout standard_metadata_t standard_metadata) {
    action forward_data(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action send_control(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action drop_gtp() {
        mark_to_drop(standard_metadata);
    }

    table gtp_tunnels {
        key = {
            hdr.gtp_u.teid: exact;
        }
        actions = {
            forward_data;
            drop_gtp;
            NoAction;
        }
        default_action = drop_gtp();
    }

    table gtp_signalling {
        key = {
            hdr.gtp_u.message_type: exact;
        }
        actions = {
            send_control;
            drop_gtp;
        }
        default_action = drop_gtp();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.gtp_u.isValid()) {
            drop_gtp();
        } else if (hdr.gtp_u.message_type == GTP_U_G_PDU) {
            gtp_tunnels.apply();
        } else {
            gtp_signalling.apply();
        }
    }
}
*/

#endif
