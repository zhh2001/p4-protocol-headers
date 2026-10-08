#ifndef P4_PROTOCOL_HEADERS_BGP_P4
#define P4_PROTOCOL_HEADERS_BGP_P4

/**
 * BGP-4 (RFC 4271, 8654, 9072)
 * BGP 应用报头和消息区域，传输层使用独立的 tcp.p4 定义
 */
const bit<16> BGP_TCP_PORT = 179;
const bit<8> BGP_VERSION = 4;
const bit<128> BGP_MARKER = 0xffffffffffffffffffffffffffffffff;
const bit<16> BGP_HEADER_LENGTH = 19;
const bit<16> BGP_MAX_MESSAGE_LENGTH = 4096;
const bit<16> BGP_MAX_EXTENDED_MESSAGE_LENGTH = 65535;
const bit<8> BGP_EXTENDED_OPEN_TYPE = 255;

enum bit<8> bgp_message_type {
    OPEN          = 1,
    UPDATE        = 2,
    NOTIFICATION  = 3,
    KEEPALIVE     = 4,
    ROUTE_REFRESH = 5
};

enum bit<8> bgp_attribute_type {
    ORIGIN           = 1,
    AS_PATH          = 2,
    NEXT_HOP         = 3,
    MED              = 4,
    LOCAL_PREF       = 5,
    ATOMIC_AGGREGATE  = 6,
    AGGREGATOR       = 7,
    COMMUNITY        = 8,
    ORIGINATOR_ID    = 9,
    CLUSTER_LIST     = 10,
    AS4_PATH         = 17,
    AS4_AGGREGATOR   = 18
};

/* Common header (19 bytes). The marker is all ones in every message type. */
header bgp_header {
    bit<128> marker;
    bit<16>  length;               // Entire message, including this header
    bit<8>   type;
};

/**
 * OPEN fixed body (10 bytes), following the common header.
 * My AS stays 16 bits. RFC 6793 carries the four-byte ASN in capability 65
 * and uses AS_TRANS (23456) here when the ASN cannot fit in two bytes.
 */
header bgp_open {
    bit<8>  version;
    bit<16> my_as;
    bit<16> hold_time;
    bit<32> bgp_id;
    bit<8>  opt_param_len;
};

/**
 * RFC 9072 length prefix (3 bytes), following bgp_open.
 * When opt_param_len is nonzero, inspect the next byte. A value of 255
 * selects this format regardless of the nonzero opt_param_len value.
 * Extended length counts only the subsequent parameters, excluding this
 * prefix. An extended encoding of zero parameters is also permitted.
 */
header bgp_open_extended_length {
    bit<8>  param_type;            // 255
    bit<16> opt_param_len;
};

/**
 * One optional parameter in the ordinary OPEN encoding.
 * Extract param_len * 8 variable bits after checking the enclosing bounds.
 */
header bgp_opt_param {
    bit<8>       param_type;
    bit<8>       param_len;
    varbit<2040> param_value;
};

/**
 * One optional parameter in the RFC 9072 encoding.
 * OPEN is still limited to 4096 bytes, even with RFC 8654 enabled.
 * The field capacity represents the 16-bit length. Enclosing message
 * bounds and target capacity must be checked before extraction.
 */
header bgp_opt_param_extended {
    bit<8>         param_type;
    bit<16>        param_len;
    varbit<524280> param_value;
};

/* One capability TLV inside optional parameter type 2 (RFC 5492). */
header bgp_capability {
    bit<8>       code;
    bit<8>       length;
    varbit<2040> value;
};

/**
 * UPDATE starts with this two-byte field, followed by withdrawn route bytes.
 * Only after those bytes does bgp_update_attributes occur.
 */
header bgp_update {
    bit<16> withdrawn_len;
};

header bgp_update_attributes {
    bit<16> path_attr_len;
};

/**
 * An opaque message region. Length comes from the enclosing message.
 * UPDATE order is withdrawn length, withdrawn routes, attributes length,
 * attributes, then NLRI. NLRI has no separate length field.
 * NLRI bytes = message length - 23 - withdrawn length - attributes length.
 * This capacity covers the largest BGP body (65535 - 19 bytes). Individual
 * regions are further bounded by their enclosing message and fixed fields.
 */
header bgp_data {
    varbit<524128> data;
};

/**
 * Path attribute prefix (2 bytes), followed by one of the length headers.
 * If extended_len is zero, use bgp_path_attr_length. Otherwise use
 * bgp_path_attr_extended_length. Attribute value follows the length field.
 * Reserved flag bits are sent as zero and ignored on receipt.
 */
header bgp_path_attr {
    bit<1> optional;
    bit<1> transitive;
    bit<1> partial;
    bit<1> extended_len;
    bit<4> unused;
    bit<8> type_code;
};

header bgp_path_attr_length {
    bit<8> attr_len;
};

header bgp_path_attr_extended_length {
    bit<16> attr_len;
};

/**
 * One AS_PATH segment, not the entire attribute.
 * path_seg_len counts ASNs, not bytes. Extract count * ASN width * 8 bits.
 * ASN width is 2 or 4 bytes according to session capabilities (RFC 6793).
 * AS4_PATH always uses 4 bytes. The enclosing attribute bounds also apply.
 * Types 1/2 are AS_SET/AS_SEQUENCE, 3/4 are confederation segments (RFC 5065).
 */
header bgp_as_path {
    bit<8>       path_seg_type;
    bit<8>       path_seg_len;
    varbit<8160> as_numbers;       // At most 255 four-byte ASNs per segment
};

/* One four-byte community (RFC 1997). Repeat for attribute length / 4. */
header bgp_community {
    bit<32> community;
};

/**
 * NOTIFICATION body. Data length is message length - 21 bytes.
 * Data capacity covers an extended message. Ordinary messages remain
 * bounded by 4096 bytes unless the receiver advertised capability 6.
 */
header bgp_notification {
    bit<8>         error_code;
    bit<8>         error_subcode;
    varbit<524112> data;
};

/* KEEPALIVE consists only of the common header and is exactly 19 bytes. */

/**
 * ROUTE-REFRESH fixed body (4 bytes), in AFI, reserved, SAFI order (RFC 2918).
 * The reserved byte is sent as zero and ignored on receipt. RFC 7313 uses
 * it as a subtype: 0 normal, 1 beginning of refresh, 2 end of refresh.
 * Optional ORF data can follow this prefix (RFC 5291).
 */
header bgp_route_refresh {
    bit<16> afi;
    bit<8>  reserved;
    bit<8>  safi;
};

struct bgp_metadata_t {
    bit<16> options_length;
    bit<1>  extended_open;
    bit<16> withdrawn_length;
    bit<16> attributes_length;
    bit<16> nlri_length;
    bit<16> refresh_data_length;
};

/**
 * P4 Parser Logic for One BGP Message
 * The cursor points to the common header. message_length is the byte count
 * of one complete, already framed message. TCP segments and PSH do not
 * delimit BGP messages. Reassembly, retransmissions, stream offsets and
 * separation of multiple messages belong to the caller.
 *
 * The headers struct contains bgp_header bgp_header, bgp_open bgp_open,
 * bgp_open_extended_length bgp_open_extended_length, bgp_data bgp_options,
 * bgp_update bgp_update, bgp_data bgp_withdrawn,
 * bgp_update_attributes bgp_update_attributes, bgp_data bgp_attributes,
 * bgp_data bgp_nlri, bgp_notification bgp_notification,
 * bgp_route_refresh bgp_route_refresh and bgp_data bgp_refresh_data.
 * Metadata contains bgp_metadata_t bgp.
 *
 * Pass extended_messages_allowed from receive-side session state. It is
 * set only when this receiver advertised capability 6 to the peer, not
 * merely when the peer advertised it. OPEN remains at most 4096 bytes and
 * KEEPALIVE exactly 19 bytes. Target limits can be lower than wire limits.
 *
 * This example checks framing and region bounds. OPEN parameter contents,
 * attribute TLVs and NLRI stay opaque. The application validates capability
 * negotiation, ASN width, ADD-PATH, mandatory attributes, AFI/SAFI, refresh
 * subtypes, hold timers and session state. It also handles BGP errors and
 * NOTIFICATION generation, including RFC 7606 UPDATE error handling.
 * IP/TCP parsing, checksums, fragmentation and parser errors are separate.
 */
/*
parser bgp_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                  in bit<16> message_length,
                  in bit<1> extended_messages_allowed) {
    bit<16> remaining;
    bit<8> option_type;
    bit<32> region_bits;

    state start {
        hdr.bgp_header.setInvalid();
        hdr.bgp_open.setInvalid();
        hdr.bgp_open_extended_length.setInvalid();
        hdr.bgp_options.setInvalid();
        hdr.bgp_update.setInvalid();
        hdr.bgp_withdrawn.setInvalid();
        hdr.bgp_update_attributes.setInvalid();
        hdr.bgp_attributes.setInvalid();
        hdr.bgp_nlri.setInvalid();
        hdr.bgp_notification.setInvalid();
        hdr.bgp_route_refresh.setInvalid();
        hdr.bgp_refresh_data.setInvalid();
        meta.bgp.options_length = 0;
        meta.bgp.extended_open = 0;
        meta.bgp.withdrawn_length = 0;
        meta.bgp.attributes_length = 0;
        meta.bgp.nlri_length = 0;
        meta.bgp.refresh_data_length = 0;
        verify(message_length >= BGP_HEADER_LENGTH, error.HeaderTooShort);
        pkt.extract(hdr.bgp_header);
        verify(hdr.bgp_header.marker == BGP_MARKER, error.NoMatch);
        verify(hdr.bgp_header.length == message_length, error.HeaderTooShort);
        verify(hdr.bgp_header.type >= 1 && hdr.bgp_header.type <= 5, error.NoMatch);
        verify(message_length <= BGP_MAX_MESSAGE_LENGTH
               || extended_messages_allowed == 1, error.NoMatch);
        remaining = message_length - BGP_HEADER_LENGTH;
        transition select(hdr.bgp_header.type) {
            1: parse_open;
            2: parse_update;
            3: parse_notification;
            4: parse_keepalive;
            5: parse_refresh;
            default: accept;
        }
    }

    state parse_open {
        verify(message_length >= 29
               && message_length <= BGP_MAX_MESSAGE_LENGTH, error.NoMatch);
        pkt.extract(hdr.bgp_open);
        verify(hdr.bgp_open.version == BGP_VERSION, error.NoMatch);
        remaining = remaining - 10;
        transition select(hdr.bgp_open.opt_param_len) {
            0: open_without_options;
            default: inspect_open_options;
        }
    }

    state open_without_options {
        verify(remaining == 0, error.NoMatch);
        transition accept;
    }

    state inspect_open_options {
        verify(remaining >= 1, error.HeaderTooShort);
        option_type = pkt.lookahead<bit<8>>();
        transition select(option_type) {
            BGP_EXTENDED_OPEN_TYPE: parse_extended_open_length;
            default: parse_ordinary_open_length;
        }
    }

    state parse_extended_open_length {
        verify(remaining >= 3, error.HeaderTooShort);
        pkt.extract(hdr.bgp_open_extended_length);
        remaining = remaining - 3;
        verify(hdr.bgp_open_extended_length.opt_param_len == remaining,
               error.NoMatch);
        meta.bgp.extended_open = 1;
        transition parse_open_options;
    }

    state parse_ordinary_open_length {
        verify((bit<16>) hdr.bgp_open.opt_param_len == remaining, error.NoMatch);
        transition parse_open_options;
    }

    state parse_open_options {
        meta.bgp.options_length = remaining;
        region_bits = (bit<32>) remaining * 8;
        pkt.extract(hdr.bgp_options, region_bits);
        transition accept;
    }

    state parse_update {
        verify(remaining >= 4, error.HeaderTooShort);
        pkt.extract(hdr.bgp_update);
        remaining = remaining - 2;
        verify(hdr.bgp_update.withdrawn_len <= remaining - 2, error.NoMatch);
        meta.bgp.withdrawn_length = hdr.bgp_update.withdrawn_len;
        region_bits = (bit<32>) meta.bgp.withdrawn_length * 8;
        pkt.extract(hdr.bgp_withdrawn, region_bits);
        remaining = remaining - meta.bgp.withdrawn_length;
        pkt.extract(hdr.bgp_update_attributes);
        remaining = remaining - 2;
        verify(hdr.bgp_update_attributes.path_attr_len <= remaining, error.NoMatch);
        meta.bgp.attributes_length = hdr.bgp_update_attributes.path_attr_len;
        region_bits = (bit<32>) meta.bgp.attributes_length * 8;
        pkt.extract(hdr.bgp_attributes, region_bits);
        meta.bgp.nlri_length = remaining - meta.bgp.attributes_length;
        region_bits = (bit<32>) meta.bgp.nlri_length * 8;
        pkt.extract(hdr.bgp_nlri, region_bits);
        transition accept;
    }

    state parse_notification {
        verify(remaining >= 2, error.HeaderTooShort);
        region_bits = (bit<32>) (remaining - 2) * 8;
        pkt.extract(hdr.bgp_notification, region_bits);
        transition accept;
    }

    state parse_keepalive {
        verify(remaining == 0, error.NoMatch);
        transition accept;
    }

    state parse_refresh {
        verify(remaining >= 4, error.HeaderTooShort);
        pkt.extract(hdr.bgp_route_refresh);
        meta.bgp.refresh_data_length = remaining - 4;
        region_bits = (bit<32>) meta.bgp.refresh_data_length * 8;
        pkt.extract(hdr.bgp_refresh_data, region_bits);
        transition accept;
    }
}
*/

/**
 * P4 Match-Action Pipeline for BGP (v1model)
 * Select a handler by message type and retain the complete packet.
 * The BGP application keeps the peer/connection context, runs the session
 * state machine and manages RIB/FIB changes. This table supplies a handler
 * port rather than establishing sessions or generating TCP responses.
 */
/*
control bgp_control(inout headers hdr, inout metadata meta,
                    inout standard_metadata_t standard_metadata) {
    action send_bgp(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action drop_bgp() {
        mark_to_drop(standard_metadata);
    }

    table bgp_handlers {
        key = {
            hdr.bgp_header.type: exact;
        }
        actions = {
            send_bgp;
            drop_bgp;
        }
        default_action = drop_bgp();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.bgp_header.isValid()) {
            drop_bgp();
        } else {
            bgp_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_BGP_P4
