#ifndef P4_PROTOCOL_HEADERS_PPPOE_P4
#define P4_PROTOCOL_HEADERS_PPPOE_P4

/**
 * PPP over Ethernet (RFC 2516)
 * 以太网上的点对点协议，分为 Discovery 和 Session 两个阶段
 */
typedef bit<8>  pppoeCode_t;
typedef bit<16> pppoe_tag_type_t;
typedef bit<16> ppp_protocol_t;

const bit<16> PPPOE_ETHERTYPE_DISCOVERY = 0x8863;
const bit<16> PPPOE_ETHERTYPE_SESSION = 0x8864;

/**
 * Common PPPoE Header (6 bytes)
 * 固定报头不包含 Discovery 标签或 PPP 协议字段
 * LENGTH counts the payload in bytes, excluding this header and Ethernet
 * padding. In Session packets it includes the PPP Protocol field.
 */
header pppoe_t {
    bit<4>      version;       // Version 1
    bit<4>      type;          // Type 1
    pppoeCode_t code;
    bit<16>     session_id;    // 0xffff is reserved
    bit<16>     payload_len;
};

/* Discovery codes and the Session data code */
const pppoeCode_t PPPOE_CODE_SESSION = 0x00;
const pppoeCode_t PPPOE_CODE_PADI = 0x09;
const pppoeCode_t PPPOE_CODE_PADO = 0x07;
const pppoeCode_t PPPOE_CODE_PADR = 0x19;
const pppoeCode_t PPPOE_CODE_PADS = 0x65;
const pppoeCode_t PPPOE_CODE_PADT = 0xA7;

/**
 * Discovery Tag (4-byte prefix followed by its value)
 * TAG_LENGTH counts only the value bytes. Empty values are allowed.
 * The varbit limit covers the full 16-bit length field. The enclosing PPPoE
 * payload length and target resources further constrain an actual tag.
 */
header pppoe_tag_t {
    pppoe_tag_type_t tag_type;
    bit<16>         tag_len;
    varbit<524280>  tag_value;
};

/* Common registered Discovery tags */
const pppoe_tag_type_t PPPOE_TAG_END_OF_LIST = 0x0000;
const pppoe_tag_type_t PPPOE_TAG_SERVICE_NAME = 0x0101;
const pppoe_tag_type_t PPPOE_TAG_AC_NAME = 0x0102;
const pppoe_tag_type_t PPPOE_TAG_HOST_UNIQ = 0x0103;
const pppoe_tag_type_t PPPOE_TAG_AC_COOKIE = 0x0104;
const pppoe_tag_type_t PPPOE_TAG_VENDOR_SPECIFIC = 0x0105;
const pppoe_tag_type_t PPPOE_TAG_RELAY_SESSION_ID = 0x0110;
const pppoe_tag_type_t PPPOE_TAG_PPP_MAX_PAYLOAD = 0x0120;
const pppoe_tag_type_t PPPOE_TAG_SERVICE_NAME_ERROR = 0x0201;
const pppoe_tag_type_t PPPOE_TAG_AC_SYSTEM_ERROR = 0x0202;
const pppoe_tag_type_t PPPOE_TAG_GENERIC_ERROR = 0x0203;

// Value prefix for the 2-byte PPP-Max-Payload tag (RFC 4638).
// This is the PPP Information field limit, excluding the Protocol field.
header pppoe_max_payload_t {
    bit<16> max_payload;
};

/**
 * PPP Protocol Prefix (RFC 1661)
 * PPPoE carries no PPP address, control or FCS fields. Parse the Information
 * field separately, using the remaining PPPoE length and negotiated MRU.
 */
header ppp_t {
    ppp_protocol_t protocol;
};

// Use the 1-byte form only after receive-side PFC negotiation for this session.
// LCP always uses the 2-byte Protocol field.
header ppp_compressed_t {
    bit<8> protocol;
};

const ppp_protocol_t PPP_PROTOCOL_IPV4 = 0x0021;
const ppp_protocol_t PPP_PROTOCOL_IPV6 = 0x0057;
const ppp_protocol_t PPP_PROTOCOL_IPCP = 0x8021;
const ppp_protocol_t PPP_PROTOCOL_IPV6CP = 0x8057;
const ppp_protocol_t PPP_PROTOCOL_LCP = 0xC021;
const ppp_protocol_t PPP_PROTOCOL_PAP = 0xC023;
const ppp_protocol_t PPP_PROTOCOL_CHAP = 0xC223;

// Parser output. The normalized protocol also covers the compressed form.
struct pppoe_metadata_t {
    bit<8>         tag_count;
    ppp_protocol_t ppp_protocol;
    bit<16>        ppp_payload_len;
};

/**
 * P4 Parser Logic for PPPoE
 * The packet cursor must point to the PPPoE header. Pass the innermost
 * EtherType as payload_type and the validated Ethernet payload byte count,
 * excluding FCS, as pppoe_available. Extra bytes after LENGTH are padding.
 * The headers struct contains pppoe_t pppoe, pppoe_tag_t[16] pppoe_tags,
 * ppp_t ppp and ppp_compressed_t ppp_compressed. The tag stack must be empty
 * on entry. More than 16 tags cause a parser error. Adjust for the target.
 *
 * Unknown Discovery tags remain opaque and need no handler. End-Of-List
 * must have length zero and stops tag parsing. Later bytes remain opaque.
 * Pass pfc_allowed from the receive-side LCP state for this peer and session.
 * Obtaining that state may need a target-specific lookup or a second pass.
 * PFC is off by default. Negotiation permits both Protocol field encodings.
 *
 * PPP Information stays opaque. The enclosing pipeline handles parser errors,
 * Discovery code/session-ID rules, mandatory tags, tag value semantics, peer
 * MAC addresses, session state, authentication, LCP/NCP and protocol rejection.
 * Bound any inner parser by meta.pppoe.ppp_payload_len, not Ethernet padding.
 * Enforce the negotiated MRU and link MTU there. PPP-Max-Payload permits a
 * larger MRU only under RFC 4638 negotiation, not just because the tag exists.
 */
/*
parser pppoe_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                    in bit<16> payload_type, in bit<32> pppoe_available,
                    in bit<1> pfc_allowed) {
    bit<16> tags_left;
    bit<32> tag_prefix;
    bit<16> value_length;
    bit<32> value_bits;
    bit<8> protocol_octet;

    state start {
        hdr.ppp.setInvalid();
        hdr.ppp_compressed.setInvalid();
        meta.pppoe.tag_count = 0;
        meta.pppoe.ppp_protocol = 0;
        meta.pppoe.ppp_payload_len = 0;
        verify(payload_type == PPPOE_ETHERTYPE_DISCOVERY
               || payload_type == PPPOE_ETHERTYPE_SESSION, error.NoMatch);
        verify(pppoe_available >= 6, error.HeaderTooShort);
        pkt.extract(hdr.pppoe);
        verify(hdr.pppoe.version == 1 && hdr.pppoe.type == 1, error.NoMatch);
        verify(hdr.pppoe.session_id != 0xffff, error.NoMatch);
        verify((bit<32>) hdr.pppoe.payload_len + 6 <= pppoe_available,
               error.HeaderTooShort);
        transition select(payload_type) {
            PPPOE_ETHERTYPE_DISCOVERY: parse_discovery;
            PPPOE_ETHERTYPE_SESSION: parse_session;
        }
    }

    state parse_discovery {
        tags_left = hdr.pppoe.payload_len;
        transition check_tags;
    }

    state check_tags {
        transition select(tags_left) {
            0: accept;
            default: parse_tag;
        }
    }

    state parse_tag {
        verify(tags_left >= 4, error.HeaderTooShort);
        tag_prefix = pkt.lookahead<bit<32>>();
        value_length = tag_prefix[15:0];
        verify(value_length <= tags_left - 4, error.HeaderTooShort);
        verify(tag_prefix[31:16] != PPPOE_TAG_END_OF_LIST
               || value_length == 0, error.NoMatch);
        value_bits = (bit<32>) value_length * 8;
        pkt.extract(hdr.pppoe_tags.next, value_bits);
        tags_left = tags_left - 4 - value_length;
        meta.pppoe.tag_count = meta.pppoe.tag_count + 1;
        transition select(hdr.pppoe_tags.last.tag_type) {
            PPPOE_TAG_END_OF_LIST: accept;
            default: check_tags;
        }
    }

    state parse_session {
        verify(hdr.pppoe.code == PPPOE_CODE_SESSION, error.NoMatch);
        verify(hdr.pppoe.session_id != 0, error.NoMatch);
        verify(hdr.pppoe.payload_len >= 1, error.HeaderTooShort);
        protocol_octet = pkt.lookahead<bit<8>>();
        transition select(protocol_octet[0:0]) {
            0: parse_ppp;
            1: parse_compressed_ppp;
        }
    }

    state parse_ppp {
        verify(hdr.pppoe.payload_len >= 2, error.HeaderTooShort);
        pkt.extract(hdr.ppp);
        verify(hdr.ppp.protocol[8:8] == 0 && hdr.ppp.protocol[0:0] == 1,
               error.NoMatch);
        verify(hdr.ppp.protocol != 0x00ff, error.NoMatch);
        meta.pppoe.ppp_protocol = hdr.ppp.protocol;
        meta.pppoe.ppp_payload_len = hdr.pppoe.payload_len - 2;
        transition accept;
    }

    state parse_compressed_ppp {
        verify(pfc_allowed == 1, error.NoMatch);
        pkt.extract(hdr.ppp_compressed);
        verify(hdr.ppp_compressed.protocol != 0xff, error.NoMatch);
        meta.pppoe.ppp_protocol = (bit<16>) hdr.ppp_compressed.protocol;
        meta.pppoe.ppp_payload_len = hdr.pppoe.payload_len - 1;
        transition accept;
    }
}
*/

/**
 * Typical session flow
 * PADI, PADO and PADR use Session ID zero. A successful PADS allocates an ID.
 * A PADS reporting Service-Name-Error uses ID zero. PADT names an existing
 * session and requires no tags. Session packets begin with the PPP Protocol
 * field and use Code zero. The MAC address pair and Session ID identify a
 * session, not the Session ID alone.
 */

#endif // P4_PROTOCOL_HEADERS_PPPOE_P4
