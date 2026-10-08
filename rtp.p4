/**
 * RTP headers (RFC 3550)
 * RTP 固定报头、CSRC 列表和通用扩展块
 */
#ifndef P4_PROTOCOL_HEADERS_RTP_P4
#define P4_PROTOCOL_HEADERS_RTP_P4

const bit<2> RTP_VERSION = 2;

// Default static assignments under RTP/AVP (RFC 3551), not a codec allowlist.
// Session signaling may override static mappings. Opus uses a dynamically
// assigned payload type (RFC 7587), so it has no fixed value here.
enum bit<7> rtp_payload {
    PCMU = 0,
    GSM  = 3,
    G722 = 9
}

const bit<7> RTP_AVP_DYNAMIC_MIN = 96;
const bit<7> RTP_AVP_DYNAMIC_MAX = 127;

// The fixed header is always 12 octets. CSRCs and extensions follow it.
header rtp_t {
    bit<2> version;
    bit<1> padding;         // Packet ends with padding, counted by its last octet
    bit<1> extension;       // One extension block follows the CSRC list
    bit<4> csrc_count;      // Number of CSRC identifiers, 0..15
    bit<1> marker;          // Meaning depends on the profile and payload format
    bit<7> payload_type;    // Resolve its encoding in the current RTP session
    bit<16> sequence_number;
    bit<32> timestamp;      // Sampling clock units, not wall-clock time
    bit<32> ssrc;
}

// Use a header stack with 15 entries and extract only csrc_count entries.
header rtp_csrc_t {
    bit<32> identifier;
}

// Present when X=1, after the CSRC list. length_words counts 32-bit words
// after this four-octet prefix. Zero is valid. The data includes any padding
// used to align the extension and is distinct from RTP packet-end padding.
header rtp_extension_t {
    bit<16> profile;
    bit<16> length_words;
}

// Full capacity of the 16-bit word count: 65535 * 32 bits.
// Extract (bit<32>) length_words * 32 bits after checking the packet bounds.
// The enclosing transport may impose a smaller packet size.
header rtp_extension_data_t {
    varbit<2097120> data;
}

// RFC 8285 profiles. A two-byte profile matches 0x1000/0xfff0 and carries
// application bits in its low four bits. The parser below keeps these and
// all other profile-specific extension contents opaque.
const bit<16> RTP_EXTENSION_ONE_BYTE = 16w0xbede;
const bit<16> RTP_EXTENSION_TWO_BYTE = 16w0x1000;
const bit<16> RTP_EXTENSION_TWO_BYTE_MASK = 16w0xfff0;

struct rtp_metadata_t {
    bit<4> parsed_csrc_count;
    bit<32> header_bytes;
    bit<32> trailing_bytes; // Media payload and any RTP packet-end padding
}

/**
 * P4 Parser Logic for a Bounded RTP Packet
 * The cursor points to the fixed header. rtp_length is the length of one
 * already identified RTP packet, excluding transport and link padding.
 * The caller checks transport bounds and provides a complete packet.
 * For UDP, use the validated UDP payload length rather than frame length.
 * RTP/RTCP demultiplexing and transport framing belong to the caller.
 *
 * The headers struct contains rtp_t rtp, rtp_csrc_t[15] rtp_csrcs,
 * rtp_extension_t rtp_extension and rtp_extension_data_t rtp_extension_data.
 * The CSRC stack must be empty on entry. Metadata contains rtp_metadata_t rtp.
 * The parser checks version, CSRC bounds and the generic extension length.
 * It preserves all extension profiles and leaves the cursor at the media
 * payload. Emit the fixed header, CSRC stack, extension prefix and data.
 *
 * The application interprets extension elements using the negotiated
 * profile and mappings. It checks packet-end padding when P=1, using the
 * final octet's nonzero count and the available trailing bytes. This parser
 * only ensures that at least one trailing byte exists in that case.
 * trailing_bytes includes padding and is not the media payload length.
 */
/*
parser rtp_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                  in bit<32> rtp_length) {
    bit<4> csrc_remaining;
    bit<32> remaining;
    bit<32> extension_bytes;
    bit<32> extension_bits;

    state start {
        hdr.rtp.setInvalid();
        hdr.rtp_extension.setInvalid();
        hdr.rtp_extension_data.setInvalid();
        meta.rtp.parsed_csrc_count = 0;
        meta.rtp.header_bytes = 0;
        meta.rtp.trailing_bytes = 0;
        verify(rtp_length >= 12, error.HeaderTooShort);
        pkt.extract(hdr.rtp);
        verify(hdr.rtp.version == RTP_VERSION, error.NoMatch);
        remaining = rtp_length - 12;
        verify((bit<32>) hdr.rtp.csrc_count * 4 <= remaining,
               error.HeaderTooShort);
        csrc_remaining = hdr.rtp.csrc_count;
        meta.rtp.header_bytes = 12;
        transition check_csrcs;
    }

    state check_csrcs {
        transition select(csrc_remaining) {
            0: check_extension;
            default: parse_csrc;
        }
    }

    state parse_csrc {
        pkt.extract(hdr.rtp_csrcs.next);
        csrc_remaining = csrc_remaining - 1;
        meta.rtp.parsed_csrc_count = meta.rtp.parsed_csrc_count + 1;
        remaining = remaining - 4;
        meta.rtp.header_bytes = meta.rtp.header_bytes + 4;
        transition check_csrcs;
    }

    state check_extension {
        transition select(hdr.rtp.extension) {
            1: parse_extension;
            default: finish;
        }
    }

    state parse_extension {
        verify(remaining >= 4, error.HeaderTooShort);
        pkt.extract(hdr.rtp_extension);
        remaining = remaining - 4;
        extension_bytes = (bit<32>) hdr.rtp_extension.length_words * 4;
        verify(extension_bytes <= remaining, error.HeaderTooShort);
        extension_bits = extension_bytes * 8;
        pkt.extract(hdr.rtp_extension_data, extension_bits);
        remaining = remaining - extension_bytes;
        meta.rtp.header_bytes = meta.rtp.header_bytes + 4 + extension_bytes;
        transition finish;
    }

    state finish {
        verify(hdr.rtp.padding == 0 || remaining >= 1, error.HeaderTooShort);
        meta.rtp.trailing_bytes = remaining;
        transition accept;
    }
}
*/

/**
 * P4 Match-Action Pipeline for RTP (v1model)
 * Route packets to a media handler without editing RTP fields or payload.
 * session_id comes from the enclosing flow classification. Payload type
 * mappings, including Opus, are configured per session. Unmapped types use
 * handler_port so the application can inspect them in their session context.
 * Sequence tracking, clock rates, decoding and playout run in the application.
 */
/*
control rtp_control(inout headers hdr, inout metadata meta,
                    inout standard_metadata_t standard_metadata,
                    in bit<32> session_id, in bit<9> handler_port) {
    action send_rtp(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action send_default() {
        standard_metadata.egress_spec = handler_port;
    }

    action drop_rtp() {
        mark_to_drop(standard_metadata);
    }

    table rtp_handlers {
        key = {
            session_id: exact;
            hdr.rtp.payload_type: exact;
        }
        actions = {
            send_rtp;
            send_default;
        }
        default_action = send_default();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.rtp.isValid()) {
            drop_rtp();
        } else {
            rtp_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_RTP_P4
