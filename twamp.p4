#ifndef P4_PROTOCOL_HEADERS_TWAMP_P4
#define P4_PROTOCOL_HEADERS_TWAMP_P4

/**
 * TWAMP-Test formats (RFC 5357 with verified errata, RFC 4656)
 * TWAMP 测试报文、受保护报文和有界解析示例
 */
const bit<16> TWAMP_CONTROL_PORT = 862; // TCP
const bit<16> TWAMP_TEST_PORT = 862; // Optional UDP well-known port, RFC 8545
const bit<32> TWAMP_MAX_UDP_BYTES = 65527;
const bit<32> TWAMP_UNAUTHENTICATED_MIN_BYTES = 41;
const bit<32> TWAMP_PROTECTED_MIN_BYTES = 112; // RFC 5357 erratum 5045

typedef bit<64> twamp_timestamp_t;

// Effective Test security mode supplied by the session, not inferred from data.
// Mixed mode (RFC 5618) can use unauthenticated Test with encrypted Control.
enum bit<3> twamp_test_mode {
    UNAUTHENTICATED = 1,
    AUTHENTICATED = 2,
    ENCRYPTED = 4
}

// Local parser roles, not fields transmitted in a TWAMP-Test packet.
enum bit<1> twamp_test_direction {
    SENDER = 0,
    REFLECTOR = 1
}

/* Error Estimate, two bytes. Error = Multiplier * 2^(Scale-32) seconds.
 * Multiplier is nonzero. S indicates external synchronization. The next bit
 * is reserved in RFC 4656. With RFC 8186 enabled, it selects NTP (0) or
 * PTPv2-truncated (1). Reflected Sender Error Estimate describes the copied
 * Sender Timestamp, independently of the reflector's timestamp format.
 */
header twamp_error_estimate_t {
    bit<1> synchronized;
    bit<1> timestamp_format;
    bit<6> scale;
    bit<8> multiplier;
}

// NTP: seconds from 1900-01-01 plus a binary fraction in units of 2^-32 s.
// The session resolves the era. PTP truncated uses low 32 seconds bits from
// 1970-01-01 TAI, followed by nanoseconds (RFC 8186, RFC 8877).
header twamp_ntp_timestamp_t {
    bit<32> seconds;
    bit<32> fraction;
}

header twamp_ptp_timestamp_t {
    bit<32> seconds;
    bit<32> nanoseconds;
}

/* Unauthenticated sender prefix, 14 bytes, followed directly by Packet Padding.
 * A base TWAMP packet has at least 27 padding bytes to accommodate reflection.
 * Sequence numbers start at zero and advance per Test session modulo 2^32.
 * Padding can carry negotiated RFC 6038 data and is kept as received.
 */
header twamp_test_t {
    bit<32> sequence_number;
    twamp_timestamp_t timestamp;
    bit<16> error_estimate;
}

/* Unauthenticated reflector prefix, 41 bytes. Timestamp is reflector transmit
 * time. Receive Timestamp records arrival at the reflector and uses the same
 * Error Estimate. Sender fields are copies from the corresponding request.
 * Reflector sequence numbers are independent, per session (erratum 1590).
 * Sender TTL is the received IP TTL/Hop Limit, or 255 if unavailable.
 * MBZ fields are sent as zero and ignored on reception.
 */
header twamp_reflect_t {
    bit<32> sequence_number;
    twamp_timestamp_t timestamp;
    bit<16> error_estimate;
    bit<16> mbz1;
    twamp_timestamp_t receive_timestamp;
    bit<32> sender_sequence_number;
    twamp_timestamp_t sender_timestamp;
    bit<16> sender_error_estimate;
    bit<16> mbz2;
    bit<8> sender_ttl;
}

/* RFC 7750 unauthenticated monitoring extension, three bytes immediately after
 * twamp_reflect_t. The complete fixed portion is 44 bytes. Sender DSCP/ECN
 * describes the received request. Selection comes from the session profile.
 */
header twamp_sender_traffic_class_t {
    bit<6> sender_dscp;
    bit<2> sender_ecn;
    bit<16> mbz;
}

/* Protected wire views. In authenticated mode, the first 16-byte block is
 * AES-ECB ciphertext. Subsequent blocks are clear. In encrypted mode, AES-CBC
 * with IV zero covers the first 32 sender bytes or 96 reflector bytes.
 * HMAC-SHA1-128 covers the corresponding plaintext region and is sent clear.
 * Packet Padding follows HMAC, outside encryption and authentication.
 */
header twamp_protected_test_t {
    bit<128> sequence_block;
    bit<128> timestamp_block;
    bit<128> hmac;
}

header twamp_protected_reflect_t {
    bit<128> sequence_block;
    bit<640> following_blocks;
    bit<128> hmac;
}

/* Plaintext alternatives after decryption, not additional wire headers
 * (RFC 5357 erratum 1589). Sender fixed portion is 48 bytes and reflector is
 * 112 bytes. To equalize lengths, sender padding is at least 64 bytes
 * (erratum 5046). HMAC is retained in these views. MBZ is ignored on receipt.
 */
header twamp_sender_plain_t {
    bit<32> sequence_number;
    bit<96> mbz1;
    twamp_timestamp_t timestamp;
    bit<16> error_estimate;
    bit<48> mbz2;
    bit<128> hmac;
}

header twamp_reflector_plain_t {
    bit<32> sequence_number;
    bit<96> mbz1;
    twamp_timestamp_t timestamp;
    bit<16> error_estimate;
    bit<48> mbz2;
    twamp_timestamp_t receive_timestamp;
    bit<64> mbz3;
    bit<32> sender_sequence_number;
    bit<96> mbz4;
    twamp_timestamp_t sender_timestamp;
    bit<16> sender_error_estimate;
    bit<48> mbz5;
    bit<8> sender_ttl;
    bit<8> sender_traffic_class; // MBZ, or RFC 7750 S-DSCP-ECN when negotiated
    bit<112> mbz6;
    bit<128> hmac;
}

struct twamp_headers_t {
    twamp_test_t sender;
    twamp_reflect_t reflector;
    twamp_sender_traffic_class_t traffic_class;
    twamp_protected_test_t protected_sender;
    twamp_protected_reflect_t protected_reflector;
}

struct twamp_metadata_t {
    bit<3> mode;
    bit<1> direction;
    bit<32> header_bytes;
    bit<32> padding_bytes;
    bool plaintext_available;
}

/**
 * TWAMP-Test parsing and local delivery (P4_16, v1model).
 * The caller supplies one complete validated ordinary UDP payload, its byte
 * count, the session's effective Test mode, direction and RFC 7750 selection.
 * Test endpoints can use UDP 862 or negotiated/configured ports. Control uses
 * TCP 862. A port number alone does not determine Test mode or direction.
 *
 * The example parses unauthenticated fields, preserves MBZ values and optional
 * DSCP/ECN bytes, and retains protected regions as opaque blocks. Emit sender,
 * reflector, traffic_class, protected_sender and protected_reflector, then the
 * original remainder. padding_bytes counts the remaining bytes within UDP.
 *
 * session_id identifies the configured Test session. Its owner handles
 * decryption, HMAC, RFC 6038 padding, clock formats and measurement state,
 * and performs reflection with timestamps from the measurement clock.
 */
/*
parser twamp_parser(packet_in pkt, out twamp_headers_t hdr,
                    out twamp_metadata_t meta, in bit<32> datagram_bytes,
                    in bit<3> test_mode, in bit<1> direction,
                    in bool dscp_ecn_monitoring) {
    state start {
        meta.mode = test_mode;
        meta.direction = direction;
        meta.header_bytes = 0;
        meta.padding_bytes = 0;
        meta.plaintext_available = false;
        verify(datagram_bytes <= TWAMP_MAX_UDP_BYTES, error.NoMatch);
        transition select(test_mode) {
            twamp_test_mode.UNAUTHENTICATED: unauthenticated;
            twamp_test_mode.AUTHENTICATED: protected_packet;
            twamp_test_mode.ENCRYPTED: protected_packet;
            default: unsupported;
        }
    }

    state unsupported {
        verify(false, error.NoMatch);
        transition accept;
    }

    state unauthenticated {
        verify(datagram_bytes >= TWAMP_UNAUTHENTICATED_MIN_BYTES,
               error.HeaderTooShort);
        transition select(direction) {
            twamp_test_direction.SENDER: parse_sender;
            default: parse_reflector;
        }
    }

    state parse_sender {
        pkt.extract(hdr.sender);
        verify(hdr.sender.error_estimate[7:0] != 0, error.NoMatch);
        meta.header_bytes = 14;
        meta.plaintext_available = true;
        transition end_packet;
    }

    state parse_reflector {
        pkt.extract(hdr.reflector);
        verify(hdr.reflector.error_estimate[7:0] != 0, error.NoMatch);
        verify(hdr.reflector.sender_error_estimate[7:0] != 0, error.NoMatch);
        meta.header_bytes = 41;
        meta.plaintext_available = true;
        transition select(dscp_ecn_monitoring) {
            true: parse_traffic_class;
            default: end_packet;
        }
    }

    state parse_traffic_class {
        verify(datagram_bytes >= 44, error.HeaderTooShort);
        pkt.extract(hdr.traffic_class);
        meta.header_bytes = 44;
        transition end_packet;
    }

    state protected_packet {
        verify(datagram_bytes >= TWAMP_PROTECTED_MIN_BYTES,
               error.HeaderTooShort);
        transition select(direction) {
            twamp_test_direction.SENDER: parse_protected_sender;
            default: parse_protected_reflector;
        }
    }

    state parse_protected_sender {
        pkt.extract(hdr.protected_sender);
        meta.header_bytes = 48;
        transition end_packet;
    }

    state parse_protected_reflector {
        pkt.extract(hdr.protected_reflector);
        meta.header_bytes = 112;
        transition end_packet;
    }

    state end_packet {
        meta.padding_bytes = datagram_bytes - meta.header_bytes;
        transition accept;
    }
}

control twamp_control(inout twamp_headers_t hdr, in twamp_metadata_t meta,
                      inout standard_metadata_t standard_metadata,
                      in bit<32> session_id) {
    action deliver_twamp(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    action drop_twamp() {
        mark_to_drop(standard_metadata);
    }
    table twamp_sessions {
        key = {
            session_id: exact;
            meta.direction: exact;
            meta.mode: exact;
        }
        actions = { deliver_twamp; drop_twamp; }
        default_action = drop_twamp();
    }
    apply {
        if (standard_metadata.parser_error != error.NoError) {
            drop_twamp();
        } else {
            twamp_sessions.apply();
        }
    }
}
*/

#endif
