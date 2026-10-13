#ifndef P4_PROTOCOL_HEADERS_SCTP_P4
#define P4_PROTOCOL_HEADERS_SCTP_P4

/**
 * Stream Control Transmission Protocol definitions (RFC 9260)
 * SCTP 公共报头、独立 Chunk 和参数前缀
 * RFC 9260 replaces RFC 4960. One packet carries one or more chunks.
 * SCTP uses IP protocol 132 with IPv4 or IPv6. UDP and DTLS encapsulations
 * require their own framing before the cursor reaches the common header.
 */

const bit<8> SCTP_IP_PROTOCOL = 132;
const bit<8> SCTP_DATA_END = 0x01;
const bit<8> SCTP_DATA_BEGIN = 0x02;
const bit<8> SCTP_DATA_UNORDERED = 0x04;
const bit<8> SCTP_DATA_IMMEDIATE = 0x08;
const bit<8> SCTP_REFLECTED_TAG = 0x01; // ABORT and SHUTDOWN COMPLETE T bit

enum bit<8> sctp_chunk_type {
    DATA = 0,
    INIT = 1,
    INIT_ACK = 2,
    SACK = 3,
    HEARTBEAT = 4,
    HEARTBEAT_ACK = 5,
    ABORT = 6,
    SHUTDOWN = 7,
    SHUTDOWN_ACK = 8,
    ERROR = 9,
    COOKIE_ECHO = 10,
    COOKIE_ACK = 11,
    SHUTDOWN_COMPLETE = 14
};

/**
 * Common header (12 bytes). Source and destination port zero are invalid.
 * Verification Tag is an association validation value, not a unique ID.
 * INIT uses tag zero. ABORT and SHUTDOWN COMPLETE have reflected-tag rules.
 * checksum retains the four wire octets of the CRC32c, including their order.
 * With a reflected CRC32c implementation, encode its result least significant
 * octet first. A P4 bit<32> reads those octets in network order as a raw value.
 * Compute over the complete SCTP packet with this field zero, including chunk
 * padding and excluding any IP pseudoheader, IP bytes and link padding.
 * CRC32c uses Castagnoli, rather than the IEEE CRC32 used by crc32 in v1model.
 * Zero can be a valid CRC32c result. RFC 9653 also allows a negotiated alternate
 * integrity method to accept zero under its rules. It is not an unconditional
 * checksum bypass. Verification belongs to the endpoint or a suitable extern.
 */
header sctp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> verification_tag;
    bit<32> checksum;
};

/* Every chunk starts with this 4-byte prefix. Length includes this prefix
 * and the value, excludes its 0-3 alignment bytes, and must be at least 4.
 * Transmit unused flag bits and padding as zero, ignore them on receipt.
 * Unknown chunk types use their top two bits for stop/skip and error reporting.
 * Those actions depend on which extensions the endpoint recognizes.
 */
header sctp_chunk_prefix_t {
    bit<8> chunk_type;
    bit<8> chunk_flags;
    bit<16> chunk_length;
};

/* Complete generic chunk, an alternative to the prefix plus typed body.
 * value_and_padding stores (round_up(chunk_length, 4) - 4) octets.
 * The maximum is 65532 octets, because length 65535 has one padding octet.
 * Keeping padding in the same header preserves interleaved chunk wire order.
 */
header sctp_chunk_t {
    bit<8> chunk_type;
    bit<8> chunk_flags;
    bit<16> chunk_length;
    varbit<524256> value_and_padding;
};

/* DATA fixed body (12 bytes after the chunk prefix), then nonempty user data.
 * Chunk Length = 16 + user data length. Flags are Res[7:4], I, U, B and E.
 * B/E identify first, middle, last or unfragmented pieces. When U = 1, ignore
 * stream_seq. PPID zero means unspecified. This body is not an I-DATA body.
 */
header sctp_data_t {
    bit<32> tsn;
    bit<16> stream_id;
    bit<16> stream_seq;
    bit<32> payload_proto;
};

/* INIT and INIT ACK share this 16-byte fixed body, then parameter TLVs.
 * Chunk Length is at least 20. init_tag and both stream counts are nonzero,
 * a_rwnd is at least 1500. INIT ACK additionally requires a State Cookie.
 * INIT, INIT ACK and SHUTDOWN COMPLETE must each be the only chunk in a packet.
 */
header sctp_init_t {
    bit<32> init_tag;
    bit<32> a_rwnd;
    bit<16> n_out_streams;
    bit<16> n_in_streams;
    bit<32> initial_tsn;
};

/* SACK fixed body (12 bytes). Gap blocks precede duplicate TSNs.
 * Chunk Length = 16 + 4 * gap_count + 4 * duplicate_count.
 */
header sctp_sack_t {
    bit<32> cumulative_tsn_ack;
    bit<32> a_rwnd;
    bit<16> gap_count;
    bit<16> duplicate_count;
};

header sctp_gap_ack_t {
    bit<16> start;            // Offsets from Cumulative TSN Ack
    bit<16> end;
};

header sctp_duplicate_tsn_t {
    bit<32> tsn;
};

/* SHUTDOWN fixed body (4 bytes). Total Chunk Length is 8. */
header sctp_shutdown_t {
    bit<32> cumulative_tsn_ack;
};

/* Parameter and error cause prefixes (4 bytes). Length includes the prefix,
 * excludes 0-3 padding bytes, and is at least 4. Their values remain separate.
 * Parameter padding between entries contributes to the enclosing chunk length.
 * For the final parameter, a receiver accepts either inclusion or exclusion
 * of its padding in the enclosing Chunk Length (RFC 9260 section 3.2).
 */
header sctp_parameter_t {
    bit<16> type;
    bit<16> length;
};

header sctp_cause_t {
    bit<16> code;
    bit<16> length;
};

/* HEARTBEAT and HEARTBEAT ACK carry a Heartbeat Info parameter.
 * ABORT and ERROR carry error causes. COOKIE ECHO carries an opaque cookie.
 * SHUTDOWN ACK, COOKIE ACK and SHUTDOWN COMPLETE have no chunk body (length 4).
 * Extension chunk bodies and parameter values require their own definitions.
 */

struct sctp_headers_t {
    sctp_t common;
    sctp_chunk_t[8] chunks;
};

struct sctp_metadata_t {
    bit<4> parsed_chunks;
    bit<32> parsed_bytes;
    bit<32> remaining_bytes;
    bool framing_complete;
};

/**
 * Bounded chunk framing and local delivery example (P4_16, v1model).
 * The cursor points to the common header. sctp_bytes is one complete SCTP
 * packet's validated length, excluding outer headers, link padding and FCS.
 * The caller validates the enclosing IP or transport, handles IP fragments
 * and provides a context_id for the selected local endpoint and peer policy.
 * This example has an eight-chunk parsing budget, not a protocol chunk limit.
 * When that budget is reached, the remaining bytes stay opaque and metadata
 * reports incomplete framing. The local handler validates the rest of the
 * packet. A partial parsed chunk or missing alignment bytes is rejected.
 *
 * This parser checks common ports and generic lengths. It does not consume
 * user messages or implement endpoint chunk processing. The handler verifies
 * CRC32c or the permitted RFC 9653 integrity method before using any chunks.
 * It checks typed-body lengths, SACK counts, TLVs, mandatory INIT parameters,
 * bundling, Verification Tag and negotiated extensions. Unknown chunk and
 * parameter stop/skip/report rules are applied there in received order.
 * Association state, cookies, TSN/stream tracking, reassembly, congestion and
 * replies also belong there. No SCTP fields or received padding are changed.
 *
 * The table selects a configured local SCTP handler, with drop as its default.
 * context_id scopes destination ports to the intended local endpoint.
 * It does not identify an established association from the tag alone.
 * Emit common and the chunk stack, then the remaining bytes in the deparser.
 */
/*
parser sctp_parser(packet_in pkt, out sctp_headers_t hdr,
                   out sctp_metadata_t meta, in bit<32> sctp_bytes) {
    bit<32> remaining;
    bit<32> chunk_bytes;
    bit<32> padded_bytes;

    state start {
        meta.parsed_chunks = 0;
        meta.parsed_bytes = 0;
        meta.remaining_bytes = 0;
        meta.framing_complete = false;
        verify(sctp_bytes >= 16, error.HeaderTooShort);
        pkt.extract(hdr.common);
        verify(hdr.common.src_port != 0 && hdr.common.dst_port != 0,
               error.NoMatch);
        remaining = sctp_bytes - 12;
        meta.parsed_bytes = 12;
        transition check_chunk;
    }

    state check_chunk {
        transition select(remaining, meta.parsed_chunks) {
            (0, _): finish;
            (_, 8): finish;
            default: parse_chunk;
        }
    }

    state parse_chunk {
        bit<32> prefix;
        verify(remaining >= 4, error.HeaderTooShort);
        prefix = pkt.lookahead<bit<32>>();
        chunk_bytes = (bit<32>)prefix[15:0];
        verify(chunk_bytes >= 4, error.NoMatch);
        padded_bytes = (chunk_bytes + 3) & 32w0xFFFFFFFC;
        verify(padded_bytes <= remaining, error.HeaderTooShort);
        pkt.extract(hdr.chunks.next, (padded_bytes - 4) * 8);
        remaining = remaining - padded_bytes;
        meta.parsed_chunks = meta.parsed_chunks + 1;
        meta.parsed_bytes = meta.parsed_bytes + padded_bytes;
        transition check_chunk;
    }

    state finish {
        meta.remaining_bytes = remaining;
        meta.framing_complete = remaining == 0;
        transition accept;
    }
}

control sctp_control(inout sctp_headers_t hdr,
                     inout standard_metadata_t standard_metadata,
                     in bit<32> context_id) {
    action deliver_sctp(bit<9> handler_port) {
        standard_metadata.egress_spec = handler_port;
    }

    action drop_sctp() {
        mark_to_drop(standard_metadata);
    }

    table sctp_handlers {
        key = {
            context_id: exact;
            hdr.common.dst_port: exact;
        }
        actions = {
            deliver_sctp;
            drop_sctp;
        }
        default_action = drop_sctp();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.common.isValid()) {
            mark_to_drop(standard_metadata);
        } else {
            sctp_handlers.apply();
        }
    }
}
*/

#endif
