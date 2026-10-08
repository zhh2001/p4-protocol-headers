#ifndef P4_PROTOCOL_HEADERS_NTP_P4
#define P4_PROTOCOL_HEADERS_NTP_P4

/**
 * Network Time Protocol (RFC 5905)
 * 网络时间协议，时间报文使用 UDP，服务端端口通常为 123
 */
const bit<16> NTP_UDP_PORT = 123;
typedef bit<64> ntp_timestamp_t;

/* Wire modes. Control and private messages use different packet formats. */
enum bit<3> ntp_mode {
    RESERVED          = 0,
    SYMMETRIC_ACTIVE  = 1,
    SYMMETRIC_PASSIVE = 2,
    CLIENT            = 3,
    SERVER            = 4,
    BROADCAST         = 5,
    CONTROL           = 6,
    PRIVATE           = 7
};

enum bit<2> ntp_leap {
    NO_WARNING  = 0,
    LAST_MIN_61 = 1,
    LAST_MIN_59 = 2,
    ALARM       = 3
};

enum bit<3> ntp_version {
    NTPv3 = 3,
    NTPv4 = 4
};

/**
 * Timestamp View (8 bytes)
 * Seconds are relative to 1900-01-01 and wrap every 2^32 seconds. The era is
 * not transmitted. Fraction is in units of 2^-32 seconds. The application
 * resolves the era and interprets timestamp differences.
 */
header ntp_timestamp {
    bit<32> seconds;
    bit<32> fraction;
};

/**
 * NTP Time Header (48 bytes, modes 1-5)
 * 固定时间报头，四个时间戳直接作为 64 位字段存储
 * The destination timestamp is recorded locally on receipt and is not a
 * fifth wire timestamp. Root fields keep their 16.16-second wire encoding.
 */
header ntp_header {
    bit<2>          leap;
    bit<3>          version;
    bit<3>          mode;
    bit<8>          stratum;          // 0: kiss code, 1: primary, 16: unsynchronized
    int<8>          poll;             // Signed log2 seconds
    int<8>          precision;        // Signed log2 seconds
    bit<32>         root_delay;
    bit<32>         root_dispersion;
    bit<32>         reference_id;     // Interpretation depends on stratum/version
    ntp_timestamp_t ref_timestamp;
    ntp_timestamp_t orig_timestamp;
    ntp_timestamp_t recv_timestamp;
    ntp_timestamp_t trans_timestamp;
};

/**
 * NTPv4 Extension Field (RFC 7822)
 * Length includes the 4-byte prefix, value and padding, and is a multiple of
 * four. Generic extensions are at least 16 bytes. Without a trailing MAC,
 * the final extension is at least 28 bytes. Extension specifications can
 * define their own length rules, as NTS does in RFC 8915.
 * The capacity covers the maximum 65532-byte field, excluding its prefix.
 * Check the length, packet bounds and field-specific rules before extracting
 * (length - 4) * 8 variable bits. Value includes any padding.
 */
header ntp_extension {
    bit<16>       field_type;
    bit<16>       length;
    varbit<524224> value;
};

/**
 * Traditional NTP MAC (RFC 5905, RFC 7822)
 * A 32-bit Key ID followed by a 16- or 20-byte digest. There is no digest
 * length field on the wire. Obtain the algorithm and digest length from the
 * association configuration before extracting the variable bits.
 * A crypto-NAK consists only of Key ID zero, with zero digest bits.
 * NTS authentication uses an extension field, not this traditional MAC.
 */
header ntp_auth {
    bit<32>     key_id;
    varbit<160> digest;
};

// KoD codes occupy reference_id in a stratum-zero time packet.
// They do not add a header or a text message after the four timestamps.
const bit<32> NTP_KOD_DENY = 0x44454E59;
const bit<32> NTP_KOD_RATE = 0x52415445;
const bit<32> NTP_KOD_RSTR = 0x52535452;
const bit<32> NTP_KOD_STEP = 0x53544550;

struct ntp_metadata_t {
    bit<3>  version;
    bit<3>  mode;
    bit<16> opaque_length;
};

/**
 * P4 Parser Logic for NTP
 * The packet cursor points to the first NTP byte. The caller selects traffic
 * by UDP ports or an existing association and passes the validated UDP payload
 * byte count as ntp_length. Include udp.p4 separately for transport parsing.
 * The headers struct contains ntp_header ntp_header. Metadata contains
 * ntp_metadata_t ntp. This example parses NTPv3/v4 time packets in modes 1-5.
 *
 * Control and private packets stay entirely opaque for their own handlers.
 * Those handlers validate their version and format. Mode zero is reserved.
 * Extension fields and MACs after a time header also stay opaque. Their
 * boundaries cannot be determined just from the NTP version. opaque_length
 * counts unparsed bytes within UDP, excluding IP or Ethernet padding.
 *
 * The enclosing pipeline handles parser errors, IP/UDP bounds, fragmentation,
 * checksums, association state, timestamp checks and authentication. A parsed
 * header alone does not establish that a time sample is valid. KoD handling,
 * responses and clock adjustment belong to the NTP application and time source.
 */
/*
parser ntp_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                  in bit<16> ntp_length) {
    bit<8> first_octet;

    state start {
        hdr.ntp_header.setInvalid();
        meta.ntp.version = 0;
        meta.ntp.mode = 0;
        meta.ntp.opaque_length = 0;
        verify(ntp_length >= 1, error.HeaderTooShort);
        first_octet = pkt.lookahead<bit<8>>();
        meta.ntp.version = first_octet[5:3];
        meta.ntp.mode = first_octet[2:0];
        meta.ntp.opaque_length = ntp_length;
        verify(meta.ntp.mode != 0, error.NoMatch);
        transition select(meta.ntp.mode) {
            6: accept;
            7: accept;
            default: parse_time;
        }
    }

    state parse_time {
        verify(meta.ntp.version == 3 || meta.ntp.version == 4, error.NoMatch);
        verify(ntp_length >= 48, error.HeaderTooShort);
        pkt.extract(hdr.ntp_header);
        meta.ntp.opaque_length = ntp_length - 48;
        transition accept;
    }
}
*/

/**
 * P4 Match-Action Pipeline for NTP (v1model)
 * Select configured handler ports by version and mode. Packets stay intact,
 * including timestamps, KoD reference IDs and any authentication bytes.
 * Time, control and private handlers perform their own protocol validation.
 */
/*
control ntp_control(inout headers hdr, inout metadata meta,
                    inout standard_metadata_t standard_metadata) {
    action send_ntp(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action drop_ntp() {
        mark_to_drop(standard_metadata);
    }

    table ntp_handlers {
        key = {
            meta.ntp.version: exact;
            meta.ntp.mode: exact;
        }
        actions = {
            send_ntp;
            drop_ntp;
        }
        default_action = drop_ntp();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || meta.ntp.mode == 0) {
            drop_ntp();
        } else {
            ntp_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_NTP_P4
