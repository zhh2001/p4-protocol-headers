/**
 * IGMPv1/v2 and IGMPv3 headers (RFC 1112, RFC 2236 and RFC 9776)
 * IGMP 固定报头、查询源地址和报告记录的有界解析
 */
#ifndef P4_PROTOCOL_HEADERS_IGMP_P4
#define P4_PROTOCOL_HEADERS_IGMP_P4

#include "ipv4.p4"

const bit<8> IGMP_IP_PROTOCOL = 2;
const bit<32> IGMP_ALL_SYSTEMS = 32w0xe0000001;
const bit<32> IGMP_ALL_ROUTERS = 32w0xe0000002;
const bit<32> IGMPV3_REPORT_DESTINATION = 32w0xe0000016;

// Version and query kind are derived metadata, not fields on the wire.
enum bit<8> igmp_version {
    IGMPv1 = 1,
    IGMPv2 = 2,
    IGMPv3 = 3
}

enum bit<8> igmp_type {
    MEMBERSHIP_QUERY = 0x11,
    V1_MEMBERSHIP_REPORT = 0x12,
    V2_MEMBERSHIP_REPORT = 0x16,
    V2_LEAVE_GROUP = 0x17,
    V3_MEMBERSHIP_REPORT = 0x22
}

enum bit<8> igmp_query_type {
    GENERAL_QUERY = 1,
    GROUP_SPECIFIC_QUERY = 2,
    GROUP_AND_SOURCE_SPECIFIC_QUERY = 3
}

enum bit<8> igmpv3_record_type {
    MODE_IS_INCLUDE = 1,
    MODE_IS_EXCLUDE = 2,
    CHANGE_TO_INCLUDE_MODE = 3,
    CHANGE_TO_EXCLUDE_MODE = 4,
    ALLOW_NEW_SOURCES = 5,
    BLOCK_OLD_SOURCES = 6
}

// Common four-octet prefix. max_resp_code is reserved in reports and Leave.
// The checksum covers the entire IPv4 payload, including auxiliary and extra
// data. It does not use an IP pseudo-header. Reserved fields are ignored on
// reception and initialized to zero when sending.
header igmp_header {
    bit<8> type;
    bit<8> max_resp_code;
    bit<16> checksum;
}

// Follows the common header in Queries, v1/v2 Reports and v2 Leave messages.
// IGMPv3 Reports instead carry igmpv3_report at this offset.
header igmp_group_address {
    bit<32> group_address;
}

// Four-octet extension after the Query's group address. Source addresses
// follow separately. RFC 9776 names the high four bits Flags, preserving
// the layout of RFC 3376, where those bits were reserved.
header igmpv3_query {
    bit<4> flags;
    bit<1> suppress;
    bit<3> qrv;
    bit<8> qqic;
    bit<16> num_sources;
}

// For a v3 Query, Max Response Code decodes to tenths of a second and QQIC
// decodes to seconds. For either code: code < 128 means code itself, else
// (mantissa | 0x10) << (exponent + 3), using bits 3:0 and 6:4 respectively.
// A v2 Query uses a linear Max Response Code. An eight-octet Query with code
// zero identifies v1. Timer defaults and compatibility modes are application
// state. The source vector below holds the full 16-bit count of 32-bit words,
// while the enclosing IPv4 datagram and link MTU impose smaller limits.
header igmpv3_sources {
    varbit<2097120> sources;
}

header igmpv3_source_address {
    bit<32> address;
}

// Four-octet Report body after the common header, making an eight-octet
// fixed Report prefix. The Flags field was reserved in RFC 3376.
header igmpv3_report {
    bit<16> flags;
    bit<16> num_group_recs;
}

// Fixed eight-octet record prefix for callers that parse its parts separately.
header igmpv3_group_rec_prefix {
    bit<8> rec_type;
    bit<8> aux_data_len; // Auxiliary data length in 32-bit words
    bit<16> num_sources;
    bit<32> mcast_addr;
}

// Complete record view used by the example below. data contains num_sources
// IPv4 addresses followed by aux_data_len words of auxiliary data, in that
// order. A P4 header has one varbit field, so this view retains both regions
// in one field. Its capacity is (65535 + 255) * 32 bits. The enclosing IPv4
// length is checked before extraction and imposes a smaller size in practice.
// Senders use zero auxiliary length for base IGMPv3. Receivers ignore the
// auxiliary contents and unknown record types, then process later records.
header igmpv3_group_rec {
    bit<8> rec_type;
    bit<8> aux_data_len;
    bit<16> num_sources;
    bit<32> mcast_addr;
    varbit<2105280> data;
}

// Reuse the complete IPv4 definition, including TTL, Protocol and IHL-selected
// options. IGMPv3 uses TTL 1 and the Router Alert option. Outer address, option,
// fragmentation and checksum checks belong to the enclosing IP implementation.
typedef ipv4_header igmp_transport;

struct igmp_metadata_t {
    bit<8> version; // Zero for an unrecognized message type
    bit<8> query_kind; // Zero for messages other than Queries
    bit<16> parsed_record_count;
    bit<32> source_count;
    bit<32> auxiliary_bytes;
    bit<32> parsed_bytes;
    bit<32> trailing_bytes;
}

/**
 * Bounded IGMP message parser
 * The cursor points at the IGMP type octet. message_length is the complete
 * IPv4 payload length after validating Total Length and IHL, excluding link
 * padding. The caller checks physical bounds, Protocol 2, fragment completeness
 * and the checksum over the whole message. IGMPv3 Report fragmentation may
 * require reassembly. Check TTL, Router Alert and addresses as required by the
 * received version, including the legacy compatibility rules.
 *
 * headers contains igmp_header igmp, igmp_group_address igmp_group,
 * igmpv3_query igmpv3_query, igmpv3_sources igmpv3_sources,
 * igmpv3_report igmpv3_report and igmpv3_group_rec[32] igmpv3_records.
 * metadata contains igmp_metadata_t igmp. The record stack starts empty
 * and this parser is applied once per message. The 32-record limit is an
 * example resource bound that can be adjusted for a target.
 *
 * Query length 8 selects v1 when Max Response Code is zero, otherwise v2.
 * Length >= 12 selects v3. Queries of length 9 to 11 are discarded. Extract
 * exactly the advertised source vector or record sequence. Preserve unknown
 * record types and auxiliary data. Remaining additional message bytes stay
 * opaque. Include them in the checksum and ignore them when processing v3.
 * Unknown message types retain their body for the application to ignore.
 *
 * Emit igmp, igmp_group, igmpv3_query, igmpv3_sources, igmpv3_report and
 * igmpv3_records in this order, skipping invalid headers. Each complete record
 * retains its source/auxiliary boundary via the two length fields. The
 * application validates multicast groups, unicast sources and query variants,
 * interprets assigned flags, and ignores reserved fields and unknown records.
 * Membership state, querier election, timers and response generation belong
 * to the application. Accepted packet bytes remain unchanged.
 */
/*
parser igmp_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                    in bit<32> message_length) {
    bit<32> remaining;
    bit<16> records_remaining;
    bit<64> record_prefix;
    bit<16> record_sources;
    bit<8> record_aux_words;
    bit<32> data_bytes;

    state start {
        hdr.igmp.setInvalid();
        hdr.igmp_group.setInvalid();
        hdr.igmpv3_query.setInvalid();
        hdr.igmpv3_sources.setInvalid();
        hdr.igmpv3_report.setInvalid();
        meta.igmp.version = 0;
        meta.igmp.query_kind = 0;
        meta.igmp.parsed_record_count = 0;
        meta.igmp.source_count = 0;
        meta.igmp.auxiliary_bytes = 0;
        meta.igmp.parsed_bytes = 0;
        meta.igmp.trailing_bytes = 0;
        verify(message_length >= 4, error.HeaderTooShort);
        verify(message_length <= 65515, error.NoMatch);
        pkt.extract(hdr.igmp);
        remaining = message_length - 4;
        meta.igmp.parsed_bytes = 4;
        transition select(hdr.igmp.type) {
            0x11: parse_query_group;
            0x12: parse_v1_report;
            0x16: parse_v2_group;
            0x17: parse_v2_group;
            0x22: parse_v3_report;
            default: finish;
        }
    }

    state parse_query_group {
        verify(remaining >= 4, error.HeaderTooShort);
        pkt.extract(hdr.igmp_group);
        remaining = remaining - 4;
        meta.igmp.parsed_bytes = 8;
        meta.igmp.query_kind = 2;
        if (hdr.igmp_group.group_address == 0) {
            meta.igmp.query_kind = 1;
        }
        transition select(message_length) {
            8: legacy_query;
            default: parse_v3_query;
        }
    }

    state legacy_query {
        meta.igmp.version = 2;
        if (hdr.igmp.max_resp_code == 0) {
            meta.igmp.version = 1;
        }
        transition finish;
    }

    state parse_v3_query {
        verify(remaining >= 4, error.HeaderTooShort);
        pkt.extract(hdr.igmpv3_query);
        remaining = remaining - 4;
        meta.igmp.version = 3;
        meta.igmp.parsed_bytes = 12;
        meta.igmp.source_count = (bit<32>)hdr.igmpv3_query.num_sources;
        if (hdr.igmp_group.group_address != 0
            && hdr.igmpv3_query.num_sources != 0) {
            meta.igmp.query_kind = 3;
        }
        data_bytes = (bit<32>)hdr.igmpv3_query.num_sources * 4;
        verify(data_bytes <= remaining, error.HeaderTooShort);
        pkt.extract(hdr.igmpv3_sources, data_bytes * 8);
        remaining = remaining - data_bytes;
        meta.igmp.parsed_bytes = meta.igmp.parsed_bytes + data_bytes;
        transition finish;
    }

    state parse_v1_report {
        meta.igmp.version = 1;
        transition parse_legacy_group;
    }

    state parse_v2_group {
        meta.igmp.version = 2;
        transition parse_legacy_group;
    }

    state parse_legacy_group {
        verify(remaining >= 4, error.HeaderTooShort);
        pkt.extract(hdr.igmp_group);
        remaining = remaining - 4;
        meta.igmp.parsed_bytes = 8;
        transition finish;
    }

    state parse_v3_report {
        verify(remaining >= 4, error.HeaderTooShort);
        pkt.extract(hdr.igmpv3_report);
        meta.igmp.version = 3;
        remaining = remaining - 4;
        meta.igmp.parsed_bytes = 8;
        records_remaining = hdr.igmpv3_report.num_group_recs;
        verify(records_remaining <= 32, error.StackOutOfBounds);
        transition check_records;
    }

    state check_records {
        transition select(records_remaining) {
            0: finish;
            default: parse_record;
        }
    }

    state parse_record {
        verify(remaining >= 8, error.HeaderTooShort);
        record_prefix = pkt.lookahead<bit<64>>();
        record_sources = record_prefix[47:32];
        record_aux_words = record_prefix[55:48];
        data_bytes = ((bit<32>)record_sources + (bit<32>)record_aux_words) * 4;
        verify(data_bytes <= remaining - 8, error.HeaderTooShort);
        pkt.extract(hdr.igmpv3_records.next, data_bytes * 8);
        remaining = remaining - 8 - data_bytes;
        records_remaining = records_remaining - 1;
        meta.igmp.parsed_record_count = meta.igmp.parsed_record_count + 1;
        meta.igmp.source_count = meta.igmp.source_count + (bit<32>)record_sources;
        meta.igmp.auxiliary_bytes = meta.igmp.auxiliary_bytes
            + (bit<32>)record_aux_words * 4;
        meta.igmp.parsed_bytes = meta.igmp.parsed_bytes + 8 + data_bytes;
        transition check_records;
    }

    state finish {
        meta.igmp.trailing_bytes = remaining;
        transition accept;
    }
}
*/

/**
 * Application dispatch (v1model)
 * handler_port is the default application destination. The table separates
 * query versions and variants from reports and Leave messages. Parser errors
 * drop the packet. An enclosing control also drops failed IP/checksum checks.
 * This example forwards accepted packets without altering membership state.
 */
/*
control igmp_control(inout headers hdr, inout metadata meta,
                     inout standard_metadata_t standard_metadata,
                     in bit<9> handler_port) {
    action send_igmp(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action send_default() {
        standard_metadata.egress_spec = handler_port;
    }

    table igmp_handlers {
        key = {
            meta.igmp.version: exact;
            hdr.igmp.type: exact;
            meta.igmp.query_kind: exact;
        }
        actions = {
            send_igmp;
            send_default;
        }
        default_action = send_default();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.igmp.isValid()) {
            mark_to_drop(standard_metadata);
        } else {
            igmp_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_IGMP_P4
