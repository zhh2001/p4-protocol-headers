#ifndef P4_PROTOCOL_HEADERS_SFLOW_P4
#define P4_PROTOCOL_HEADERS_SFLOW_P4

#include "udp.p4"

/**
 * sFlow v5 datagram and base structures (sFlow.org, July 2004, with errata)
 * sFlow 数据报、普通与扩展样本、基础流记录和接口计数器
 */
const bit<16> SFLOW_UDP_PORT = 6343;
const bit<32> SFLOW_MAX_DATAGRAM_BYTES = 65527; // Ordinary UDP length minus 8
const bit<20> SFLOW_STANDARD_ENTERPRISE = 0;
const bit<30> SFLOW_COMPACT_INTERFACE_LOCAL = 0x3FFFFFFF;
const bit<32> SFLOW_EXPANDED_INTERFACE_LOCAL = 0xFFFFFFFF;
const bit<30> SFLOW_DISCARD_ACL = 258; // Errata: compact output = 0x40000102

enum bit<32> sflow_version {
    V5 = 5
}

enum bit<32> sflow_address_type {
    UNKNOWN = 0,
    IPV4 = 1,
    IPV6 = 2
}

// Format numbers have separate namespaces for samples, flow and counter data.
enum bit<12> sflow_sample_format {
    FLOW = 1,
    COUNTER = 2,
    FLOW_EXPANDED = 3,
    COUNTER_EXPANDED = 4
}

enum bit<12> sflow_flow_format {
    RAW_HEADER = 1,
    ETHERNET = 2,
    IPV4 = 3,
    IPV6 = 4,
    EXTENDED_SWITCH = 1001
}

enum bit<12> sflow_counter_format {
    INTERFACE = 1,
    ETHERNET = 2
}

// Selected header_protocol values. Unknown protocol numbers stay opaque.
enum bit<32> sflow_header_protocol {
    ETHERNET = 1,
    IPV4 = 11,
    IPV6 = 12,
    MPLS = 13,
    POS = 14
}

// Address is an XDR discriminated union: unknown has no address bytes.
header sflow_datagram_prefix_t {
    bit<32> version;
    bit<32> agent_address_type;
}

// Complete IPv4 datagram header, 28 bytes, followed by sample_count samples.
header sflow_datagram_header {
    bit<32> version;
    bit<32> agent_address_type; // 1
    bit<32> agent_address;
    bit<32> sub_agent_id;
    bit<32> sequence_number;
    bit<32> uptime;             // Milliseconds since boot, wraps at 2^32
    bit<32> sample_count;
}

// Complete IPv6 datagram header, 40 bytes. Address family is independent of UDP.
header sflow_datagram_ipv6_t {
    bit<32> version;
    bit<32> agent_address_type; // 2
    bit<128> agent_address;
    bit<32> sub_agent_id;
    bit<32> sequence_number;
    bit<32> uptime;
    bit<32> sample_count;
}

// Complete unknown-address datagram header, 24 bytes (address type 0).
header sflow_datagram_unknown_t {
    bit<32> version;
    bit<32> agent_address_type;
    bit<32> sub_agent_id;
    bit<32> sequence_number;
    bit<32> uptime;
    bit<32> sample_count;
}

/* Sample prefix, eight bytes. Data Format is enterprise (20 bits) and format
 * (12 bits). sample_length counts only the sample body, excluding this prefix
 * and its trailing XDR padding. Every opaque value is padded to four bytes.
 */
header sflow_sample_header {
    bit<20> enterprise;
    bit<12> format;
    bit<32> sample_length;
}

// Bounded complete sample view for ordinary UDP. Keep body and XDR pad together.
header sflow_sample_t {
    bit<20> enterprise;
    bit<12> format;
    bit<32> sample_length;
    varbit<524256> padded_value;
}

/* Compact flow prefix, 32 bytes (sample_data 0:1). Source ID packs type into
 * the high byte and index into the low 24 bits. Interface words pack format
 * into two high bits and value into 30 bits. Input format is 0. Output format
 * 0 selects one interface, 1 a discard reason, 2 multiple destinations.
 * Value 0 is unknown, and format 0 value 0x3FFFFFFF means device-local traffic.
 * sequence_number belongs to the sampling instance, as clarified by errata.
 */
header sflow_flow_sample {
    bit<32> sequence_number;
    bit<8> source_id_type;
    bit<24> source_id_index;
    bit<32> sampling_rate;
    bit<32> sample_pool;
    bit<32> dropped_packets;
    bit<2> input_format;
    bit<30> input_value;
    bit<2> output_format;
    bit<30> output_value;
    bit<32> record_count;
}

// Compact counter prefix, 12 bytes (sample_data 0:2).
header sflow_counter_sample {
    bit<32> sequence_number;
    bit<8> source_id_type;
    bit<24> source_id_index;
    bit<32> record_count;
}

/* Expanded flow prefix, 44 bytes (sample_data 0:3). Source and interface fields
 * use full XDR words. Format 0 value 0xFFFFFFFF means device-local traffic.
 * An agent uses compact or expanded encodings consistently across interfaces.
 */
header sflow_flow_sample_expanded_t {
    bit<32> sequence_number;
    bit<32> source_id_type;
    bit<32> source_id_index;
    bit<32> sampling_rate;
    bit<32> sample_pool;
    bit<32> dropped_packets;
    bit<32> input_format;
    bit<32> input_value;
    bit<32> output_format;
    bit<32> output_value;
    bit<32> record_count;
}

// Expanded counter prefix, 16 bytes (sample_data 0:4).
header sflow_counter_sample_expanded_t {
    bit<32> sequence_number;
    bit<32> source_id_type;
    bit<32> source_id_index;
    bit<32> record_count;
}

// Record lengths count only opaque data, excluding prefix and XDR padding.
header sflow_flow_record {
    bit<20> enterprise;
    bit<12> format;
    bit<32> flow_data_length;
}

header sflow_counter_record {
    bit<20> enterprise;
    bit<12> format;
    bit<32> counter_data_length;
}

/* Sampled header (flow_data 0:1). header_length counts captured bytes only.
 * Extract that many bytes, then consume (-header_length) & 3 XDR pad bytes.
 * The capacity covers captured headers carried by ordinary UDP.
 * frame_length includes FCS for layer 2. For an ordinary Ethernet sample,
 * stripped_bytes includes at least the four FCS bytes removed before sampling.
 */
header sflow_raw_packet_header {
    bit<32> protocol;
    bit<32> frame_length;
    bit<32> stripped_bytes;
    bit<32> header_length;
    varbit<524256> header_bytes;
}

header sflow_xdr_padding_t {
    varbit<24> bytes;
}

/* Sampled Ethernet (flow_data 0:2), 24 bytes. Each XDR opaque mac[6] has its
 * own two pad bytes. Packet type uses a 32-bit XDR word, not EtherType's width.
 */
header sflow_sampled_ethernet_t {
    bit<32> frame_length;
    bit<48> src_mac;
    bit<16> src_padding;
    bit<48> dst_mac;
    bit<16> dst_padding;
    bit<32> packet_type;
}

// Sampled IPv4 (flow_data 0:3), 32 bytes, excludes lower-layer encapsulation.
header sflow_sampled_ipv4_t {
    bit<32> length;
    bit<32> protocol;
    bit<32> src_ip;
    bit<32> dst_ip;
    bit<32> src_port;
    bit<32> dst_port;
    bit<32> tcp_flags;
    bit<32> tos;
}

// Sampled IPv6 (flow_data 0:4), 56 bytes. Port and flag fields remain XDR words.
header sflow_sampled_ipv6_t {
    bit<32> length;
    bit<32> protocol;
    bit<128> src_ip;
    bit<128> dst_ip;
    bit<32> src_port;
    bit<32> dst_port;
    bit<32> tcp_flags;
    bit<32> priority;
}

// Extended switch (flow_data 0:1001), 16 bytes. Errata uses 0xFFFFFFFF if unknown.
header sflow_extended_switch_t {
    bit<32> src_vlan;
    bit<32> src_priority;
    bit<32> dst_vlan;
    bit<32> dst_priority;
}

/* Generic interface counters (counter_data 0:1), 88 bytes. if_status bit 0
 * is administrative state, bit 1 operational state (1 = up). Counter maxima
 * indicate unavailable counters or can occur just before wrap to zero.
 */
header sflow_if_counters {
    bit<32> if_index;
    bit<32> if_type;
    bit<64> if_speed;
    bit<32> if_direction;
    bit<32> if_status;
    bit<64> if_in_octets;
    bit<32> if_in_ucast_pkts;
    bit<32> if_in_multicast_pkts;
    bit<32> if_in_broadcast_pkts;
    bit<32> if_in_discards;
    bit<32> if_in_errors;
    bit<32> if_in_unknown_protos;
    bit<64> if_out_octets;
    bit<32> if_out_ucast_pkts;
    bit<32> if_out_multicast_pkts;
    bit<32> if_out_broadcast_pkts;
    bit<32> if_out_discards;
    bit<32> if_out_errors;
    bit<32> if_promiscuous_mode;
}

// Ethernet counters (counter_data 0:2), 52 bytes.
header sflow_ethernet_counters_t {
    bit<32> alignment_errors;
    bit<32> fcs_errors;
    bit<32> single_collision_frames;
    bit<32> multiple_collision_frames;
    bit<32> sqe_test_errors;
    bit<32> deferred_transmissions;
    bit<32> late_collisions;
    bit<32> excessive_collisions;
    bit<32> internal_mac_transmit_errors;
    bit<32> carrier_sense_errors;
    bit<32> frame_too_longs;
    bit<32> internal_mac_receive_errors;
    bit<32> symbol_errors;
}

// UDP Length includes its eight-byte header. Reuse the standard transport type.
typedef udp_header sflow_transport_header;

struct sflow_headers_t {
    sflow_datagram_header ipv4;
    sflow_datagram_ipv6_t ipv6;
    sflow_datagram_unknown_t unknown;
    sflow_sample_t[16] samples;
}

struct sflow_metadata_t {
    bit<32> agent_address_type;
    bit<128> agent_address;
    bit<32> sub_agent_id;
    bit<32> sequence_number;
    bit<32> uptime;
    bit<32> declared_samples;
    bit<32> remaining_samples;
    bit<32> remaining_bytes;
    bit<5> parsed_samples;
    bool framing_complete;
    bit<5> flow_samples;
    bit<5> counter_samples;
    bit<5> expanded_flow_samples;
    bit<5> expanded_counter_samples;
    bit<5> other_samples;
}

/**
 * Bounded framing and local delivery (P4_16, v1model).
 * The cursor starts at sFlow version. The caller supplies the complete,
 * validated ordinary UDP payload size after IP reassembly and checksum checks.
 * Transport headers and link padding are outside datagram_bytes.
 *
 * Up to 16 top-level samples are extracted. remaining_samples and
 * remaining_bytes identify the untouched remainder at the limit. The end of
 * the declared array must coincide with the datagram end when it is reached.
 * Sample bodies and their XDR padding stay intact, including unknown formats
 * and appended fields permitted by the structure-extension rules.
 * Emit ipv4, ipv6, unknown and samples, then the original remainder.
 *
 * context_id selects the collector's configured input peer. The collector
 * checks XDR padding, decodes sample bodies and records using their lengths,
 * and interprets sampling-instance sequence numbers, counters and resets.
 */
/*
parser sflow_parser(packet_in pkt, out sflow_headers_t hdr,
                    out sflow_metadata_t meta, in bit<32> datagram_bytes) {
    bit<32> remaining;
    bit<32> samples_left;
    bit<32> padded_bytes;

    state start {
        sflow_datagram_prefix_t prefix;
        meta.agent_address_type = 0;
        meta.agent_address = 0;
        meta.sub_agent_id = 0;
        meta.sequence_number = 0;
        meta.uptime = 0;
        meta.declared_samples = 0;
        meta.remaining_samples = 0;
        meta.remaining_bytes = datagram_bytes;
        meta.parsed_samples = 0;
        meta.framing_complete = false;
        meta.flow_samples = 0;
        meta.counter_samples = 0;
        meta.expanded_flow_samples = 0;
        meta.expanded_counter_samples = 0;
        meta.other_samples = 0;
        verify(datagram_bytes >= 8, error.HeaderTooShort);
        verify(datagram_bytes <= SFLOW_MAX_DATAGRAM_BYTES, error.NoMatch);
        verify((datagram_bytes & 3) == 0, error.NoMatch);
        prefix = pkt.lookahead<sflow_datagram_prefix_t>();
        verify(prefix.version == sflow_version.V5, error.NoMatch);
        meta.agent_address_type = prefix.agent_address_type;
        remaining = datagram_bytes;
        transition select(prefix.agent_address_type) {
            sflow_address_type.UNKNOWN: parse_unknown;
            sflow_address_type.IPV4: parse_ipv4;
            sflow_address_type.IPV6: parse_ipv6;
            default: unsupported;
        }
    }

    state unsupported {
        verify(false, error.NoMatch);
        transition accept;
    }

    state parse_unknown {
        verify(remaining >= 24, error.HeaderTooShort);
        pkt.extract(hdr.unknown);
        meta.sub_agent_id = hdr.unknown.sub_agent_id;
        meta.sequence_number = hdr.unknown.sequence_number;
        meta.uptime = hdr.unknown.uptime;
        samples_left = hdr.unknown.sample_count;
        remaining = remaining - 24;
        transition start_samples;
    }

    state parse_ipv4 {
        verify(remaining >= 28, error.HeaderTooShort);
        pkt.extract(hdr.ipv4);
        meta.agent_address = (bit<128>)hdr.ipv4.agent_address;
        meta.sub_agent_id = hdr.ipv4.sub_agent_id;
        meta.sequence_number = hdr.ipv4.sequence_number;
        meta.uptime = hdr.ipv4.uptime;
        samples_left = hdr.ipv4.sample_count;
        remaining = remaining - 28;
        transition start_samples;
    }

    state parse_ipv6 {
        verify(remaining >= 40, error.HeaderTooShort);
        pkt.extract(hdr.ipv6);
        meta.agent_address = hdr.ipv6.agent_address;
        meta.sub_agent_id = hdr.ipv6.sub_agent_id;
        meta.sequence_number = hdr.ipv6.sequence_number;
        meta.uptime = hdr.ipv6.uptime;
        samples_left = hdr.ipv6.sample_count;
        remaining = remaining - 40;
        transition start_samples;
    }

    state start_samples {
        meta.declared_samples = samples_left;
        transition check_sample;
    }

    state check_sample {
        meta.remaining_samples = samples_left;
        meta.remaining_bytes = remaining;
        verify(samples_left <= (remaining >> 3), error.HeaderTooShort);
        transition select(samples_left, meta.parsed_samples) {
            (0, _): end_datagram;
            (_, 16): accept;
            default: parse_sample;
        }
    }

    state end_datagram {
        verify(remaining == 0, error.NoMatch);
        meta.framing_complete = true;
        transition accept;
    }

    state parse_sample {
        sflow_sample_header prefix;
        verify(remaining >= 8, error.HeaderTooShort);
        prefix = pkt.lookahead<sflow_sample_header>();
        verify(prefix.sample_length <= remaining - 8, error.HeaderTooShort);
        padded_bytes = (prefix.sample_length + 3) & 0xFFFFFFFC;
        verify(padded_bytes <= remaining - 8, error.HeaderTooShort);
        pkt.extract(hdr.samples.next, padded_bytes * 8);
        if (prefix.enterprise == SFLOW_STANDARD_ENTERPRISE) {
            if (prefix.format == sflow_sample_format.FLOW) {
                meta.flow_samples = meta.flow_samples + 1;
            } else if (prefix.format == sflow_sample_format.COUNTER) {
                meta.counter_samples = meta.counter_samples + 1;
            } else if (prefix.format == sflow_sample_format.FLOW_EXPANDED) {
                meta.expanded_flow_samples = meta.expanded_flow_samples + 1;
            } else if (prefix.format == sflow_sample_format.COUNTER_EXPANDED) {
                meta.expanded_counter_samples = meta.expanded_counter_samples + 1;
            } else {
                meta.other_samples = meta.other_samples + 1;
            }
        } else {
            meta.other_samples = meta.other_samples + 1;
        }
        meta.parsed_samples = meta.parsed_samples + 1;
        remaining = remaining - 8 - padded_bytes;
        samples_left = samples_left - 1;
        transition check_sample;
    }
}

control sflow_control(inout sflow_headers_t hdr, in sflow_metadata_t meta,
                      inout standard_metadata_t standard_metadata,
                      in bit<32> context_id) {
    action deliver_sflow(bit<9> collector_port) {
        standard_metadata.egress_spec = collector_port;
    }

    action drop_sflow() {
        mark_to_drop(standard_metadata);
    }

    table sflow_collectors {
        key = {
            context_id: exact;
            meta.agent_address_type: exact;
            meta.agent_address: exact;
            meta.sub_agent_id: exact;
        }
        actions = {
            deliver_sflow;
            drop_sflow;
        }
        default_action = drop_sflow();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError) {
            drop_sflow();
        } else {
            sflow_collectors.apply();
        }
    }
}
*/

#endif
