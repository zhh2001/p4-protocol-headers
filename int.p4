#ifndef P4_PROTOCOL_HEADERS_INT_P4
#define P4_PROTOCOL_HEADERS_INT_P4

#include "udp.p4"

/**
 * INT Dataplane 2.1 and Telemetry Report Format 2.0 (P4.org)
 * INT 报头、按指令选择的元数据字段与遥测报告
 * Both formats encode version 2. Encapsulation markers and UDP report ports
 * are configured by the deployment. INT-XD adds no header to the data packet.
 */
const bit<4> INT_VERSION = 2;
const bit<4> INT_REPORT_VERSION = 2;
const bit<16> INT_GENEVE_OPTION_CLASS = 0x0103;
const bit<32> INT_REPORT_MAX_UDP_BYTES = 65527;

enum bit<4> int_header_type {
    MD = 1,
    DESTINATION = 2, // Payload format is not defined in INT 2.1
    MX = 3
}

enum bit<2> int_next_protocol_type {
    DSCP = 0,
    UDP_PORT = 1,
    IP_PROTOCOL = 2
}

// Instruction bit 0 is the MSB. Bits 4, 5 and 6 request two words each.
const bit<16> INT_MD_NODE_ID = 0x8000;
const bit<16> INT_MD_L1_INTERFACES = 0x4000;
const bit<16> INT_MD_HOP_LATENCY = 0x2000;
const bit<16> INT_MD_QUEUE = 0x1000;
const bit<16> INT_MD_INGRESS_TIMESTAMP = 0x0800;
const bit<16> INT_MD_EGRESS_TIMESTAMP = 0x0400;
const bit<16> INT_MD_L2_INTERFACES = 0x0200;
const bit<16> INT_MD_TX_UTILIZATION = 0x0100;
const bit<16> INT_MD_BUFFER = 0x0080;
const bit<16> INT_MD_CHECKSUM_COMPLEMENT = 0x0001; // MD only, last per-hop field
const bit<16> INT_REPORT_MD_DROP_REASON = 0x0001; // Bit 15 means Drop Reason in reports

/* TCP/UDP Shim, four bytes. Length counts following INT words, excluding
 * this Shim. NPT = 0 carries reserved[8], original DSCP[6], reserved[2].
 * NPT = 1 carries the original UDP destination port. NPT = 2 carries a reserved
 * byte and the original IP protocol byte. NPT is zero for DSCP/probe marking.
 * Reserved bits are sent as zero and ignored on reception.
 */
header int_shim_header {
    bit<4> int_type;
    bit<2> next_protocol_type;
    bit<2> reserved;
    bit<8> length;
    bit<16> next_protocol_data;
}

// Eight-byte probe marker before the TCP/UDP Shim, when that marking is used.
header int_probe_marker_t {
    bit<64> value;
}

// GRE Shim: Length excludes this word. Next Protocol is an EtherType.
header int_gre_shim_t {
    bit<4> int_type;
    bit<1> gre_inserted;
    bit<3> reserved;
    bit<8> length;
    bit<16> next_protocol;
}

// VXLAN-GPE Shim: G records conversion from VXLAN. Length excludes this word.
header int_vxlan_gpe_shim_t {
    bit<4> int_type;
    bit<4> reserved1;
    bit<8> length;
    bit<1> vxlan_converted;
    bit<7> reserved2;
    bit<8> next_protocol;
}

/* INT-MD fixed header, 12 bytes. D requests discard at the INT sink after
 * extraction. E records exhausted hop budget and M records an MTU limit.
 * Hop ML counts four-byte words per hop, including per-hop domain metadata.
 * Remaining Hop Count is decremented only when a node adds its metadata.
 * Reserved fields are sent as zero and ignored on reception.
 */
header int_metadata_header {
    bit<4> version;
    bit<1> discard;
    bit<1> hop_limit_exceeded;
    bit<1> mtu_exceeded;
    bit<12> reserved;
    bit<5> hop_metadata_length;
    bit<8> remaining_hop_count;
    bit<16> instruction_bitmap;
    bit<16> domain_id;
    bit<16> domain_instructions;
    bit<16> domain_flags;
}

// INT-MX fixed header, 12 bytes. Optional source-inserted domain metadata follows.
header int_mx_header_t {
    bit<4> version;
    bit<1> discard;
    bit<27> reserved;
    bit<16> instruction_bitmap;
    bit<16> domain_id;
    bit<16> domain_instructions;
    bit<16> domain_flags;
}

/* Per-hop fields appear in instruction-bit order, then domain metadata, then
 * Checksum Complement if requested. New hops prepend their metadata, so the
 * latest hop is first. Unavailable MD values are all ones in the field width.
 * The domain's metadata semantics define timestamp, latency, occupancy and
 * utilization units. Timestamps are device-local 64-bit values.
 */
header int_node_id_t {
    bit<32> node_id;
}

header int_l1_interfaces_t {
    bit<16> ingress_interface;
    bit<16> egress_interface;
}

header int_hop_latency_t {
    bit<32> value;
}

header int_queue_t {
    bit<8> queue_id;
    bit<24> occupancy;
}

header int_timestamp_t {
    bit<64> value;
}

header int_l2_interfaces_t {
    bit<32> ingress_interface;
    bit<32> egress_interface;
}

header int_tx_utilization_t {
    bit<32> value;
}

header int_buffer_t {
    bit<8> buffer_id;
    bit<24> occupancy;
}

// One complete four-byte Checksum Complement value, 0xFFFFFFFF if unused.
header int_checksum_complement_t {
    bit<32> value;
}

// Generic single-hop view, up to 31 words. Its layout follows the instructions.
header int_switch_metadata {
    varbit<992> fields;
}

/* Opaque Shim-bounded data. MD may have source-only domain metadata beyond
 * Hop ML, so the stack length alone does not always determine a hop count.
 * MX carries source-inserted domain data. The bound is 255 four-byte words.
 */
header int_data_t {
    varbit<8160> bytes;
}

/* Telemetry Report group header, eight bytes, one per UDP payload. Sequence
 * is 22 bits per (Node ID, Hardware ID, report destination). One or more
 * individual reports follow. Flow identity is in the reported packet bytes.
 */
header int_report_header {
    bit<4> version;
    bit<6> hardware_id;
    bit<22> sequence_number;
    bit<32> node_id;
}

enum bit<4> int_report_type {
    INNER_ONLY = 0,
    INT = 1,
    IOAM = 2 // Main-content format is not defined in Report 2.0
}

enum bit<4> int_report_inner_type {
    NONE = 0,
    TLV = 1,
    DOMAIN_EXTENSION = 2,
    ETHERNET = 3,
    IPV4 = 4,
    IPV6 = 5
}

/* Individual report prefix, four bytes. Report Length counts following words,
 * excluding this prefix. Value 255 extends to the UDP payload end and means
 * at least 255 words, so this is the last individual report. MD Length counts
 * optional metadata words, excluding the fixed main contents. For Inner Only,
 * MD Length is ignored. D/Q/F/I are report associations, distinct from MD flags.
 */
header int_report_prefix_t {
    bit<4> report_type;
    bit<4> inner_type;
    bit<8> report_length;
    bit<8> metadata_length;
    bit<1> dropped;
    bit<1> congested_queue;
    bit<1> tracked_flow;
    bit<1> intermediate;
    bit<4> reserved;
}

// Complete report view, with capacity for the rest of an ordinary UDP payload.
header int_report_t {
    bit<4> report_type;
    bit<4> inner_type;
    bit<8> report_length;
    bit<8> metadata_length;
    bit<1> dropped;
    bit<1> congested_queue;
    bit<1> tracked_flow;
    bit<1> intermediate;
    bit<4> reserved;
    varbit<524120> contents;
}

/* INT report fixed main contents, eight bytes, then optional baseline and
 * domain metadata. Baseline bit 0 is reserved because Node ID is in the group
 * header. Bit 15 carries Drop Reason below. Other baseline bits match INT.
 * Unavailable fields have their report bitmap bits cleared by the producer.
 */
header int_report_metadata_t {
    bit<16> metadata_bitmap;
    bit<16> domain_id;
    bit<16> domain_metadata_bitmap;
    bit<16> domain_status;
}

header int_report_drop_reason_t {
    bit<8> queue_id;
    bit<8> reason;
    bit<16> padding;
}

/* Report inner TLV prefix. Length counts value words, excluding this prefix.
 * Types 0/1/2/3 mean domain extension/Ethernet/IPv4/IPv6. Data Template selects
 * a domain-extension schema, and is ignored for the three packet types.
 */
header int_report_tlv_prefix_t {
    bit<4> tlv_type;
    bit<4> reserved;
    bit<8> length;
    bit<16> data_template;
}

header int_report_tlv_t {
    bit<4> tlv_type;
    bit<4> reserved;
    bit<8> length;
    bit<16> data_template;
    varbit<8160> value;
}

// UDP only. The report destination port is configured, without a fixed default.
typedef udp_header int_transport_header;

struct int_headers_t {
    int_shim_header shim;
    int_metadata_header md;
    int_mx_header_t mx;
    int_data_t data;
}

struct int_metadata_t {
    bit<32> int_bytes;
    bit<32> following_bytes;
    bit<16> domain_id;
    bit<16> instruction_bitmap;
    bool has_instructions;
}

struct int_report_headers_t {
    int_report_header group;
    int_report_t[16] reports;
}

struct int_report_metadata_state_t {
    bit<32> remaining_bytes;
    bit<5> parsed_reports;
    bit<5> int_reports;
    bit<5> other_reports;
    bool terminal_length_seen;
    bool framing_complete;
}

/**
 * TCP/UDP Shim parsing and report-group framing (P4_16, v1model).
 * The caller locates INT using the domain's configured encapsulation marker,
 * validates transport bounds/checksums and supplies bytes available at the
 * cursor. int_parser starts at a TCP/UDP Shim, consumes its declared INT data
 * and leaves the original payload untouched. Emit shim, md, mx and data.
 * Reserved bits are preserved. Destination/future types remain opaque.
 *
 * int_report_parser starts at the group header of a complete ordinary UDP
 * payload and extracts up to 16 individual reports. remaining_bytes identifies
 * an untouched remainder at the limit. Emit group and reports. In both paths,
 * emit the original remainder last. Report bodies, domain schemas and inner
 * packets are decoded by the collector. context_id identifies the configured
 * input. These controls deliver intact packets for processing by that input.
 */
/*
parser int_parser(packet_in pkt, out int_headers_t hdr,
                  out int_metadata_t meta, in bit<32> available_bytes) {
    bit<32> data_bytes;

    state start {
        meta.int_bytes = 0;
        meta.following_bytes = 0;
        meta.domain_id = 0;
        meta.instruction_bitmap = 0;
        meta.has_instructions = false;
        verify(available_bytes >= 4, error.HeaderTooShort);
        pkt.extract(hdr.shim);
        data_bytes = (bit<32>)hdr.shim.length * 4;
        verify(data_bytes <= available_bytes - 4, error.HeaderTooShort);
        meta.int_bytes = 4 + data_bytes;
        meta.following_bytes = available_bytes - meta.int_bytes;
        transition select(hdr.shim.int_type) {
            int_header_type.MD: parse_md;
            int_header_type.MX: parse_mx;
            default: parse_data;
        }
    }

    state parse_md {
        verify(data_bytes >= 12, error.HeaderTooShort);
        pkt.extract(hdr.md);
        verify(hdr.md.version == INT_VERSION, error.NoMatch);
        meta.domain_id = hdr.md.domain_id;
        meta.instruction_bitmap = hdr.md.instruction_bitmap;
        meta.has_instructions = true;
        data_bytes = data_bytes - 12;
        transition parse_data;
    }

    state parse_mx {
        verify(data_bytes >= 12, error.HeaderTooShort);
        pkt.extract(hdr.mx);
        verify(hdr.mx.version == INT_VERSION, error.NoMatch);
        meta.domain_id = hdr.mx.domain_id;
        meta.instruction_bitmap = hdr.mx.instruction_bitmap;
        meta.has_instructions = true;
        data_bytes = data_bytes - 12;
        transition parse_data;
    }

    state parse_data {
        pkt.extract(hdr.data, data_bytes * 8);
        transition accept;
    }
}

parser int_report_parser(packet_in pkt, out int_report_headers_t hdr,
                         out int_report_metadata_state_t meta,
                         in bit<32> datagram_bytes) {
    bit<32> remaining;
    bit<32> contents_bytes;

    state start {
        meta.remaining_bytes = datagram_bytes;
        meta.parsed_reports = 0;
        meta.int_reports = 0;
        meta.other_reports = 0;
        meta.terminal_length_seen = false;
        meta.framing_complete = false;
        verify(datagram_bytes >= 12, error.HeaderTooShort);
        verify(datagram_bytes <= INT_REPORT_MAX_UDP_BYTES, error.NoMatch);
        pkt.extract(hdr.group);
        verify(hdr.group.version == INT_REPORT_VERSION, error.NoMatch);
        remaining = datagram_bytes - 8;
        transition check_report;
    }

    state check_report {
        meta.remaining_bytes = remaining;
        verify(remaining == 0 || remaining >= 4, error.HeaderTooShort);
        transition select(remaining, meta.parsed_reports) {
            (0, _): end_group;
            (_, 16): accept;
            default: parse_report;
        }
    }

    state end_group {
        meta.framing_complete = true;
        transition accept;
    }

    state parse_report {
        int_report_prefix_t prefix;
        prefix = pkt.lookahead<int_report_prefix_t>();
        contents_bytes = (bit<32>)prefix.report_length * 4;
        if (prefix.report_length == 255) {
            verify(remaining - 4 >= contents_bytes, error.HeaderTooShort);
            contents_bytes = remaining - 4;
            meta.terminal_length_seen = true;
        }
        verify(contents_bytes <= remaining - 4, error.HeaderTooShort);
        if (prefix.report_type == int_report_type.INT) {
            verify(contents_bytes >= 8, error.HeaderTooShort);
            verify((bit<32>)prefix.metadata_length * 4 <= contents_bytes - 8,
                   error.HeaderTooShort);
            meta.int_reports = meta.int_reports + 1;
        } else {
            meta.other_reports = meta.other_reports + 1;
        }
        pkt.extract(hdr.reports.next, contents_bytes * 8);
        meta.parsed_reports = meta.parsed_reports + 1;
        remaining = remaining - 4 - contents_bytes;
        transition check_report;
    }
}

control int_control(inout int_headers_t hdr, in int_metadata_t meta,
                    inout standard_metadata_t standard_metadata,
                    in bit<32> context_id) {
    action deliver_int(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    action drop_int() {
        mark_to_drop(standard_metadata);
    }
    table int_inputs {
        key = {
            context_id: exact;
            hdr.shim.int_type: exact;
            meta.domain_id: exact;
        }
        actions = { deliver_int; drop_int; }
        default_action = drop_int();
    }
    apply {
        if (standard_metadata.parser_error != error.NoError) {
            drop_int();
        } else {
            int_inputs.apply();
        }
    }
}

control int_report_control(inout int_report_headers_t hdr,
                           in int_report_metadata_state_t meta,
                           inout standard_metadata_t standard_metadata,
                           in bit<32> context_id) {
    action deliver_report(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    action drop_report() {
        mark_to_drop(standard_metadata);
    }
    table report_inputs {
        key = {
            context_id: exact;
            hdr.group.node_id: exact;
            hdr.group.hardware_id: exact;
        }
        actions = { deliver_report; drop_report; }
        default_action = drop_report();
    }
    apply {
        if (standard_metadata.parser_error != error.NoError) {
            drop_report();
        } else {
            report_inputs.apply();
        }
    }
}
*/

#endif
