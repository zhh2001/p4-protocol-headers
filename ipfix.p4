#ifndef P4_PROTOCOL_HEADERS_IPFIX_P4
#define P4_PROTOCOL_HEADERS_IPFIX_P4

#include "udp.p4"

/**
 * IPFIX message, Set and Template formats (RFC 7011, RFC 7012)
 * IPFIX 消息、集合、模板与有界解析示例
 */
const bit<16> IPFIX_VERSION = 10;
const bit<16> IPFIX_PORT = 4739; // UDP, TCP and SCTP
const bit<16> IPFIX_SECURE_PORT = 4740; // TLS/TCP or DTLS/SCTP and DTLS/UDP
const bit<16> IPFIX_DATA_SET_MIN_ID = 256;
const bit<16> IPFIX_VARIABLE_FIELD_LENGTH = 65535;
const bit<32> IPFIX_MAX_MESSAGE_BYTES = 65535;

// There is one message format. Set IDs distinguish the contained records.
enum bit<16> ipfix_set_id {
    TEMPLATE = 2,
    OPTIONS_TEMPLATE = 3
}

/* Message header, 16 bytes. Length includes this header and every Set.
 * Export Time is unsigned UNIX seconds. Sequence Number counts Data Records
 * sent before this message, modulo 2^32, per stream and Observation Domain
 * (RFC 7011 erratum 4396). Template and Options Template Records do not advance
 * it. SCTP counts each stream separately. TCP and UDP use one per Transport Session.
 */
header ipfix_header {
    bit<16> version;
    bit<16> length;
    bit<32> export_time;
    bit<32> sequence_number;
    bit<32> observation_domain_id;
}

/* Set prefix, four bytes. Length includes prefix, records and any padding.
 * IDs 0 and 1 are unused. IDs 4..255 are reserved for future use. Data Sets
 * use their Template ID (256..65535), for both ordinary and Options data.
 * Set padding is sent as zero and is shorter than any record in the Set.
 * Reception of nonzero padding alone does not make a message malformed.
 * Sets have no mandatory alignment. Locate the next Set using Length.
 */
header ipfix_set_header {
    bit<16> set_id;
    bit<16> length;
}

// Complete Set view. Capacity is (65535 - 16 - 4) bytes for records and padding.
header ipfix_set_t {
    bit<16> set_id;
    bit<16> length;
    varbit<524120> records_and_padding;
}

/* Ordinary Template prefix, four bytes, followed by field_count specifiers.
 * Template IDs 256..65535 are scoped to Transport Session + Observation Domain
 * and share one namespace with Options Templates. Field order is significant.
 */
header ipfix_template_header {
    bit<16> template_id;
    bit<16> field_count;
}

/* Options Template prefix, six bytes, followed by field_count specifiers.
 * The first scope_field_count are scope fields, included in field_count.
 * A definition has 1 <= scope_field_count <= field_count.
 */
header ipfix_options_template_header_t {
    bit<16> template_id;
    bit<16> field_count;
    bit<16> scope_field_count;
}

/* Withdrawal is four bytes for both Template kinds: Template ID and zero
 * Field Count, without Scope Field Count. ID 2 in Set 2 withdraws all ordinary
 * Templates. ID 3 in Set 3 withdraws all Options Templates. Individual IDs
 * are 256..65535. Withdrawals are used over TCP/SCTP, not UDP.
 */
typedef ipfix_template_header ipfix_template_withdrawal_t;

/* Common Field Specifier prefix, four bytes. E = 0 identifies an IANA IE and
 * has no Enterprise Number. E = 1 is followed by a four-byte Enterprise Number.
 * Field Length is the encoded value size, or 65535 for a variable-length IE.
 * Integer fields may use reduced-size encoding, so the Template sets width.
 */
header ipfix_field_specifier {
    bit<1> enterprise_bit;
    bit<15> field_id;
    bit<16> field_length;
}

header ipfix_enterprise_number_t {
    bit<32> enterprise_number;
}

// Complete eight-byte Field Specifier for E = 1.
header ipfix_enterprise_field_specifier_t {
    bit<1> enterprise_bit;
    bit<15> field_id;
    bit<16> field_length;
    bit<32> enterprise_number;
}

/* Variable-length IE prefix. Values 0..254 give the value length directly.
 * A first byte of 255 selects the three-byte form below. Length excludes
 * the one or three prefix bytes. The extended form can encode 0..65535.
 */
header ipfix_variable_length_t {
    bit<8> length;
}

header ipfix_variable_length_extended_t {
    bit<8> marker; // 255
    bit<16> length;
}

// One Data Record, with order and encoded size supplied by its cached Template.
header ipfix_data_record {
    varbit<524120> fields;
}

/* Example 29-byte record layout, all E = 0, with IE/length pairs in order:
 * 8/4, 12/4, 7/2, 11/2, 4/1, 2/8, 1/8. Use this view only when the Template
 * specifies exactly this order and these lengths. Records have no fixed pad.
 */
header ipfix_common_flow_fields {
    bit<32> source_ipv4_address;
    bit<32> destination_ipv4_address;
    bit<16> source_transport_port;
    bit<16> destination_transport_port;
    bit<8> protocol_identifier;
    bit<64> packet_delta_count;
    bit<64> octet_delta_count;
}

// UDP view only. UDP Length includes its eight-byte header. TCP/SCTP are separate.
typedef udp_header ipfix_transport_header;

struct ipfix_headers_t {
    ipfix_header message;
    ipfix_set_t[16] sets;
}

struct ipfix_metadata_t {
    bit<32> remaining_bytes;
    bit<5> parsed_sets;
    bit<5> template_sets;
    bit<5> options_template_sets;
    bit<5> data_sets;
    bit<5> other_sets;
    bool framing_complete;
}

/**
 * Bounded Set framing and local delivery (P4_16, v1model).
 * The cursor starts at Version. message_bytes bounds one complete message
 * supplied after TCP/SCTP reassembly or UDP validation, and TLS/DTLS decoding
 * when used. The UDP caller uses the complete datagram payload as the bound
 * and validates the UDP checksum, including IPv4. Transport headers and link
 * padding are outside message_bytes. Following stream data belongs to the caller.
 *
 * Up to 16 Sets are extracted. remaining_bytes identifies the untouched
 * remainder at the limit. Emit message and sets, then the original remainder.
 * Set bodies, padding and future Set types stay intact. The collector decodes
 * Templates, withdrawals, variable-length values and reduced-size integers.
 * It keys Templates by Transport Session, Observation Domain and Template ID,
 * and tracks sequence numbers per stream and Observation Domain. session_id
 * identifies the configured Transport Session independently of wire identifiers.
 */
/*
parser ipfix_parser(packet_in pkt, out ipfix_headers_t hdr,
                    out ipfix_metadata_t meta, in bit<32> message_bytes) {
    bit<32> remaining;

    state start {
        meta.remaining_bytes = message_bytes;
        meta.parsed_sets = 0;
        meta.template_sets = 0;
        meta.options_template_sets = 0;
        meta.data_sets = 0;
        meta.other_sets = 0;
        meta.framing_complete = false;
        verify(message_bytes >= 16, error.HeaderTooShort);
        verify(message_bytes <= IPFIX_MAX_MESSAGE_BYTES, error.NoMatch);
        pkt.extract(hdr.message);
        verify(hdr.message.version == IPFIX_VERSION, error.NoMatch);
        verify((bit<32>)hdr.message.length == message_bytes, error.NoMatch);
        remaining = message_bytes - 16;
        transition check_set;
    }

    state check_set {
        meta.remaining_bytes = remaining;
        verify(remaining == 0 || remaining >= 4, error.HeaderTooShort);
        transition select(remaining, meta.parsed_sets) {
            (0, _): end_message;
            (_, 16): accept;
            default: parse_set;
        }
    }

    state end_message {
        meta.framing_complete = true;
        transition accept;
    }

    state parse_set {
        ipfix_set_header prefix;
        prefix = pkt.lookahead<ipfix_set_header>();
        verify(prefix.set_id >= 2, error.NoMatch);
        verify(prefix.length >= 4, error.NoMatch);
        verify((bit<32>)prefix.length <= remaining, error.HeaderTooShort);
        pkt.extract(hdr.sets.next, ((bit<32>)prefix.length - 4) * 8);
        if (prefix.set_id == ipfix_set_id.TEMPLATE) {
            meta.template_sets = meta.template_sets + 1;
        } else if (prefix.set_id == ipfix_set_id.OPTIONS_TEMPLATE) {
            meta.options_template_sets = meta.options_template_sets + 1;
        } else if (prefix.set_id >= IPFIX_DATA_SET_MIN_ID) {
            meta.data_sets = meta.data_sets + 1;
        } else {
            meta.other_sets = meta.other_sets + 1;
        }
        meta.parsed_sets = meta.parsed_sets + 1;
        remaining = remaining - (bit<32>)prefix.length;
        transition check_set;
    }
}

control ipfix_control(inout ipfix_headers_t hdr, in ipfix_metadata_t meta,
                      inout standard_metadata_t standard_metadata,
                      in bit<32> session_id) {
    action deliver_ipfix(bit<9> collector_port) {
        standard_metadata.egress_spec = collector_port;
    }

    action drop_ipfix() {
        mark_to_drop(standard_metadata);
    }

    table ipfix_collectors {
        key = {
            session_id: exact;
            hdr.message.observation_domain_id: exact;
        }
        actions = {
            deliver_ipfix;
            drop_ipfix;
        }
        default_action = drop_ipfix();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError) {
            drop_ipfix();
        } else {
            ipfix_collectors.apply();
        }
    }
}
*/

#endif
