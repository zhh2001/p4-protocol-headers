/**
 * STP and RSTP BPDUs (IEEE 802.1D-2004, Clause 9 and IEEE 802.1Q, Clause 14)
 * 标准 BPDU 报头、LLC 封装和本地解析示例
 */
#ifndef P4_PROTOCOL_HEADERS_STP_P4
#define P4_PROTOCOL_HEADERS_STP_P4

const bit<16> STP_PROTOCOL_ID = 0;
const bit<8> STP_VERSION = 0;
const bit<8> RSTP_VERSION = 2;
const bit<8> MSTP_VERSION = 3;
const bit<8> STP_BPDU_CONFIG = 8w0x00;
const bit<8> STP_BPDU_TCN = 8w0x80;
const bit<8> RSTP_BPDU = 8w0x02; // Also the type used by MST/SPT BPDUs

const bit<48> STP_MULTICAST = 48w0x0180c2000000;
const bit<8> STP_LLC_SAP = 8w0x42;
const bit<8> STP_LLC_CONTROL = 8w0x03; // Unnumbered Information
const bit<32> STP_TIMER_UNITS_PER_SECOND = 256;

const bit<8> STP_FLAG_TC = 8w0x01;
const bit<8> STP_FLAG_TCA = 8w0x80; // Configuration BPDU only
const bit<8> RSTP_FLAG_PROPOSAL = 8w0x02;
const bit<8> RSTP_FLAG_ROLE_MASK = 8w0x0c;
const bit<8> RSTP_FLAG_LEARNING = 8w0x10;
const bit<8> RSTP_FLAG_FORWARDING = 8w0x20;
const bit<8> RSTP_FLAG_AGREEMENT = 8w0x40;

// Role values after shifting (flags & RSTP_FLAG_ROLE_MASK) right by two.
// Alternate and Backup share an encoding. The protocol state distinguishes
// them. Unknown role is handled by the state machine, rather than rejected.
const bit<2> RSTP_ROLE_UNKNOWN = 0;
const bit<2> RSTP_ROLE_ALTERNATE_BACKUP = 1;
const bit<2> RSTP_ROLE_ROOT = 2;
const bit<2> RSTP_ROLE_DESIGNATED = 3;

// Ethernet 802.3 carrier. length counts LLC and BPDU octets, excluding this
// header, Ethernet padding and FCS. Standard BPDUs use LLC, not an EtherType
// or a vendor-specific SNAP/PVST encapsulation. Destination acceptance for
// an S-component or another bridge context uses its applicable group address.
header stp_transport {
    bit<48> dst_mac;
    bit<48> src_mac;
    bit<16> length;
}

header stp_llc_t {
    bit<8> dsap; // 0x42
    bit<8> ssap; // 0x42
    bit<8> control_field; // 0x03
}

// Common four-octet prefix. A TCN BPDU consists only of this prefix.
// Transmit STP Config/TCN with version 0, type 0x00/0x80 respectively.
// Receive validation for those two types does not restrict version.
header stp_prefix {
    bit<16> protocol_id;
    bit<8> version;
    bit<8> bpdu_type;
}

typedef stp_prefix stp_tcn_t;

// Thirty-one octets following stp_prefix in Config/RST BPDUs. Bridge IDs
// split the priority nibble and twelve-bit system ID extension explicitly.
// A priority nibble of 8 represents the managed bridge priority 32768.
// Port priority 8 represents managed priority 128. Port numbers are 1..4095.
// All multioctet integers use network byte order. Timer values are unsigned
// units of 1/256 second, including fractional seconds, and are not seconds.
header stp_config_body {
    bit<8> flags;
    bit<4> root_priority;
    bit<12> root_system_id_extension;
    bit<48> root_mac;
    bit<32> root_path_cost;
    bit<4> bridge_priority;
    bit<12> bridge_system_id_extension;
    bit<48> bridge_mac;
    bit<4> port_priority;
    bit<12> port_number;
    bit<16> message_age;
    bit<16> max_age;
    bit<16> hello_time;
    bit<16> forward_delay;
}

// Complete thirty-five-octet Config BPDU as an alternative to prefix/body.
// The packed port_id holds a priority nibble and a twelve-bit port number.
// Append rstp_ext_t for a complete thirty-six-octet RST BPDU. This view is
// not a TCN header and does not include the later MST/SPT extensions.
// Do not emit it alongside a separate stp_prefix and stp_config_body.
header stp_t {
    bit<16> protocol_id;
    bit<8> version;
    bit<8> bpdu_type;
    bit<8> flags;
    bit<4> root_priority;
    bit<12> root_system_id_extension;
    bit<48> root_mac;
    bit<32> root_path_cost;
    bit<4> bridge_priority;
    bit<12> bridge_system_id_extension;
    bit<48> bridge_mac;
    bit<16> port_id;
    bit<16> message_age;
    bit<16> max_age;
    bit<16> hello_time;
    bit<16> forward_delay;
}

// Octet 36 of an RST/MST/SPT BPDU. Transmit zero in version 2. A version 2
// RST receiver does not use this byte to validate the BPDU. MST/SPT parsing
// also uses it when classifying later formats under IEEE 802.1Q, 14.5.
header rstp_ext_t {
    bit<8> version1_length;
}

// Config uses only TC and TCA. Other bits are zero on transmission and
// ignored on receipt. RST uses TC, Proposal, Role, Learning, Forwarding and
// Agreement. Its bit 7 (0x80) is unused, transmitted zero and ignored on
// receipt. The same position is an MSTI Master flag in an MSTI message,
// which is a different format. Flags alone never set a local port's state.

struct stp_metadata_t {
    bit<32> bpdu_bytes; // Excludes LLC and Ethernet pad
    bit<32> parsed_bytes; // Includes LLC
    bit<32> unparsed_bytes; // BPDU tail plus retained Ethernet pad
    bit<32> tail_bytes; // Unparsed bytes within the declared link length
    bit<32> padding_bytes;
}

/**
 * Bounded LLC and BPDU prefix parser
 * The cursor starts at LLC. headers contains stp_llc_t stp_llc,
 * stp_prefix stp, stp_config_body stp_info and rstp_ext_t rstp.
 * metadata contains stp_metadata_t stp. Emit valid headers in that order.
 * The enclosing parser supplies the 802.3 declared_length and physically
 * bounded payload_length, excluding the MAC header and FCS. It validates
 * the destination for the receiving bridge context and retains port identity.
 *
 * The parser handles Config, TCN and the common rapid prefix. It checks
 * LLC, Protocol Identifier, type and available bytes. Config/TCN version
 * values remain unrestricted for interoperability (IEEE 802.1Q, 14.6).
 * Version 2 rapid BPDUs need 36 octets. Version 3 or later common information
 * can occupy 35 octets under the RST fallback rules in 14.5. Extract octet 36
 * only when it is within the declared BPDU, never from Ethernet padding.
 *
 * Later MST/SPT information remains unparsed and unchanged. The application
 * classifies and validates those formats using version, remaining lengths
 * and configured bridge mode. No complete MST/SPT decoding is implied here.
 * Its state machines also validate timer use, priority vectors, loopback
 * conditions, reserved parameters and protocol migration as applicable.
 * In particular, an expired Message Age is not a parser error for RST.
 * The pipeline preserves received flags and Version 1 Length for the handler.
 */
/*
parser stp_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                  in bit<16> declared_length, in bit<32> payload_length) {
    state start {
        hdr.stp_llc.setInvalid();
        hdr.stp.setInvalid();
        hdr.stp_info.setInvalid();
        hdr.rstp.setInvalid();
        meta.stp.bpdu_bytes = 0;
        meta.stp.parsed_bytes = 0;
        meta.stp.unparsed_bytes = payload_length;
        meta.stp.tail_bytes = 0;
        meta.stp.padding_bytes = 0;
        verify(declared_length <= 1500, error.NoMatch);
        verify(declared_length >= 7, error.HeaderTooShort);
        verify((bit<32>) declared_length <= payload_length,
               error.HeaderTooShort);
        pkt.extract(hdr.stp_llc);
        verify(hdr.stp_llc.dsap == STP_LLC_SAP
               && hdr.stp_llc.ssap == STP_LLC_SAP
               && hdr.stp_llc.control_field == STP_LLC_CONTROL, error.NoMatch);
        pkt.extract(hdr.stp);
        verify(hdr.stp.protocol_id == STP_PROTOCOL_ID, error.NoMatch);
        meta.stp.bpdu_bytes = (bit<32>) declared_length - 3;
        meta.stp.parsed_bytes = 7;
        meta.stp.padding_bytes = payload_length - (bit<32>) declared_length;
        transition select(hdr.stp.bpdu_type) {
            STP_BPDU_CONFIG: parse_config;
            STP_BPDU_TCN: finish;
            RSTP_BPDU: parse_rapid;
            default: unsupported_type;
        }
    }

    state parse_config {
        verify(declared_length >= 38, error.HeaderTooShort);
        pkt.extract(hdr.stp_info);
        meta.stp.parsed_bytes = 38;
        transition finish;
    }

    state parse_rapid {
        verify(hdr.stp.version >= RSTP_VERSION, error.NoMatch);
        verify(declared_length >= 38, error.HeaderTooShort);
        verify(hdr.stp.version >= MSTP_VERSION || declared_length >= 39,
               error.HeaderTooShort);
        pkt.extract(hdr.stp_info);
        meta.stp.parsed_bytes = 38;
        transition select(declared_length) {
            38: finish;
            default: parse_version1_length;
        }
    }

    state parse_version1_length {
        pkt.extract(hdr.rstp);
        meta.stp.parsed_bytes = 39;
        transition finish;
    }

    state finish {
        meta.stp.unparsed_bytes = payload_length - meta.stp.parsed_bytes;
        meta.stp.tail_bytes = (bit<32>) declared_length - meta.stp.parsed_bytes;
        transition accept;
    }

    state unsupported_type {
        verify(false, error.NoMatch);
        transition accept;
    }
}
*/

/**
 * Local BPDU application delivery (v1model)
 * The table selects a spanning tree handler by receiving port and BPDU type.
 * handler_port and action ports denote local application endpoints, such as
 * a CPU port. BPDUs are consumed locally, not relayed as ordinary data.
 * Parser errors drop the packet. Root selection, timer expiry, topology
 * changes, forwarding state and FDB updates require a spanning tree protocol
 * entity outside this pipeline. Keep the original receiving port with the
 * delivered BPDU. A flag or advertised Port Role never directly opens a port.
 */
/*
control stp_control(inout headers hdr,
                    inout standard_metadata_t standard_metadata,
                    in bit<9> handler_port) {
    action send_bpdu(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action send_default() {
        standard_metadata.egress_spec = handler_port;
    }

    table stp_handlers {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.stp.bpdu_type: exact;
        }
        actions = {
            send_bpdu;
            send_default;
        }
        default_action = send_default();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.stp_llc.isValid() || !hdr.stp.isValid()) {
            mark_to_drop(standard_metadata);
        } else {
            stp_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_STP_P4
