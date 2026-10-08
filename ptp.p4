/**
 * Precision Time Protocol headers (IEEE 1588-2008 and IEEE 1588-2019)
 * PTPv2 公共报头、固定消息体和 TLV
 */
#ifndef P4_PROTOCOL_HEADERS_PTP_P4
#define P4_PROTOCOL_HEADERS_PTP_P4

const bit<4> PTP_VERSION = 2;
const bit<16> PTP_ETHERTYPE = 16w0x88f7;
const bit<16> PTP_EVENT_PORT = 319;
const bit<16> PTP_GENERAL_PORT = 320;

enum bit<4> ptp_message_type {
    SYNC = 0x0,
    DELAY_REQ = 0x1,
    PDELAY_REQ = 0x2,
    PDELAY_RESP = 0x3,
    FOLLOW_UP = 0x8,
    DELAY_RESP = 0x9,
    PDELAY_RESP_FOLLOW_UP = 0xa,
    ANNOUNCE = 0xb,
    SIGNALING = 0xc,
    MANAGEMENT = 0xd
}

// Masks for the complete 16-bit flagField, in wire order.
const bit<16> PTP_FLAG_ALTERNATE_MASTER = 16w0x0100;
const bit<16> PTP_FLAG_TWO_STEP = 16w0x0200;
const bit<16> PTP_FLAG_UNICAST = 16w0x0400;
const bit<16> PTP_FLAG_LEAP_61 = 16w0x0001;
const bit<16> PTP_FLAG_LEAP_59 = 16w0x0002;
const bit<16> PTP_FLAG_UTC_OFFSET_VALID = 16w0x0004;
const bit<16> PTP_FLAG_TIMESCALE = 16w0x0008;
const bit<16> PTP_FLAG_TIME_TRACEABLE = 16w0x0010;
const bit<16> PTP_FLAG_FREQUENCY_TRACEABLE = 16w0x0020;
const bit<16> PTP_FLAG_SYNC_UNCERTAIN = 16w0x0040; // IEEE 1588-2019

/**
 * Common header (34 octets)
 * majorSdoId occupies the former transportSpecific nibble. minorVersionPTP
 * and minorSdoId occupy fields reserved in the 2008 edition. v2.0 uses minor
 * version 0, v2.1 uses 1. sdoId combines majorSdoId and minorSdoId into 12 bits.
 * messageTypeSpecific was reserved in 2008. Retain these fields on receipt.
 * messageLength includes this header, the fixed body and any suffix TLVs.
 * UDP and Ethernet headers and transport padding are outside that length.
 */
header ptp_header {
    bit<4> majorSdoId;
    bit<4> messageType;
    bit<4> minorVersionPTP;
    bit<4> versionPTP;
    bit<16> messageLength;
    bit<8> domainNumber;
    bit<8> minorSdoId;
    bit<16> flags;
    int<64> correctionField; // Signed nanoseconds * 2^16, including fractions
    bit<32> messageTypeSpecific;
    bit<80> sourcePortIdentity; // ClockIdentity (64) and portNumber (16)
    bit<16> sequenceId;
    bit<8> controlField;
    int<8> logMessageInterval; // Signed log2 seconds, with special wire values
}

// Timestamp is 10 octets. Fractions of a nanosecond are represented in
// correctionField, not appended to this timestamp. For an active timestamp,
// nanoseconds is 0..999999999. Meaning and validity depend on the message.
header ptp_timestamp {
    bit<48> seconds;
    bit<32> nanoseconds;
}

header ptp_port_identity {
    bit<64> clockIdentity;
    bit<16> portNumber;
}

header ptp_clock_quality {
    bit<8> clockClass;
    bit<8> clockAccuracy;
    bit<16> offsetScaledLogVariance;
}

// Fixed bodies follow the common header. Timestamp fields keep the full
// 80-bit wire value. Use ptp_timestamp as a field view when needed.
header ptp_sync {
    bit<80> originTimestamp;
}

header ptp_delay_req {
    bit<80> originTimestamp;
}

header ptp_pdelay_req {
    bit<80> originTimestamp;
    bit<80> reserved;
}

header ptp_pdelay_resp {
    bit<80> requestReceiptTimestamp;
    bit<80> requestingPortIdentity;
}

header ptp_follow_up {
    bit<80> preciseOriginTimestamp;
}

header ptp_delay_resp {
    bit<80> receiveTimestamp;
    bit<80> requestingPortIdentity;
}

header ptp_pdelay_resp_follow_up {
    bit<80> responseOriginTimestamp;
    bit<80> requestingPortIdentity;
}

header ptp_announce {
    bit<80> originTimestamp;
    int<16> currentUtcOffset;
    bit<8> reserved;
    bit<8> grandmasterPriority1;
    bit<32> grandmasterClockQuality; // clockClass (8), accuracy (8), variance (16)
    bit<8> grandmasterPriority2;
    bit<64> grandmasterIdentity;
    bit<16> stepsRemoved;
    bit<8> timeSource;
}

header ptp_signaling {
    bit<80> targetPortIdentity;
}

header ptp_management {
    bit<80> targetPortIdentity;
    bit<8> startingBoundaryHops;
    bit<8> boundaryHops;
    bit<4> reserved1;
    bit<4> actionField;
    bit<8> reserved2;
}

enum bit<4> ptp_management_action {
    GET = 0,
    SET = 1,
    RESPONSE = 2,
    COMMAND = 3,
    ACKNOWLEDGE = 4
}

const bit<16> PTP_TLV_MANAGEMENT = 16w0x0001;
const bit<16> PTP_TLV_MANAGEMENT_ERROR_STATUS = 16w0x0002;
const bit<16> PTP_TLV_ORGANIZATION_EXTENSION = 16w0x0003;
const bit<16> PTP_TLV_REQUEST_UNICAST_TRANSMISSION = 16w0x0004;
const bit<16> PTP_TLV_GRANT_UNICAST_TRANSMISSION = 16w0x0005;
const bit<16> PTP_TLV_CANCEL_UNICAST_TRANSMISSION = 16w0x0006;
const bit<16> PTP_TLV_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION = 16w0x0007;
const bit<16> PTP_TLV_PATH_TRACE = 16w0x0008;
const bit<16> PTP_TLV_ALTERNATE_TIME_OFFSET_INDICATOR = 16w0x0009;
const bit<16> PTP_TLV_AUTHENTICATION_2008 = 16w0x2000;
const bit<16> PTP_TLV_PAD = 16w0x8008;
const bit<16> PTP_TLV_AUTHENTICATION = 16w0x8009; // IEEE 1588-2019

// TLV length counts value octets, including any type-specific padding,
// excluding the four-octet type/length prefix. It must be even.
header ptp_tlv {
    bit<16> tlvType;
    bit<16> length;
}

// Complete TLV for an ordered stack. An even 16-bit length can describe
// at most 65534 value octets. Message bounds usually impose a lower limit.
header ptp_tlv_record {
    bit<16> tlvType;
    bit<16> length;
    varbit<524272> value;
}

header ptp_opaque_body {
    varbit<524008> value; // At most 65535 - 34 octets
}

// Alternative complete Path Trace TLV. Each clock identity is eight octets.
// Check tlvType == PTP_TLV_PATH_TRACE and length % 8 == 0 before extracting.
// Emit this header or a generic TLV record, without duplicating the prefix.
header ptp_path_trace {
    bit<16> tlvType;
    bit<16> length;
    varbit<524224> pathSequence; // At most 8191 clock identities
}

// Management TLV values start with managementId. CLOCK_DESCRIPTION is
// managementId 0x0001 within TLV type 0x0001, not a standalone TLV type 0x0009.
// The following field views support its variable-length encoding.
// Authentication and statistics values remain in the generic TLV record
// for the application to decode according to the standard and profile.
const bit<16> PTP_MID_CLOCK_DESCRIPTION = 16w0x0001;

header ptp_management_value_prefix {
    bit<16> managementId;
}

header ptp_management_error_prefix {
    bit<16> managementErrorId;
    bit<16> managementId;
    bit<32> reserved;
}

header ptp_clock_description_prefix {
    bit<16> clockType;
}

// PTPText has a one-octet length counting UTF-8 text octets.
// CLOCK_DESCRIPTION uses PTPText for physicalLayerProtocol,
// productDescription, revisionData and userDescription.
header ptp_text {
    bit<8> length;
    varbit<2040> text;
}

header ptp_physical_address_prefix {
    bit<16> physicalAddressLength;
}

header ptp_protocol_address_prefix {
    bit<16> networkProtocol;
    bit<16> addressLength;
}

header ptp_manufacturer_identity {
    bit<24> manufacturerIdentity;
    bit<8> reserved;
}

header ptp_profile_identity {
    bit<48> profileIdentifier;
}

struct ptp_metadata_t {
    bit<12> sdo_id;
    bit<1> known_message;
    bit<1> event_message;
    bit<8> tlv_count;
    bit<16> fixed_bytes; // Common header and fixed message body
    bit<16> suffix_bytes;
}

/**
 * P4 Parser Logic for PTPv2 Messages and a Bounded TLV Suffix
 * The cursor points to the common PTP header. available_length is the number
 * of transport-validated octets available for this message. The caller
 * identifies PTP over Ethernet, UDP/IPv4 or UDP/IPv6 and checks transport
 * bounds. Use ethernet.p4, ipv4.p4, ipv6.p4 and udp.p4 for those headers.
 * Both UDP ports 319/320 are relevant. PTP has no combined UDP/IP wire header.
 *
 * The headers struct contains ptp_header ptp_header and fixed-body headers
 * ptp_sync ptp_sync, ptp_delay_req ptp_delay_req, ptp_pdelay_req ptp_pdelay_req,
 * ptp_pdelay_resp ptp_pdelay_resp, ptp_follow_up ptp_follow_up,
 * ptp_delay_resp ptp_delay_resp, ptp_pdelay_resp_follow_up ptp_pdelay_resp_follow_up,
 * ptp_announce ptp_announce, ptp_signaling ptp_signaling,
 * ptp_management ptp_management, ptp_opaque_body ptp_opaque and
 * ptp_tlv_record[16] ptp_tlvs. The TLV stack must be empty on entry.
 * Metadata contains ptp_metadata_t ptp. Sixteen TLVs is an example storage
 * limit, not a protocol limit. Retain unknown TLV values and their ordering.
 *
 * The parser checks major version, fixed-body bounds and TLV framing.
 * It preserves the minor version, SDO fields, flags and reserved fields.
 * Unrecognized message types keep an opaque body for application handling.
 * Profile rules, timestamps, mandatory TLVs, management actions and
 * authentication are validated by the application. Synchronization needs
 * hardware timestamping, state and a clock servo outside this parser.
 * Emit the common header, the selected body and ordered TLV stack.
 * Transport padding after messageLength remains unparsed and unchanged.
 */
/*
parser ptp_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                  in bit<32> available_length) {
    bit<16> remaining;
    bit<32> tlv_prefix;
    bit<16> value_bytes;
    bit<32> value_bits;

    state start {
        hdr.ptp_header.setInvalid();
        hdr.ptp_sync.setInvalid();
        hdr.ptp_delay_req.setInvalid();
        hdr.ptp_pdelay_req.setInvalid();
        hdr.ptp_pdelay_resp.setInvalid();
        hdr.ptp_follow_up.setInvalid();
        hdr.ptp_delay_resp.setInvalid();
        hdr.ptp_pdelay_resp_follow_up.setInvalid();
        hdr.ptp_announce.setInvalid();
        hdr.ptp_signaling.setInvalid();
        hdr.ptp_management.setInvalid();
        hdr.ptp_opaque.setInvalid();
        meta.ptp.sdo_id = 0;
        meta.ptp.known_message = 0;
        meta.ptp.event_message = 0;
        meta.ptp.tlv_count = 0;
        meta.ptp.fixed_bytes = 0;
        meta.ptp.suffix_bytes = 0;
        verify(available_length >= 34, error.HeaderTooShort);
        pkt.extract(hdr.ptp_header);
        verify(hdr.ptp_header.versionPTP == PTP_VERSION, error.NoMatch);
        verify(hdr.ptp_header.messageLength >= 34, error.HeaderTooShort);
        verify((bit<32>) hdr.ptp_header.messageLength <= available_length,
               error.HeaderTooShort);
        remaining = hdr.ptp_header.messageLength - 34;
        meta.ptp.sdo_id = hdr.ptp_header.majorSdoId ++ hdr.ptp_header.minorSdoId;
        meta.ptp.fixed_bytes = 34;
        transition select(hdr.ptp_header.messageType) {
            0: parse_sync;
            1: parse_delay_req;
            2: parse_pdelay_req;
            3: parse_pdelay_resp;
            8: parse_follow_up;
            9: parse_delay_resp;
            10: parse_pdelay_resp_follow_up;
            11: parse_announce;
            12: parse_signaling;
            13: parse_management;
            default: parse_opaque;
        }
    }

    state parse_sync {
        verify(remaining >= 10, error.HeaderTooShort);
        pkt.extract(hdr.ptp_sync);
        remaining = remaining - 10;
        meta.ptp.event_message = 1;
        transition begin_tlvs;
    }

    state parse_delay_req {
        verify(remaining >= 10, error.HeaderTooShort);
        pkt.extract(hdr.ptp_delay_req);
        remaining = remaining - 10;
        meta.ptp.event_message = 1;
        transition begin_tlvs;
    }

    state parse_pdelay_req {
        verify(remaining >= 20, error.HeaderTooShort);
        pkt.extract(hdr.ptp_pdelay_req);
        remaining = remaining - 20;
        meta.ptp.event_message = 1;
        transition begin_tlvs;
    }

    state parse_pdelay_resp {
        verify(remaining >= 20, error.HeaderTooShort);
        pkt.extract(hdr.ptp_pdelay_resp);
        remaining = remaining - 20;
        meta.ptp.event_message = 1;
        transition begin_tlvs;
    }

    state parse_follow_up {
        verify(remaining >= 10, error.HeaderTooShort);
        pkt.extract(hdr.ptp_follow_up);
        remaining = remaining - 10;
        transition begin_tlvs;
    }

    state parse_delay_resp {
        verify(remaining >= 20, error.HeaderTooShort);
        pkt.extract(hdr.ptp_delay_resp);
        remaining = remaining - 20;
        transition begin_tlvs;
    }

    state parse_pdelay_resp_follow_up {
        verify(remaining >= 20, error.HeaderTooShort);
        pkt.extract(hdr.ptp_pdelay_resp_follow_up);
        remaining = remaining - 20;
        transition begin_tlvs;
    }

    state parse_announce {
        verify(remaining >= 30, error.HeaderTooShort);
        pkt.extract(hdr.ptp_announce);
        remaining = remaining - 30;
        transition begin_tlvs;
    }

    state parse_signaling {
        verify(remaining >= 10, error.HeaderTooShort);
        pkt.extract(hdr.ptp_signaling);
        remaining = remaining - 10;
        transition begin_tlvs;
    }

    state parse_management {
        verify(remaining >= 14, error.HeaderTooShort);
        pkt.extract(hdr.ptp_management);
        remaining = remaining - 14;
        transition begin_tlvs;
    }

    state begin_tlvs {
        meta.ptp.known_message = 1;
        meta.ptp.fixed_bytes = hdr.ptp_header.messageLength - remaining;
        meta.ptp.suffix_bytes = remaining;
        transition check_tlvs;
    }

    state check_tlvs {
        transition select(remaining) {
            0: accept;
            default: parse_tlv;
        }
    }

    state parse_tlv {
        verify(meta.ptp.tlv_count < 16, error.StackOutOfBounds);
        verify(remaining >= 4, error.HeaderTooShort);
        tlv_prefix = pkt.lookahead<bit<32>>();
        value_bytes = tlv_prefix[15:0];
        verify((value_bytes & 16w1) == 0, error.NoMatch);
        verify(value_bytes <= remaining - 4, error.HeaderTooShort);
        value_bits = (bit<32>) value_bytes * 8;
        pkt.extract(hdr.ptp_tlvs.next, value_bits);
        meta.ptp.tlv_count = meta.ptp.tlv_count + 1;
        remaining = remaining - 4 - value_bytes;
        transition check_tlvs;
    }

    state parse_opaque {
        value_bits = (bit<32>) remaining * 8;
        pkt.extract(hdr.ptp_opaque, value_bits);
        transition accept;
    }
}
*/

/**
 * P4 Match-Action Pipeline for PTP (v1model)
 * Dispatch by SDO, domain and message type without changing packet bytes.
 * handler_port is the fallback for application-level profile validation.
 * Correction updates, timestamp correlation, clock selection, clock
 * adjustment and authentication belong to the enclosing PTP implementation.
 */
/*
control ptp_control(inout headers hdr, inout metadata meta,
                    inout standard_metadata_t standard_metadata,
                    in bit<9> handler_port) {
    action send_ptp(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action send_default() {
        standard_metadata.egress_spec = handler_port;
    }

    action drop_ptp() {
        mark_to_drop(standard_metadata);
    }

    table ptp_handlers {
        key = {
            meta.ptp.sdo_id: exact;
            hdr.ptp_header.domainNumber: exact;
            hdr.ptp_header.messageType: exact;
        }
        actions = {
            send_ptp;
            send_default;
        }
        default_action = send_default();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.ptp_header.isValid()) {
            drop_ptp();
        } else {
            ptp_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_PTP_P4
