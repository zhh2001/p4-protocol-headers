/**
 * Generalized Precision Time Protocol (IEEE 802.1AS)
 * gPTP 公共报头复用 PTPv2，以下补充组织扩展 TLV
 */
#ifndef P4_PROTOCOL_HEADERS_GPTP_P4
#define P4_PROTOCOL_HEADERS_GPTP_P4

#include "ptp.p4"

// The common header is 34 octets. Timestamps belong to the message bodies
// defined in ptp.p4, not to a separate compact gPTP wire header.
typedef ptp_header gptp_t;

const bit<12> GPTP_SDO_ID = 12w0x100;
const bit<12> GPTP_CMLDS_SDO_ID = 12w0x200; // Common Mean Link Delay Service
const bit<48> GPTP_ETHERNET_DESTINATION = 48w0x0180c200000e;
const bit<24> GPTP_ORGANIZATION_ID = 24w0x0080c2;
const bit<16> GPTP_TLV_ORGANIZATION_EXTENSION_DO_NOT_PROPAGATE = 16w0x8000;

const bit<24> GPTP_SUBTYPE_FOLLOW_UP_INFORMATION = 1;
const bit<24> GPTP_SUBTYPE_MESSAGE_INTERVAL_REQUEST = 2;
const bit<24> GPTP_SUBTYPE_CAPABLE = 4;
const bit<24> GPTP_SUBTYPE_CAPABLE_INTERVAL_REQUEST = 5;

// Special interval request values. Other permitted values encode log2 seconds.
// The application applies the ranges and state transitions for its profile.
const int<8> GPTP_INTERVAL_NO_CHANGE = -128;
const int<8> GPTP_INTERVAL_INITIAL = 126;
const int<8> GPTP_INTERVAL_STOP = 127;

// Message interval request flags, with bit 0 reserved.
const bit<8> GPTP_COMPUTE_NEIGHBOR_RATE_RATIO = 8w0x02;
const bit<8> GPTP_COMPUTE_MEAN_LINK_DELAY = 8w0x04;
const bit<8> GPTP_ONE_STEP_RECEIVE_CAPABLE = 8w0x08;

// Prefix shared by the organizational TLVs below. lengthField counts value
// octets after type/length, including organizationId and organizationSubType.
// It must be even and at least six for an organizational TLV.
header gptp_organization_tlv_prefix {
    bit<16> tlvType;
    bit<16> lengthField;
    bit<24> organizationId;
    bit<24> organizationSubType;
}

// Complete Follow_Up information TLV (32 octets).
// tlvType = PTP_TLV_ORGANIZATION_EXTENSION, lengthField = 28,
// organizationId = GPTP_ORGANIZATION_ID, organizationSubType = 1.
// Rate offsets use a scale of 2^41. lastGmPhaseChange is signed ScaledNs,
// in units of 2^-16 ns. It is a time interval, not an 80-bit Timestamp.
// A two-step Sync carries ten reserved body octets. Its Follow_Up carries
// the preciseOriginTimestamp and this TLV. A one-step Sync carries its
// originTimestamp and this TLV. The application validates their association.
header gptp_follow_up_information_tlv {
    bit<16> tlvType;
    bit<16> lengthField;
    bit<24> organizationId;
    bit<24> organizationSubType;
    int<32> cumulativeScaledRateOffset;
    bit<16> gmTimeBaseIndicator;
    int<96> lastGmPhaseChange;
    int<32> scaledLastGmFreqChange;
}

// Complete Message interval request TLV (16 octets).
// tlvType = PTP_TLV_ORGANIZATION_EXTENSION, lengthField = 12,
// organizationId = GPTP_ORGANIZATION_ID, organizationSubType = 2.
header gptp_message_interval_request_tlv {
    bit<16> tlvType;
    bit<16> lengthField;
    bit<24> organizationId;
    bit<24> organizationSubType;
    int<8> logLinkDelayInterval;
    int<8> logTimeSyncInterval;
    int<8> logAnnounceInterval;
    bit<8> flags;
    bit<16> reserved;
}

// Complete gPTP-capable TLV (16 octets).
// tlvType = GPTP_TLV_ORGANIZATION_EXTENSION_DO_NOT_PROPAGATE,
// lengthField = 12, organizationId = GPTP_ORGANIZATION_ID, subtype = 4.
// Flags and reserved fields are sent as zero and ignored on receipt.
header gptp_capable_tlv {
    bit<16> tlvType;
    bit<16> lengthField;
    bit<24> organizationId;
    bit<24> organizationSubType;
    int<8> logGptpCapableMessageInterval;
    bit<8> flags;
    bit<32> reserved;
}

// Complete gPTP-capable message interval request TLV (14 octets).
// tlvType = GPTP_TLV_ORGANIZATION_EXTENSION_DO_NOT_PROPAGATE,
// lengthField = 10, organizationId = GPTP_ORGANIZATION_ID, subtype = 5.
header gptp_capable_interval_request_tlv {
    bit<16> tlvType;
    bit<16> lengthField;
    bit<24> organizationId;
    bit<24> organizationSubType;
    int<8> logGptpCapableMessageInterval;
    bit<24> reserved;
}

/**
 * Parsing example for gPTP over full-duplex Ethernet
 * Use the ptp_parser example from ptp.p4, with the headers and metadata
 * described there. This wrapper starts at the common header after the
 * enclosing parser has validated EtherType 0x88f7 and Ethernet bounds.
 * available_length counts PTP octets and any Ethernet padding, without FCS.
 * ptp_parser limits body and TLV extraction to messageLength.
 *
 * Both SDOs are accepted here. CMLDS uses the peer-delay message bodies.
 * Message types, domains and mandatory TLVs are validated by the application.
 * Unknown extensions keep their complete values and order in ptp_tlvs[16].
 * The sixteen-entry storage limit is an example limit, not a protocol limit.
 * For a typed TLV view, validate type, value length, organizationId and
 * subtype before extracting one of the complete headers above. Emit either
 * that typed header or its generic record, without duplicating the prefix.
 * Path Trace uses ptp_path_trace from ptp.p4.
 *
 * Sync/Follow_Up correlation, peer-delay measurement, asCapable state,
 * best-clock selection and the clock servo belong to the enclosing gPTP
 * implementation. A sequenceId identifies a message, not its authenticity.
 */
/*
parser gptp_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                   in bit<32> available_length) {
    ptp_parser() parse_ptp;

    state start {
        parse_ptp.apply(pkt, hdr, meta, available_length);
        verify(meta.ptp.sdo_id == GPTP_SDO_ID
               || meta.ptp.sdo_id == GPTP_CMLDS_SDO_ID, error.NoMatch);
        transition accept;
    }
}
*/

/**
 * Dispatch example (v1model)
 * handler_port delivers the message to the local gPTP application.
 * Include ingress_port in the key because peer delay is specific to a link.
 * The example preserves packet bytes. It does not relay link-local frames.
 * Transparent-clock correction needs hardware ingress and egress timestamps
 * in a common time base. originTimestamp is not a local ingress timestamp.
 * The signed correctionField represents nanoseconds multiplied by 2^16.
 * A grandmaster identity is 64 bits in Announce. Best-clock selection uses
 * the full priority information and protocol state outside this table.
 */
/*
control gptp_control(inout headers hdr, inout metadata meta,
                     inout standard_metadata_t standard_metadata,
                     in bit<9> handler_port) {
    action send_gptp(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action send_default() {
        standard_metadata.egress_spec = handler_port;
    }

    action drop_gptp() {
        mark_to_drop(standard_metadata);
    }

    table gptp_handlers {
        key = {
            standard_metadata.ingress_port: exact;
            meta.ptp.sdo_id: exact;
            hdr.ptp_header.domainNumber: exact;
            hdr.ptp_header.messageType: exact;
        }
        actions = {
            send_gptp;
            send_default;
        }
        default_action = send_default();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.ptp_header.isValid()) {
            drop_gptp();
        } else {
            gptp_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_GPTP_P4
