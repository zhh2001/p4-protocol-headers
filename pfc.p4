/**
 * Priority-based Flow Control (IEEE 802.3, Annex 31D and IEEE 802.1Q)
 * 标准 PFC 报头和本地处理示例
 */
#ifndef P4_PROTOCOL_HEADERS_PFC_P4
#define P4_PROTOCOL_HEADERS_PFC_P4

#include "ethernet.p4"

const bit<16> PFC_ETHER_TYPE = 16w0x8808; // MAC Control
const bit<16> PFC_OPCODE = 16w0x0101;
const bit<48> PFC_MULTICAST = 48w0x0180c2000001;
const bit<32> PFC_HEADER_BYTES = 20;
const bit<32> PFC_PAUSE_QUANTUM_BITS = 512;

// Twenty octets from opcode through the last pause time, in network byte
// order. The priority enable vector consists of reserved and priority_enable.
// Transmit reserved as zero and ignore its value on receipt.
// Bit n of priority_enable selects pause_time_n, with priority 0 in the LSB.
// All eight time fields are present even when their enable bits are clear.
header pfc_t {
    bit<16> opcode;
    bit<8> reserved;
    bit<8> priority_enable;
    bit<16> pause_time_0;
    bit<16> pause_time_1;
    bit<16> pause_time_2;
    bit<16> pause_time_3;
    bit<16> pause_time_4;
    bit<16> pause_time_5;
    bit<16> pause_time_6;
    bit<16> pause_time_7;
}

// Each selected time is 0..65535 units of 512 bit-times at the MAC data
// rate. A selected zero time releases that priority's pause. An unselected
// time is ignored and does not update the priority's timer, even if zero.
// The bitmap selects updates for this frame, rather than advertising the
// port's negotiated PFC configuration or its current paused state.
// Convert a time to bits in at least 32 bits before applying the link rate.

// PFC uses the MAC Control group address on a full-duplex point-to-point
// link. A conventional transmitted frame has this untagged Ethernet header,
// the twenty-octet PFC header and 26 zero reserved/pad octets. It is 60 octets
// without its four-octet FCS. MAC frame validation and FCS processing belong
// to the target. No timestamp or synchronization domain follows the timers.
typedef ethernet_header pfc_transport;

struct pfc_metadata_t {
    bit<32> parsed_bytes;
    bit<32> unparsed_bytes;
}

/**
 * Bounded PFC parser
 * The cursor starts at the MAC Control opcode. headers contains pfc_t pfc
 * and metadata contains pfc_metadata_t pfc. Emit hdr.pfc at that position.
 * The caller supplies the validated MAC frame's EtherType and destination,
 * and a physically bounded payload_length excluding Ethernet and FCS.
 * Retained pad is included in that length. It stays unparsed and unchanged.
 *
 * Dispatch only frames for MAC Control PFC to this parser. Other opcodes,
 * including global PAUSE (0x0001), need their own handlers. Reserved values
 * and unselected time fields are ignored on receipt, rather than rejected.
 * Frame size, source address and FCS checks occur before this example.
 */
/*
parser pfc_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                  in bit<16> link_type, in bit<48> destination,
                  in bit<32> payload_length) {
    state start {
        hdr.pfc.setInvalid();
        meta.pfc.parsed_bytes = 0;
        meta.pfc.unparsed_bytes = payload_length;
        verify(link_type == PFC_ETHER_TYPE, error.NoMatch);
        verify(destination == PFC_MULTICAST, error.NoMatch);
        verify(payload_length >= PFC_HEADER_BYTES, error.HeaderTooShort);
        pkt.extract(hdr.pfc);
        verify(hdr.pfc.opcode == PFC_OPCODE, error.NoMatch);
        meta.pfc.parsed_bytes = PFC_HEADER_BYTES;
        meta.pfc.unparsed_bytes = payload_length - PFC_HEADER_BYTES;
        transition accept;
    }
}
*/

/**
 * Local application delivery (v1model)
 * MAC Control frames are consumed locally. handler_port and table action
 * ports denote application delivery endpoints, such as a target CPU port.
 * They are not ordinary bridge egress links. The receiving physical port
 * selects its PFC handler. Parser errors drop the packet.
 *
 * The handler applies enabled time updates using per-port configuration,
 * priority-to-traffic-class mapping, link rate and existing timer state.
 * Queue scheduling, DCBX negotiation and timer expiry require target or
 * application support. PFC does not pause transmission of MAC Control
 * frames. This example only delivers the request and leaves those functions
 * to the handler.
 */
/*
control pfc_control(inout headers hdr,
                    inout standard_metadata_t standard_metadata,
                    in bit<9> handler_port) {
    action send_pfc(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action send_default() {
        standard_metadata.egress_spec = handler_port;
    }

    table pfc_handlers {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            send_pfc;
            send_default;
        }
        default_action = send_default();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.pfc.isValid()) {
            mark_to_drop(standard_metadata);
        } else {
            pfc_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_PFC_P4
