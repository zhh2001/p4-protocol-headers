#ifndef P4_PROTOCOL_HEADERS_CQF_P4
#define P4_PROTOCOL_HEADERS_CQF_P4

#include "tas.p4"

/**
 * Cyclic Queuing and Forwarding (IEEE 802.1Qch, IEEE 802.1Q Annex T)
 * CQF 本地队列绑定和双周期配置示例
 * CQF combines PSFP stream gates with scheduled transmission gates.
 * It adds no data-frame header. Synchronized cycles alternately fill one
 * queue and drain the other, then exchange their roles in the next cycle.
 */

/* Local binding for two distinct traffic-class queues on one egress port.
 * The port's Traffic Class Table maps each IPV to its corresponding class.
 * These are configuration values, rather than a management wire format.
 */
struct cqf_queue_pair_t {
    bit<3> phase_0_ipv;
    bit<3> phase_1_ipv;
    tas_traffic_class_t phase_0_class;
    tas_traffic_class_t phase_1_class;
}

/* Use tas_port_config_t and tas_gate_control_entry_t for the egress schedule.
 * Configure the PSFP stream-gate list with the same base time and repeating
 * period. Its IPV alternates between phase_0_ipv and phase_1_ipv for admitted
 * frames. Each IPV selects the queue whose transmission gate is closed.
 * The other queue drains frames admitted in the preceding cycle.
 *
 * Select the IPV at ingress stream-gate evaluation and carry it to queuing.
 * Use it in place of the frame's priority for the per-egress Traffic Class
 * Table lookup (8.6.6.1). The IPV is local metadata, separate from VLAN PCP.
 * Stream identification, gate admission and interval-octet limits use PSFP.
 *
 * Management chooses the cycle and admission windows to cover serialization,
 * link and forwarding delays, clock uncertainty and competing traffic.
 * Guard intervals can require additional gate-list entries. The target's
 * synchronized gate engines execute the lists and drain each queue within
 * its allotted cycle.
 */

/**
 * Configuration example: 125 us per CQF cycle, classes 6 and 7.
 * This port maps IPV 6 to class 6 and IPV 7 to class 7. These are example
 * assignments. In phase 0, the stream gate assigns IPV 6 while class 7 can
 * transmit. In phase 1, it assigns IPV 7 while class 6 can transmit.
 * Other transmission gates stay open. Gate bit n selects traffic class n.
 * The two-entry egress list repeats every 250 us, so AdminCycleTime is
 * 1/4000 seconds and AdminControlListLength is 2. Install a common base time
 * and coordinate both gate lists before enabling the configured service.
 */
/*
const cqf_queue_pair_t CQF_EXAMPLE_QUEUE_PAIR = {
    3w6, 3w7, 3w6, 3w7
};

const tas_gate_control_entry_t CQF_EXAMPLE_PHASE_0 = {
    tas_gate_operation.SET_GATE_STATES, 8w0xBF, 32w125000
};

const tas_gate_control_entry_t CQF_EXAMPLE_PHASE_1 = {
    tas_gate_operation.SET_GATE_STATES, 8w0x7F, 32w125000
};

const tas_cycle_time_t CQF_EXAMPLE_GCL_CYCLE = {
    32w1, 32w4000
};
*/

#endif
