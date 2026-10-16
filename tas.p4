#ifndef P4_PROTOCOL_HEADERS_TAS_P4
#define P4_PROTOCOL_HEADERS_TAS_P4

/**
 * Time-Aware Shaper (IEEE 802.1Qbv, IEEE 802.1Q Clauses 8.6.8.4 and 8.6.9)
 * TAS 本地调度配置和交通类映射示例
 * Scheduled traffic uses transmission gates on egress queues. It adds no
 * data-frame header. The structures below hold local configuration/metadata.
 */
typedef bit<3> tas_traffic_class_t;
typedef bit<8> tas_gate_states_t;

const tas_gate_states_t TAS_ALL_GATES_OPEN = 8w0xFF;
const tas_gate_states_t TAS_ALL_GATES_CLOSED = 8w0x00;

// Operation selectors match IEEE8021-ST-MIB control-list operation values.
// Hold/release operations coordinate with MAC Merge (IEEE 802.1Qbu).
enum bit<8> tas_gate_operation {
    SET_GATE_STATES = 0,
    SET_AND_HOLD_MAC = 1,
    SET_AND_RELEASE_MAC = 2
}

/* One entry of the ordered gate control list.
 * Bit n of gate_states controls traffic class n, with class 0 in the LSB.
 * One means open and zero means closed. time_interval_ns is the duration
 * of an entry. Management protocols provide their own surrounding encoding.
 */
struct tas_gate_control_entry_t {
    tas_gate_operation operation;
    tas_gate_states_t gate_states;
    bit<32> time_interval_ns;
}

// PTP timescale. nanoseconds is less than 1000000000.
struct tas_base_time_t {
    bit<48> seconds;
    bit<32> nanoseconds;
}

// CycleTime is a rational number of seconds. denominator is nonzero.
struct tas_cycle_time_t {
    bit<32> numerator;
    bit<32> denominator;
}

/* Administrative parameters for one egress port. The control list is stored
 * separately by the scheduler, with control_list_length ordered entries.
 * cycle_time_extension_ns applies when installing a new schedule.
 * Management signals ConfigChange after staging the administrative values.
 * The scheduler activates the operational configuration at ConfigChangeTime
 * (IEEE 802.1Q Clause 12.29.1).
 */
struct tas_port_config_t {
    bool gate_enabled;
    tas_gate_states_t admin_gate_states;
    tas_base_time_t admin_base_time;
    tas_cycle_time_t admin_cycle_time;
    bit<32> admin_cycle_time_extension_ns;
    bit<32> admin_control_list_length;
}

struct tas_metadata_t {
    tas_traffic_class_t traffic_class;
    bool class_valid;
}

/**
 * Priority-to-traffic-class mapping (P4_16, IEEE 802.1Q Clause 8.6.6).
 * Call once for each chosen egress port, including each replicated copy.
 * priority is the frame's internal priority after port policy and VLAN
 * priority processing.
 * Configure all eight priority mappings for each port. number_of_classes is
 * that port's configured value in 1..8. A missing or out-of-range mapping
 * returns class_valid=false for the caller to handle.
 *
 * The target maps traffic_class to an egress queue. Its scheduler executes
 * the operational gate control list using the synchronized clock, holds
 * frames while gates are closed and checks transmission time before the
 * next gate-close event. Hold/release timing and guard bands belong to the
 * scheduler. This helper assigns local metadata and leaves the frame intact.
 */
/*
control tas_classify(in bit<32> egress_port, in bit<3> priority,
                     in bit<4> number_of_classes, out tas_metadata_t meta) {
    action assign_class(tas_traffic_class_t traffic_class) {
        meta.traffic_class = traffic_class;
        meta.class_valid = true;
    }
    table priority_to_class {
        key = {
            egress_port: exact;
            priority: exact;
        }
        actions = { assign_class; NoAction; }
        default_action = NoAction();
    }
    apply {
        meta.traffic_class = 0;
        meta.class_valid = false;
        if (number_of_classes >= 1 && number_of_classes <= 8) {
            priority_to_class.apply();
            if ((bit<4>) meta.traffic_class >= number_of_classes) {
                meta.class_valid = false;
            }
        }
    }
}
*/

#endif
