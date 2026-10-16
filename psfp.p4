#ifndef P4_PROTOCOL_HEADERS_PSFP_P4
#define P4_PROTOCOL_HEADERS_PSFP_P4

#include "tas.p4"

/**
 * Per-Stream Filtering and Policing (IEEE 802.1Qci, IEEE 802.1Q Clause 8.6.5)
 * PSFP 本地过滤器、流门、流量计配置和过滤器选择示例
 * PSFP adds no data-frame header. These local types follow the parameters
 * in ieee802-dot1q-stream-filters-gates and ieee802-dot1q-psfp (802.1Qcw).
 */
typedef bit<32> psfp_instance_id_t;
typedef bit<32> psfp_stream_handle_t;
typedef bit<3> psfp_priority_t;

enum bit<1> psfp_gate_state_t {
    CLOSED = 0,
    OPEN = 1
}

enum bit<1> psfp_color_mode_t {
    COLOR_BLIND = 0,
    COLOR_AWARE = 1
}

// valid=false represents the null IPV. Otherwise value is a priority 0..7.
struct psfp_ipv_t {
    bool valid;
    psfp_priority_t value;
}

// max_sdu_size is in octets. Zero accepts any SDU size.
// Instance identifiers, including zero, refer to configured table rows.
// flow_meter_enabled determines whether flow_meter_id is used.
struct psfp_filter_parameters_t {
    bit<32> max_sdu_size;
    bool block_oversize_enabled;
    psfp_instance_id_t stream_gate_id;
    bool flow_meter_enabled;
    psfp_instance_id_t flow_meter_id;
}

struct psfp_filter_config_t {
    psfp_instance_id_t filter_id;
    bool any_stream;
    psfp_stream_handle_t stream_handle;
    bool any_priority;
    psfp_priority_t priority;
    psfp_filter_parameters_t parameters;
}

struct psfp_filter_status_t {
    bool stream_blocked_due_to_oversize_frame;
}

// Each entry executes SetGateAndIPV. The optional octet limit counts MSDU
// octets. A present zero limit admits no octets, distinct from no limit.
struct psfp_gate_control_entry_t {
    psfp_gate_state_t gate_state;
    psfp_ipv_t ipv;
    bit<32> time_interval_ns;
    bool interval_octet_max_present;
    bit<32> interval_octet_max;
}

// Ordered control-list entries are stored separately. Times use the same
// PTP timescale and rational seconds as TAS. Stage administrative values,
// then signal ConfigChange to activate the operational gate schedule.
// Management defaults: gate_enabled=false, admin_gate_state=OPEN, null IPV.
struct psfp_gate_config_t {
    psfp_instance_id_t gate_id;
    bool gate_enabled;
    psfp_gate_state_t admin_gate_state;
    psfp_ipv_t admin_ipv;
    tas_base_time_t admin_base_time;
    tas_cycle_time_t admin_cycle_time;
    bit<32> admin_cycle_time_extension_ns;
    bit<32> admin_control_list_length;
    bool gate_closed_due_to_invalid_rx_enabled;
    bool gate_closed_due_to_octets_exceeded_enabled;
}

struct psfp_gate_status_t {
    psfp_gate_state_t oper_gate_state;
    psfp_ipv_t oper_ipv;
    bool gate_closed_due_to_invalid_rx;
    bool gate_closed_due_to_octets_exceeded;
}

// MEF 10.3 bandwidth profile: rates in bits/second, bursts in octets.
struct psfp_flow_meter_config_t {
    psfp_instance_id_t meter_id;
    bit<64> committed_information_rate_bps;
    bit<32> committed_burst_size;
    bit<64> excess_information_rate_bps;
    bit<32> excess_burst_size;
    bool coupling_flag;
    psfp_color_mode_t color_mode;
    bool drop_on_yellow;
    bool mark_all_frames_red_enabled;
}

// The target maintains these latches. Management can reset them.
struct psfp_flow_meter_status_t {
    bool mark_all_frames_red;
}

// Per-filter counters count frames at each stage reached, not octets.
struct psfp_filter_counters_t {
    bit<64> matching_frames;
    bit<64> passing_sdu;
    bit<64> not_passing_sdu;
    bit<64> passing_frames;
    bit<64> not_passing_frames;
    bit<64> red_frames;
}

struct psfp_filter_metadata_t {
    bool matched;
    psfp_instance_id_t filter_id;
    psfp_filter_parameters_t parameters;
}

/**
 * Stream-filter selection (P4_16)
 * Instantiate per Bridge component. stream_handle comes from IEEE 802.1CB
 * Stream identification. priority is the frame's priority before any IPV
 * override. Install exact values or full wildcards in the two ternary keys.
 * Order entries by increasing filter instance ID using the control-plane
 * API's entry-priority convention. The first matching filter wins, even over
 * an exact match with a larger instance ID. No match bypasses PSFP processing.
 *
 * For a match, the target applies maximum-SDU filtering, stream gating and
 * the optional flow meter in order. Use the MAC service's SDU length for
 * size and octet accounting. Latch oversize blocking when enabled. The gate
 * engine evaluates reception time, interval usage and its closed latches.
 * The meter maintains MEF 10.3 token state, color handling and red latching.
 * Red frames are discarded. Yellow frames are discarded when DropOnYellow
 * is true, otherwise their local drop_eligible parameter is set to true.
 * Meter state is associated with reception ports, rather than output copies.
 *
 * Update counters at the stages reached. A non-null gate IPV replaces the
 * priority only for the per-egress Traffic Class Table lookup (8.6.6.1).
 * The target supplies atomic state updates and synchronized gate execution.
 * This helper returns the selected parameters for that processing.
 */
/*
control psfp_filter_lookup(in psfp_stream_handle_t stream_handle,
                           in psfp_priority_t priority,
                           out psfp_filter_metadata_t meta) {
    action select_filter(psfp_instance_id_t filter_id, bit<32> max_sdu_size,
                         bit<1> block_oversize_enabled,
                         psfp_instance_id_t stream_gate_id,
                         bit<1> flow_meter_enabled,
                         psfp_instance_id_t flow_meter_id) {
        meta.matched = true;
        meta.filter_id = filter_id;
        meta.parameters.max_sdu_size = max_sdu_size;
        meta.parameters.block_oversize_enabled = (block_oversize_enabled == 1);
        meta.parameters.stream_gate_id = stream_gate_id;
        meta.parameters.flow_meter_enabled = (flow_meter_enabled == 1);
        meta.parameters.flow_meter_id = flow_meter_id;
    }

    table stream_filters {
        key = {
            stream_handle: ternary;
            priority: ternary;
        }
        actions = { select_filter; NoAction; }
        const default_action = NoAction();
    }

    apply {
        meta.matched = false;
        meta.filter_id = 0;
        meta.parameters.max_sdu_size = 0;
        meta.parameters.block_oversize_enabled = false;
        meta.parameters.stream_gate_id = 0;
        meta.parameters.flow_meter_enabled = false;
        meta.parameters.flow_meter_id = 0;
        stream_filters.apply();
    }
}
*/

#endif
