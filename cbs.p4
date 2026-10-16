#ifndef P4_PROTOCOL_HEADERS_CBS_P4
#define P4_PROTOCOL_HEADERS_CBS_P4

/**
 * Credit-Based Shaper (IEEE 802.1Q Clause 8.6.8.2, IEEE 802.1Qdx)
 * CBS 本地队列参数和配置查询示例
 * CBS selects transmissions from egress queues and adds no data-frame header.
 */
typedef bit<3> cbs_traffic_class_t;

/* One per-port entry of ieee802-dot1q-cbsa:cbsa-parameter-table.
 * For a Bridge Port, this YANG table is used in the absence of SRP.
 * A port has at most eight entries, indexed by traffic class 0..7.
 * Both slopes use bits/second and have a management default of zero.
 * admin_idle_slope_bps is writable. oper_idle_slope_bps is read-only status.
 * Without SRP, the operational value equals the administrative value.
 * With SRP active for the class, reservations determine the operational
 * value and the administrative value has no effect.
 * https://www.ieee802.org/1/files/public/YANGs/ieee802-dot1q-cbsa.yang
 */
struct cbs_queue_parameters_t {
    cbs_traffic_class_t traffic_class;
    bit<64> admin_idle_slope_bps;
    bit<64> oper_idle_slope_bps;
}

struct cbs_metadata_t {
    bool class_valid;
    bool cbs_selected;
    bit<64> oper_idle_slope_bps;
}

/* The target scheduler maintains signed credit in bits using actual MAC
 * transmission time. sendSlope = operIdleSlope - portTransmitRate.
 * Credit eligibility, empty-queue recovery, interference bounds and gate
 * coordination are scheduler functions (8.6.8.2 and Annex L).
 */

/**
 * Local scheduler-parameter lookup (P4_16)
 * Call for each chosen egress port, including each replicated copy, after
 * priority-to-traffic-class mapping. number_of_classes is the port's value
 * in 1..8. Traffic classes and SR class IDs are separate identifiers.
 *
 * Management configures the target's queue mapping, transmission selection
 * algorithm and bandwidth, then mirrors CBS queues in this table using
 * their operational idle slopes. Refresh entries when reservations, link
 * speed or scheduler configuration changes. Management checks the bandwidth
 * allocation against port capacity and the target's supported parameters.
 *
 * An invalid class returns class_valid=false. A valid class without a CBS
 * entry returns cbs_selected=false for the caller's other scheduling path.
 * A CBS entry with a zero slope still returns cbs_selected=true.
 * This helper reads local configuration into metadata and leaves frames
 * intact. The target scheduler performs the shaping.
 */
/*
control cbs_lookup(in bit<32> egress_port,
                   in cbs_traffic_class_t traffic_class,
                   in bit<4> number_of_classes, out cbs_metadata_t meta) {
    action select_cbs(bit<64> oper_idle_slope_bps) {
        meta.cbs_selected = true;
        meta.oper_idle_slope_bps = oper_idle_slope_bps;
    }

    table queue_parameters {
        key = {
            egress_port: exact;
            traffic_class: exact;
        }
        actions = { select_cbs; NoAction; }
        default_action = NoAction();
    }

    apply {
        meta.class_valid = false;
        meta.cbs_selected = false;
        meta.oper_idle_slope_bps = 0;
        if (number_of_classes >= 1 && number_of_classes <= 8
            && (bit<4>) traffic_class < number_of_classes) {
            meta.class_valid = true;
            queue_parameters.apply();
        }
    }
}
*/

#endif
