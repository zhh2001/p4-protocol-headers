#ifndef P4_PROTOCOL_HEADERS_LISP_P4
#define P4_PROTOCOL_HEADERS_LISP_P4

/**
 * LISP data plane (RFC 9300) and control plane (RFC 9301)
 * 数据封装、控制消息前缀与 AFI 地址定义
 * Map versions follow RFC 9302, shared extensions RFC 9304,
 * LCAF RFC 8060 and Map-Request PubSub flags RFC 9437.
 */

typedef bit<4> lisp_message_type_t;
const bit<16> LISP_DATA_PORT = 4341;
const bit<16> LISP_CONTROL_PORT = 4342;
const bit<16> LISP_AFI_UNSPECIFIED = 0;
const bit<16> LISP_AFI_IPV4 = 1;
const bit<16> LISP_AFI_IPV6 = 2;
const bit<16> LISP_AFI_LCAF = 16387;

const lisp_message_type_t LISP_MAP_REQUEST = 1;
const lisp_message_type_t LISP_MAP_REPLY = 2;
const lisp_message_type_t LISP_MAP_REGISTER = 3;
const lisp_message_type_t LISP_MAP_NOTIFY = 4;
const lisp_message_type_t LISP_MAP_NOTIFY_ACK = 5;
const lisp_message_type_t LISP_MAP_REFERRAL = 6;
const lisp_message_type_t LISP_ECM = 8;
const lisp_message_type_t LISP_SHARED_EXTENSION = 15;

const bit<3> LISP_ACT_NO_ACTION = 0;
const bit<3> LISP_ACT_NATIVE_FORWARD = 1;
const bit<3> LISP_ACT_SEND_MAP_REQUEST = 2;
const bit<3> LISP_ACT_DROP_NO_REASON = 3;
const bit<3> LISP_ACT_DROP_POLICY = 4;
const bit<3> LISP_ACT_DROP_AUTH = 5;
const bit<8> LISP_PRIORITY_UNUSED = 255;

/* Data header, eight bytes. EIDs belong to inner IP headers and RLOCs
 * to outer IP headers. N selects a 24-bit nonce and takes precedence over
 * V on receive. With N = 0, V selects two 12-bit map versions. E is ignored
 * when N = 0. I selects a 24-bit Instance ID and reduces LSBs to eight bits.
 * L enables the Locator-Status-Bits. R is zero on transmit and ignored on
 * receive. KK = 0 is plaintext, 1-3 identify RFC 8061 encryption keys.
 */
header lisp_data_t {
    bit<1> nonce_present;
    bit<1> locator_status_present;
    bit<1> echo_nonce_request;
    bit<1> map_version_present;
    bit<1> instance_present;
    bit<1> reserved;
    bit<2> key_id;
    bit<24> nonce_or_map_versions;
    bit<32> instance_or_locator_status;
}

/* Alternate views of fields within lisp_data_t, not additional headers. */
header lisp_map_versions_t {
    bit<12> source_version;
    bit<12> destination_version;
}

header lisp_instance_status_t {
    bit<24> instance_id;
    bit<8> locator_status;
}

/* One-byte lookahead prefix. Low bits depend on the control message type. */
header lisp_control_type_t {
    lisp_message_type_t message_type;
    bit<4> type_specific;
}

/* Map-Request fixed prefix, 12 bytes. IRC encodes 1-32 ITR-RLOC addresses
 * as count minus one. Receive Record Count can exceed one. The source EID,
 * ITR-RLOC addresses, request records, optional Map-Reply record and optional
 * 24-byte IDs follow. ID-present and record N are assigned by RFC 9437.
 */
header lisp_map_request_t {
    lisp_message_type_t message_type;
    bit<1> authoritative;
    bit<1> map_data_present;
    bit<1> probe;
    bit<1> solicit_map_request;
    bit<1> proxy_itr;
    bit<1> smr_invoked;
    bit<1> reserved_bit;
    bit<1> id_present;
    bit<5> reserved;
    bit<1> local_xtr;
    bit<1> dont_map_reply;
    bit<5> itr_rloc_count;
    bit<8> record_count;
    bit<64> nonce;
}

/* Request-record prefix, four bytes, followed by an AFI-encoded EID. */
header lisp_request_record_t {
    bit<1> notification_requested;
    bit<7> reserved;
    bit<8> eid_mask_length;
    bit<16> eid_afi;
}

/* Map-Reply fixed prefix, 12 bytes. Records follow, then LISP-SEC
 * authentication information when S = 1.
 */
header lisp_map_reply_t {
    lisp_message_type_t message_type;
    bit<1> probe;
    bit<1> echo_nonce_capable;
    bit<1> security;
    bit<17> reserved;
    bit<8> record_count;
    bit<64> nonce;
}

/* Map-Register fixed prefix, 16 bytes. Authentication Data Length counts
 * only the following authentication bytes. Key ID and Algorithm ID each
 * occupy one byte. Records and optional xTR-ID/Site-ID follow that data.
 */
header lisp_map_register_t {
    lisp_message_type_t message_type;
    bit<1> proxy_map_reply;
    bit<1> security;
    bit<1> id_present;
    bit<12> reserved;
    bit<1> eid_notify;
    bit<1> use_ttl;
    bit<1> merge;
    bit<1> reserved_bit;
    bit<1> want_map_notify;
    bit<8> record_count;
    bit<64> nonce;
    bit<8> key_id;
    bit<8> algorithm_id;
    bit<16> authentication_length;
}

/* Map-Notify / Map-Notify-Ack fixed prefix, 16 bytes, with type 4 / 5.
 * RFC 9301 defines the leading 20 bits after Type as Reserved. The owner
 * interprets extensions and the copied registration contents after it.
 */
header lisp_map_notify_t {
    lisp_message_type_t message_type;
    bit<20> reserved;
    bit<8> record_count;
    bit<64> nonce;
    bit<8> key_id;
    bit<8> algorithm_id;
    bit<16> authentication_length;
}

/* Encapsulated Control Message prefix, four bytes. S introduces LISP-SEC
 * authentication data before inner IP. D requests DDT processing. E and M
 * use the assignments in RFC 9301 Section 12.4 and the IANA ECM registry.
 */
header lisp_ecm_t {
    lisp_message_type_t message_type;
    bit<1> security;
    bit<1> ddt;
    bit<1> to_etr;
    bit<1> to_map_server;
    bit<24> reserved;
}

/* Shared Extension prefix, two bytes. Its subtype defines the body. */
header lisp_extension_t {
    lisp_message_type_t message_type;
    bit<12> subtype;
}

/* EID mapping record prefix, 12 bytes, followed by an AFI-encoded EID and
 * Locator Count locator records. TTL is in minutes. ACT applies to negative
 * Map-Replies with Locator Count = 0. Map Version is 12 bits.
 */
header lisp_map_record_t {
    bit<32> record_ttl;
    bit<8> locator_count;
    bit<8> eid_mask_length;
    bit<3> action_code;
    bit<1> authoritative;
    bit<12> reserved;
    bit<4> version_reserved;
    bit<12> map_version;
    bit<16> eid_afi;
}

/* Locator record prefix, eight bytes, followed by an AFI-encoded address.
 * Priority 255 excludes the locator for the corresponding traffic class.
 * Unused Flags are zero on transmit and ignored on receipt.
 */
header lisp_locator_record_t {
    bit<8> priority;
    bit<8> weight;
    bit<8> multicast_priority;
    bit<8> multicast_weight;
    bit<13> unused_flags;
    bit<1> local;
    bit<1> probe;
    bit<1> reachable;
    bit<16> locator_afi;
}

header lisp_afi_t {
    bit<16> afi;
}

header lisp_ipv4_address_t {
    bit<32> address;
}

header lisp_ipv6_address_t {
    bit<128> address;
}

/* LCAF prefix after AFI 16387, six bytes. Length counts only its body.
 * type_specific is Rsvd2 in the common format, with meaning for some types,
 * such as the IID mask length for Type 2. Nested addresses belong to the type.
 */
header lisp_lcaf_prefix_t {
    bit<8> reserved;
    bit<8> flags;
    bit<8> lcaf_type;
    bit<8> type_specific;
    bit<16> length;
}

header lisp_lcaf_t {
    bit<8> reserved;
    bit<8> flags;
    bit<8> lcaf_type;
    bit<8> type_specific;
    bit<16> length;
    varbit<524280> value;
}

/* IDs at the end of messages that carry them, 24 bytes. */
header lisp_ids_t {
    bit<128> xtr_id;
    bit<64> site_id;
}

enum bit<8> lisp_plane {
    DATA = 0,
    CONTROL = 1
};

struct lisp_headers_t {
    lisp_data_t data;
    lisp_map_request_t request;
    lisp_map_reply_t reply;
    lisp_map_register_t registration;
    lisp_map_notify_t notify;
    lisp_ecm_t ecm;
    lisp_extension_t extension;
    lisp_control_type_t referral;
};

struct lisp_metadata_t {
    lisp_plane plane;
    bit<8> header_bytes;
    bit<32> remaining_bytes;
    lisp_message_type_t message_type;
    bit<12> subtype;
    bit<24> instance_id;
    bit<32> locator_status;
    bit<24> nonce;
    bit<12> source_version;
    bit<12> destination_version;
    bool echo_requested;
    bit<2> key_id;
    bit<4> inner_version;
    bit<8> record_count;
    bit<6> itr_rloc_count;
    bit<16> authentication_length;
    bool ids_present;
};

struct lisp_address_headers_t {
    lisp_ipv4_address_t ipv4;
    lisp_ipv6_address_t ipv6;
    lisp_lcaf_t lcaf;
};

/**
 * Fixed-prefix parsing and local delivery (P4_16, v1model).
 * The cursor points to a validated UDP payload. lisp_bytes excludes UDP
 * and link padding. The caller checks IP/UDP lengths and completes outer
 * reassembly. DATA selects RFC 9300 on destination port 4341. CONTROL
 * selects RFC 9301 when either UDP port is 4342 and requires a verified,
 * nonzero UDP checksum. Data-plane zero checksums follow RFC 9300/6936.
 *
 * Plain data exposes the inner IP version. Encrypted data retains the IV
 * and ciphertext. Control parsing extracts fixed message prefixes, checks
 * authentication length bounds and retains addresses, records, IDs and
 * authentication bytes. DDT referrals retain their type prefix for a DDT
 * handler. Emit the valid member of lisp_headers_t before the untouched body.
 *
 * context_id selects a configured local endpoint. Handlers validate inner
 * packets, AFIs, complete records and authentication, maintain mapping and
 * nonce state, and process encryption, LISP-SEC, DDT and PubSub as applicable.
 */
/*
parser lisp_parser(packet_in pkt, out lisp_headers_t hdr,
                   out lisp_metadata_t meta, in bit<32> lisp_bytes,
                   in lisp_plane plane) {
    state start {
        meta.plane = plane;
        meta.header_bytes = 0;
        meta.remaining_bytes = 0;
        meta.message_type = 0;
        meta.subtype = 0;
        meta.instance_id = 0;
        meta.locator_status = 0;
        meta.nonce = 0;
        meta.source_version = 0;
        meta.destination_version = 0;
        meta.echo_requested = false;
        meta.key_id = 0;
        meta.inner_version = 0;
        meta.record_count = 0;
        meta.itr_rloc_count = 0;
        meta.authentication_length = 0;
        meta.ids_present = false;
        transition select(plane) {
            lisp_plane.DATA: parse_data;
            lisp_plane.CONTROL: classify_control;
            default: unsupported;
        }
    }

    state unsupported {
        verify(false, error.NoMatch);
        transition accept;
    }

    state parse_data {
        verify(lisp_bytes >= 8, error.HeaderTooShort);
        pkt.extract(hdr.data);
        meta.header_bytes = 8;
        meta.remaining_bytes = lisp_bytes - 8;
        meta.key_id = hdr.data.key_id;
        if (hdr.data.instance_present == 1) {
            meta.instance_id = hdr.data.instance_or_locator_status[31:8];
        }
        if (hdr.data.locator_status_present == 1) {
            meta.locator_status = hdr.data.instance_or_locator_status;
            if (hdr.data.instance_present == 1) {
                meta.locator_status = (bit<32>)hdr.data.instance_or_locator_status[7:0];
            }
        }
        if (hdr.data.nonce_present == 1) {
            meta.nonce = hdr.data.nonce_or_map_versions;
            meta.echo_requested = hdr.data.echo_nonce_request == 1;
        } else if (hdr.data.map_version_present == 1) {
            meta.source_version = hdr.data.nonce_or_map_versions[23:12];
            meta.destination_version = hdr.data.nonce_or_map_versions[11:0];
        }
        transition select(meta.key_id) {
            0: inspect_inner_ip;
            default: accept;
        }
    }

    state inspect_inner_ip {
        bit<8> first;
        verify(meta.remaining_bytes >= 1, error.HeaderTooShort);
        first = pkt.lookahead<bit<8>>();
        meta.inner_version = first[7:4];
        verify((meta.inner_version == 4 && meta.remaining_bytes >= 20)
               || (meta.inner_version == 6 && meta.remaining_bytes >= 40),
               error.NoMatch);
        transition accept;
    }

    state classify_control {
        lisp_control_type_t prefix;
        verify(lisp_bytes >= 1, error.HeaderTooShort);
        prefix = pkt.lookahead<lisp_control_type_t>();
        meta.message_type = prefix.message_type;
        transition select(meta.message_type) {
            LISP_MAP_REQUEST: parse_request;
            LISP_MAP_REPLY: parse_reply;
            LISP_MAP_REGISTER: parse_register;
            LISP_MAP_NOTIFY: parse_notify;
            LISP_MAP_NOTIFY_ACK: parse_notify;
            LISP_ECM: parse_ecm;
            LISP_SHARED_EXTENSION: parse_extension;
            LISP_MAP_REFERRAL: parse_referral;
            default: unsupported;
        }
    }

    state parse_request {
        verify(lisp_bytes >= 12, error.HeaderTooShort);
        pkt.extract(hdr.request);
        verify(hdr.request.record_count != 0, error.NoMatch);
        meta.header_bytes = 12;
        meta.remaining_bytes = lisp_bytes - 12;
        meta.record_count = hdr.request.record_count;
        meta.itr_rloc_count = (bit<6>)hdr.request.itr_rloc_count + 1;
        meta.ids_present = hdr.request.id_present == 1;
        verify(!meta.ids_present || meta.remaining_bytes >= 24, error.HeaderTooShort);
        transition accept;
    }

    state parse_reply {
        verify(lisp_bytes >= 12, error.HeaderTooShort);
        pkt.extract(hdr.reply);
        meta.header_bytes = 12;
        meta.remaining_bytes = lisp_bytes - 12;
        meta.record_count = hdr.reply.record_count;
        transition accept;
    }

    state parse_register {
        verify(lisp_bytes >= 16, error.HeaderTooShort);
        pkt.extract(hdr.registration);
        meta.header_bytes = 16;
        meta.remaining_bytes = lisp_bytes - 16;
        meta.record_count = hdr.registration.record_count;
        meta.authentication_length = hdr.registration.authentication_length;
        meta.ids_present = hdr.registration.id_present == 1;
        verify((bit<32>)meta.authentication_length <= meta.remaining_bytes,
               error.HeaderTooShort);
        verify(!meta.ids_present
               || meta.remaining_bytes - (bit<32>)meta.authentication_length >= 24,
               error.HeaderTooShort);
        transition accept;
    }

    state parse_notify {
        verify(lisp_bytes >= 16, error.HeaderTooShort);
        pkt.extract(hdr.notify);
        meta.header_bytes = 16;
        meta.remaining_bytes = lisp_bytes - 16;
        meta.record_count = hdr.notify.record_count;
        meta.authentication_length = hdr.notify.authentication_length;
        verify((bit<32>)meta.authentication_length <= meta.remaining_bytes,
               error.HeaderTooShort);
        transition accept;
    }

    state parse_ecm {
        verify(lisp_bytes >= 4, error.HeaderTooShort);
        pkt.extract(hdr.ecm);
        meta.header_bytes = 4;
        meta.remaining_bytes = lisp_bytes - 4;
        transition accept;
    }

    state parse_extension {
        verify(lisp_bytes >= 2, error.HeaderTooShort);
        pkt.extract(hdr.extension);
        meta.header_bytes = 2;
        meta.remaining_bytes = lisp_bytes - 2;
        meta.subtype = hdr.extension.subtype;
        transition accept;
    }

    state parse_referral {
        pkt.extract(hdr.referral);
        meta.header_bytes = 1;
        meta.remaining_bytes = lisp_bytes - 1;
        transition accept;
    }
}

control lisp_control(inout lisp_headers_t hdr,
                     in lisp_metadata_t meta,
                     inout standard_metadata_t standard_metadata,
                     in bit<32> context_id) {
    action deliver_lisp(bit<9> handler_port) {
        standard_metadata.egress_spec = handler_port;
    }

    action drop_lisp() {
        mark_to_drop(standard_metadata);
    }

    table data_handlers {
        key = {
            context_id: exact;
            meta.instance_id: exact;
            meta.key_id: exact;
            meta.inner_version: exact;
        }
        actions = { deliver_lisp; drop_lisp; }
        default_action = drop_lisp();
    }

    table control_handlers {
        key = {
            context_id: exact;
            meta.message_type: exact;
            meta.subtype: exact;
        }
        actions = { deliver_lisp; drop_lisp; }
        default_action = drop_lisp();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError || meta.header_bytes == 0) {
            drop_lisp();
        } else if (meta.plane == lisp_plane.DATA) {
            data_handlers.apply();
        } else {
            control_handlers.apply();
        }
    }
}
*/

/**
 * AFI-delimited address parsing (P4_16, v1model).
 * The enclosing record supplies its AFI and the bytes remaining after it.
 * AFI 0 consumes zero bytes. The caller permits it only in the applicable
 * record role. LCAF values retain their type-specific and nested contents.
 * consumed_bytes excludes the enclosing AFI. Emit ipv4, ipv6 or lcaf.
 */
/*
parser lisp_address_parser(packet_in pkt, out lisp_address_headers_t hdr,
                           out bit<32> consumed_bytes, in bit<16> afi,
                           in bit<32> available_bytes) {
    state start {
        consumed_bytes = 0;
        transition select(afi) {
            LISP_AFI_UNSPECIFIED: accept;
            LISP_AFI_IPV4: parse_ipv4;
            LISP_AFI_IPV6: parse_ipv6;
            LISP_AFI_LCAF: parse_lcaf;
            default: unsupported;
        }
    }

    state unsupported {
        verify(false, error.NoMatch);
        transition accept;
    }

    state parse_ipv4 {
        verify(available_bytes >= 4, error.HeaderTooShort);
        pkt.extract(hdr.ipv4);
        consumed_bytes = 4;
        transition accept;
    }

    state parse_ipv6 {
        verify(available_bytes >= 16, error.HeaderTooShort);
        pkt.extract(hdr.ipv6);
        consumed_bytes = 16;
        transition accept;
    }

    state parse_lcaf {
        lisp_lcaf_prefix_t prefix;
        verify(available_bytes >= 6, error.HeaderTooShort);
        prefix = pkt.lookahead<lisp_lcaf_prefix_t>();
        consumed_bytes = 6 + (bit<32>)prefix.length;
        verify(consumed_bytes <= available_bytes, error.HeaderTooShort);
        pkt.extract(hdr.lcaf, (bit<32>)prefix.length * 8);
        transition accept;
    }
}
*/

/**
 * Plain data-header construction (P4_16, v1model).
 * The cursor/payload already contains an IPv4 or IPv6 packet. use_instance
 * enables the supplied 24-bit IID, including IID zero. The enclosing pipeline
 * selects RLOCs from its map cache, enforces MTU and TTL rules, creates outer
 * IP/UDP with destination port 4341 and sets lengths and checksums.
 */
/*
control lisp_encapsulation(inout lisp_headers_t hdr, in bool use_instance,
                           in bit<24> instance_id) {
    apply {
        hdr.data.setValid();
        hdr.data.nonce_present = 0;
        hdr.data.locator_status_present = 0;
        hdr.data.echo_nonce_request = 0;
        hdr.data.map_version_present = 0;
        hdr.data.instance_present = use_instance ? 1w1 : 1w0;
        hdr.data.reserved = 0;
        hdr.data.key_id = 0;
        hdr.data.nonce_or_map_versions = 0;
        hdr.data.instance_or_locator_status = use_instance
            ? ((bit<32>)instance_id << 8) : 0;
    }
}
*/

#endif
