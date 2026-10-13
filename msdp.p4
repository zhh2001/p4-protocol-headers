/*
 * Multicast Source Discovery Protocol for IPv4
 * MSDP 公共头、Source-Active 条目和有界消息解析示例
 * RFC 3618, sections 12 and 13
 */
#ifndef P4_PROTOCOL_HEADERS_MSDP_P4
#define P4_PROTOCOL_HEADERS_MSDP_P4

const bit<16> MSDP_TCP_PORT = 639;
const bit<8> MSDP_SOURCE_ACTIVE = 1;
const bit<8> MSDP_SA_REQUEST = 2;
const bit<8> MSDP_SA_RESPONSE = 3;
const bit<8> MSDP_KEEPALIVE = 4;
const bit<8> MSDP_RESERVED_TYPE_5 = 5; // Previously Notification
const bit<8> MSDP_TRACEROUTE_PROGRESS = 6;
const bit<8> MSDP_TRACEROUTE_REPLY = 7;
const bit<16> MSDP_MAX_MESSAGE_BYTES = 9192;
const bit<8> MSDP_MAX_SA_ENTRIES = 255;
const bit<8> MSDP_SOURCE_PREFIX_LENGTH = 32;

// Three-octet TLV prefix. length includes this prefix and the value.
// KeepAlive is exactly three octets. Other types have at least four.
// There is no version field or common reserved field. Senders limit
// messages to 9192 octets, excluding TCP/IP and link-layer headers.
// RFC 3618 section 12 recommends accepting an oversized received TLV,
// ignoring extra data and keeping the session. This is a receive policy,
// not permission to generate messages beyond the transmission limit.
header msdp_t {
    bit<8> msg_type;
    bit<16> length;
}

// Source-Active (type 1) body prefix, immediately after msdp_t.
// The entry count is eight bits. All entries share this RP address.
// Control information occupies 8 + 12 * entry_count octets, including
// the common header. Any remaining value is one encapsulated IPv4 packet.
header msdp_sa_t {
    bit<8> entry_count;
    bit<32> rp_address;
}

// One twelve-octet (S,G) entry after msdp_sa_t, in wire order.
// Reserved is zero on transmission and ignored on reception.
// Senders set source_prefix_length to 32. No TTL or RP is carried here.
// If encapsulated data follows the list, only the last entry describes it.
// Its source/group must match the packet's IPv4 source/destination, and
// the packet's total length must equal the remaining message length.
header msdp_sa_entry_t {
    bit<24> reserved;
    bit<8> source_prefix_length;
    bit<32> group;
    bit<32> source;
}

// Types 2/3 and 6/7 are assigned, but their value layouts are not described
// in RFC 3618. Type 5 is reserved. Do not infer their body format from SA.
// Unknown types are discarded without resetting the session (section 13).

struct msdp_metadata_t {
    bit<32> message_bytes;
    bit<32> parsed_bytes;
    bit<32> remaining;
    bit<8> entries_left;
    bit<8> parsed_entries;
    bool oversized;
}

/*
 * One framed MSDP message and local delivery example
 * headers contains msdp_t msdp, msdp_sa_t msdp_sa and
 * msdp_sa_entry_t[255] msdp_sa_entries. metadata contains
 * msdp_metadata_t msdp. Invoke once per packet with headers invalid.
 *
 * The cursor starts at Type. message_bytes is the physically available
 * size of one complete TLV, including its three-octet prefix. TCP port 639
 * identifies the session, not message boundaries. TCP reassembly, stream
 * offsets, retransmissions and separation of coalesced messages belong
 * to the caller. TCP PSH, IP lengths and Ethernet padding do not delimit
 * an MSDP message. Bytes beyond message_bytes are outside this TLV.
 *
 * This parser checks framing and extracts the SA prefix and all entries
 * within the normal 9192-octet limit. A received TLV beyond that limit
 * retains its entire body and sets oversized for the session handler to
 * apply section 12's receive policy. It does not produce a format error
 * solely for exceeding the transmission limit. Other types retain their
 * value unchanged. KeepAlive within the normal limit has no value.
 *
 * For ordinary SA, remaining is the encapsulated-data length, zero when
 * absent. The data stays raw. The handler validates its IPv4 length and
 * last-entry association, source prefixes, multicast groups and RP/source
 * addresses. Reserved entry bits remain unchanged and are ignored.
 * Emit msdp, msdp_sa when valid and the valid entry stack, then the
 * remaining payload. This preserves the original byte order.
 *
 * Peer-RPF needs the originating RP and established-peer/MRIB state.
 * SA filtering, caching, Anycast RP policy, PIM joins, timers, TCP checksum
 * validation and encapsulated-data forwarding belong to the session owner.
 * The surrounding application reports TLV format errors to that owner
 * for section 13's session-reset decision. Unknown types are delivered
 * for silent discard there, without a session reset. Parser errors alone
 * do not operate a TCP connection. This example only parses and delivers.
 */
/*
parser msdp_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                   in bit<32> message_bytes) {
    state start {
        meta.msdp.message_bytes = message_bytes;
        meta.msdp.parsed_bytes = 0;
        meta.msdp.remaining = message_bytes;
        meta.msdp.entries_left = 0;
        meta.msdp.parsed_entries = 0;
        meta.msdp.oversized = false;
        verify(message_bytes >= 3 && message_bytes <= 65535, error.NoMatch);
        pkt.extract(hdr.msdp);
        verify((bit<32>)hdr.msdp.length == message_bytes, error.NoMatch);
        meta.msdp.parsed_bytes = 3;
        meta.msdp.remaining = message_bytes - 3;
        meta.msdp.oversized = message_bytes > (bit<32>)MSDP_MAX_MESSAGE_BYTES;
        transition select(meta.msdp.oversized) {
            true: accept;
            default: classify;
        }
    }

    state classify {
        transition select(hdr.msdp.msg_type) {
            MSDP_SOURCE_ACTIVE: source_active;
            MSDP_KEEPALIVE: keepalive;
            default: opaque_value;
        }
    }

    state source_active {
        verify(meta.msdp.remaining >= 5, error.NoMatch);
        pkt.extract(hdr.msdp_sa);
        meta.msdp.parsed_bytes = 8;
        meta.msdp.remaining = meta.msdp.remaining - 5;
        meta.msdp.entries_left = hdr.msdp_sa.entry_count;
        verify(meta.msdp.remaining >= (bit<32>)hdr.msdp_sa.entry_count * 12,
               error.NoMatch);
        transition next_entry;
    }

    state next_entry {
        transition select(meta.msdp.entries_left) {
            0: accept;
            default: entry;
        }
    }

    state entry {
        verify(meta.msdp.parsed_entries < MSDP_MAX_SA_ENTRIES
               && meta.msdp.remaining >= 12, error.NoMatch);
        pkt.extract(hdr.msdp_sa_entries.next);
        meta.msdp.entries_left = meta.msdp.entries_left - 1;
        meta.msdp.parsed_entries = meta.msdp.parsed_entries + 1;
        meta.msdp.parsed_bytes = meta.msdp.parsed_bytes + 12;
        meta.msdp.remaining = meta.msdp.remaining - 12;
        transition next_entry;
    }

    state keepalive {
        verify(meta.msdp.remaining == 0, error.NoMatch);
        transition accept;
    }

    state opaque_value {
        verify(meta.msdp.remaining >= 1, error.NoMatch);
        transition accept;
    }
}

// v1model example. Ports identify local MSDP processing endpoints.
control msdp_control(inout headers hdr, inout metadata meta,
                     inout standard_metadata_t standard_metadata,
                     in bit<9> handler_port) {
    action deliver(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action deliver_default() {
        standard_metadata.egress_spec = handler_port;
    }

    table message_handlers {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.msdp.msg_type: exact;
            meta.msdp.oversized: exact;
        }
        actions = { deliver; deliver_default; }
        default_action = deliver_default();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.msdp.isValid()) {
            mark_to_drop(standard_metadata);
        } else {
            message_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_MSDP_P4
