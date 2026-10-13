/*
 * Routing Information Protocol for IPv4
 * RIPv1/RIPv2 标准报头、认证格式和有界报文解析示例
 * RFC 1058, RFC 2453 and RFC 4822
 */
#ifndef P4_PROTOCOL_HEADERS_RIP_P4
#define P4_PROTOCOL_HEADERS_RIP_P4

const bit<16> RIP_UDP_PORT = 520;
const bit<8> RIP_VERSION_1 = 1;
const bit<8> RIP_VERSION_2 = 2;
const bit<8> RIP_REQUEST = 1;
const bit<8> RIP_RESPONSE = 2;
const bit<16> RIP_AF_UNSPECIFIED = 0;
const bit<16> RIP_AF_IPV4 = 2;
const bit<16> RIP_AF_AUTHENTICATION = 16w0xffff;
const bit<16> RIP_AUTH_TRAILER = 1;
const bit<16> RIP_AUTH_PASSWORD = 2;
const bit<16> RIP_AUTH_CRYPTO = 3;
const bit<32> RIP_INFINITY = 16;
const bit<32> RIP_ALL_ROUTERS = 32w0xe0000009; // 224.0.0.9, RIPv2
const bit<8> RIP_MAX_ENTRIES = 25;

// Four-octet common header, followed by twenty-octet entries for ordinary
// Request/Response messages. reserved is zero on transmission. Version 1
// rejects nonzero MBZ fields, versions greater than 1 ignore those fields.
// UDP supplies the message length. RIPng uses different entries and port 521.
header rip_t {
    bit<8> command;
    bit<8> version;
    bit<16> reserved;
}

// RIPv1 entry. The three unused fields are MBZ on transmission/reception.
header rip_v1_entry_t {
    bit<16> address_family;
    bit<16> reserved1;
    bit<32> ip_address;
    bit<32> reserved2;
    bit<32> reserved3;
    bit<32> metric;
}

// RIPv2 entry. Metrics are 32 bits, 1..15 reachable, 16 unreachable.
// A zero netmask carries no mask. A zero next_hop uses the sender.
// AFI 0 with metric 16 in the only request entry requests the whole table.
// Unknown route AFIs are retained for the handler to ignore individually.
header rip_entry_t {
    bit<16> address_family;
    bit<16> route_tag;
    bit<32> ip_address;
    bit<32> netmask;
    bit<32> next_hop;
    bit<32> metric;
}

// Twenty-octet password authentication entry, first in a RIPv2 message.
// address_family is 0xffff and auth_type is 2. auth_data holds the password,
// left-justified and padded with zero octets to sixteen octets.
// Authentication occupies one of the message's 25 entry slots.
header rip_auth_t {
    bit<16> address_family;
    bit<16> auth_type;
    bit<128> auth_data;
}

// Alternative first entry for authentication type 3 (RFC 4822).
// packet_length is the offset from the RIP command octet to the trailer,
// including the four-octet RIP header, this entry and all route entries.
// auth_data_length counts only the digest octets, excluding the trailer's
// four-octet prefix. The algorithm/key is selected by the receiving
// interface's security association and key_id, not by a wire algorithm ID.
header rip_crypto_auth_t {
    bit<16> address_family;
    bit<16> auth_type;
    bit<16> packet_length;
    bit<8> key_id;
    bit<8> auth_data_length;
    bit<32> sequence_number;
    bit<64> reserved;
}

// Authentication trailer at packet_length. AFI is 0xffff, type is 1.
// The variable field covers the full length representable by the header.
// Keyed MD5 uses 16 digest octets. HMAC-SHA-1/256/384/512 use 20/32/48/64.
// Hash padding is computed in memory and is not transmitted.
header rip_auth_trailer_t {
    bit<16> address_family;
    bit<16> auth_type;
    varbit<2040> auth_data;
}

struct rip_metadata_t {
    bit<32> pdu_bytes;
    bit<32> parsed_bytes;
    bit<32> remaining;
    bit<32> entry_bytes;
    bit<16> auth_type; // Zero means no authentication entry was parsed
    bit<16> trailer_bytes;
    bit<8> entry_count; // Route entries, excluding authentication
    bool full_table_request;
}

/*
 * Single-datagram parser and local delivery example
 * headers contains rip_t rip, rip_v1_entry_t[25] rip_v1_entries,
 * rip_entry_t[25] rip_entries, rip_auth_t rip_auth,
 * rip_crypto_auth_t rip_crypto and rip_auth_trailer_t rip_trailer.
 * metadata contains rip_metadata_t rip. Invoke once per packet, with
 * headers initially invalid.
 *
 * The enclosing parser validates IPv4 and UDP lengths, handles IPv4
 * options/reassembly, identifies RIP using UDP ports and supplies a
 * physically bounded payload_bytes from UDP length minus eight. Ethernet
 * padding and bytes beyond UDP length are outside this RIP message.
 * The cursor starts at the RIP command octet. This IPv4 UDP profile has
 * at most 65507 payload octets, excluding IP/UDP headers and IP options.
 *
 * Native Request/Response messages have up to 25 twenty-octet entries,
 * or up to 24 route entries after password/cryptographic authentication.
 * A password/crypto entry is recognized only at the first entry position
 * in versions greater than 1. Later AFIs remain route fields for the
 * handler to inspect. Crypto packet_length delimits the route region,
 * and UDP payload length must equal packet_length + 4 + auth_data_length.
 * The trailer is additional to the entry slots. Its digest stays raw.
 * Version 0 is rejected. Version 1 MBZ fields are checked. Higher versions
 * use the v2 layout here, retaining unused fields for compatibility.
 * Other commands retain their entire body for an appropriate handler.
 * Unsupported authentication types and inconsistent entry/trailer
 * boundaries produce a parser error. Authentication-only messages have
 * no route entries and leave full_table_request false.
 *
 * Emit rip, the valid first authentication entry, the active entry stack,
 * then rip_trailer if valid. Emit any remaining payload unchanged.
 * The handler applies the interface's receive-version/authentication
 * policy, validates UDP checksum, source ports, addresses, metrics,
 * masks and next hops, and ignores unsupported route AFIs individually.
 * Password/digest verification, algorithm-specific digest lengths,
 * key rollover, sequence/replay checks and routing state need the control
 * plane. A parsed authentication entry does not establish trust.
 * This example preserves messages for local processing without installing
 * routes or generating RIP updates, timers or split-horizon decisions.
 */
/*
parser rip_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                  in bit<32> payload_bytes) {
    bit<32> prefix;

    state start {
        meta.rip.pdu_bytes = payload_bytes;
        meta.rip.parsed_bytes = 0;
        meta.rip.remaining = payload_bytes;
        meta.rip.entry_bytes = 0;
        meta.rip.auth_type = 0;
        meta.rip.trailer_bytes = 0;
        meta.rip.entry_count = 0;
        meta.rip.full_table_request = false;
        verify(payload_bytes >= 4 && payload_bytes <= 65507, error.NoMatch);
        pkt.extract(hdr.rip);
        verify(hdr.rip.version != 0, error.NoMatch);
        meta.rip.parsed_bytes = 4;
        meta.rip.remaining = payload_bytes - 4;
        transition select(hdr.rip.version) {
            RIP_VERSION_1: version1;
            default: classify;
        }
    }

    state version1 {
        verify(hdr.rip.reserved == 0, error.NoMatch);
        transition classify;
    }

    state classify {
        transition select(hdr.rip.command) {
            RIP_REQUEST: first_entry;
            RIP_RESPONSE: first_entry;
            default: accept;
        }
    }

    state first_entry {
        verify(meta.rip.remaining >= 20, error.NoMatch);
        transition select(hdr.rip.version) {
            RIP_VERSION_1: plain_entries;
            default: authentication;
        }
    }

    state authentication {
        prefix = pkt.lookahead<bit<32>>();
        transition select(prefix[31:16], prefix[15:0]) {
            (RIP_AF_AUTHENTICATION, RIP_AUTH_PASSWORD): password;
            (RIP_AF_AUTHENTICATION, RIP_AUTH_CRYPTO): crypto;
            (RIP_AF_AUTHENTICATION, _): invalid_message;
            default: plain_entries;
        }
    }

    state plain_entries {
        verify(meta.rip.remaining <= 500, error.NoMatch);
        meta.rip.entry_bytes = meta.rip.remaining;
        transition next_entry;
    }

    state password {
        pkt.extract(hdr.rip_auth);
        meta.rip.auth_type = RIP_AUTH_PASSWORD;
        meta.rip.parsed_bytes = 24;
        meta.rip.remaining = meta.rip.remaining - 20;
        verify(meta.rip.remaining <= 480, error.NoMatch);
        meta.rip.entry_bytes = meta.rip.remaining;
        transition next_entry;
    }

    state crypto {
        pkt.extract(hdr.rip_crypto);
        meta.rip.auth_type = RIP_AUTH_CRYPTO;
        meta.rip.parsed_bytes = 24;
        meta.rip.remaining = meta.rip.remaining - 20;
        verify(hdr.rip_crypto.packet_length >= 24
               && hdr.rip_crypto.packet_length <= 504, error.NoMatch);
        meta.rip.entry_bytes = (bit<32>)hdr.rip_crypto.packet_length - 24;
        meta.rip.trailer_bytes = 4 + (bit<16>)hdr.rip_crypto.auth_data_length;
        verify(payload_bytes == (bit<32>)hdr.rip_crypto.packet_length
               + (bit<32>)meta.rip.trailer_bytes, error.NoMatch);
        transition next_entry;
    }

    state next_entry {
        transition select(meta.rip.entry_bytes, hdr.rip.version) {
            (0, _): after_entries;
            (_, RIP_VERSION_1): entry1;
            default: entry2;
        }
    }

    state entry1 {
        verify(meta.rip.entry_count < RIP_MAX_ENTRIES
               && meta.rip.entry_bytes >= 20, error.NoMatch);
        pkt.extract(hdr.rip_v1_entries.next);
        verify(hdr.rip_v1_entries.last.reserved1 == 0
               && hdr.rip_v1_entries.last.reserved2 == 0
               && hdr.rip_v1_entries.last.reserved3 == 0, error.NoMatch);
        transition consume_entry;
    }

    state entry2 {
        verify(meta.rip.entry_count < RIP_MAX_ENTRIES
               && meta.rip.entry_bytes >= 20, error.NoMatch);
        pkt.extract(hdr.rip_entries.next);
        transition consume_entry;
    }

    state consume_entry {
        meta.rip.entry_count = meta.rip.entry_count + 1;
        meta.rip.entry_bytes = meta.rip.entry_bytes - 20;
        meta.rip.remaining = meta.rip.remaining - 20;
        meta.rip.parsed_bytes = meta.rip.parsed_bytes + 20;
        transition next_entry;
    }

    state after_entries {
        transition select(meta.rip.auth_type) {
            RIP_AUTH_CRYPTO: trailer;
            default: finish;
        }
    }

    state trailer {
        verify(meta.rip.remaining == (bit<32>)meta.rip.trailer_bytes,
               error.NoMatch);
        pkt.extract(hdr.rip_trailer,
                    (bit<32>)hdr.rip_crypto.auth_data_length * 8);
        verify(hdr.rip_trailer.address_family == RIP_AF_AUTHENTICATION
               && hdr.rip_trailer.auth_type == RIP_AUTH_TRAILER, error.NoMatch);
        meta.rip.parsed_bytes = meta.rip.parsed_bytes
                                + (bit<32>)meta.rip.trailer_bytes;
        meta.rip.remaining = 0;
        transition finish;
    }

    state finish {
        verify(meta.rip.remaining == 0, error.NoMatch);
        transition select(hdr.rip.command, meta.rip.entry_count,
                          hdr.rip.version) {
            (RIP_REQUEST, 1, RIP_VERSION_1): full_table1;
            (RIP_REQUEST, 1, _): full_table2;
            default: accept;
        }
    }

    state full_table1 {
        meta.rip.full_table_request =
            hdr.rip_v1_entries[0].address_family == RIP_AF_UNSPECIFIED
            && hdr.rip_v1_entries[0].metric == RIP_INFINITY;
        transition accept;
    }

    state full_table2 {
        meta.rip.full_table_request =
            hdr.rip_entries[0].address_family == RIP_AF_UNSPECIFIED
            && hdr.rip_entries[0].metric == RIP_INFINITY;
        transition accept;
    }

    state invalid_message {
        verify(false, error.NoMatch);
        transition accept;
    }
}

// v1model example. Ports identify local RIP processing endpoints.
control rip_control(inout headers hdr, inout metadata meta,
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
            hdr.rip.version: exact;
            hdr.rip.command: exact;
            meta.rip.auth_type: exact;
        }
        actions = { deliver; deliver_default; }
        default_action = deliver_default();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.rip.isValid()) {
            mark_to_drop(standard_metadata);
        } else {
            message_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_RIP_P4
