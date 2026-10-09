/**
 * DHCPv4 headers (RFC 2131, RFC 2132, RFC 3046 and RFC 4361)
 * DHCPv4 固定报头、可变长选项和主选项区解析示例
 */
#ifndef P4_PROTOCOL_HEADERS_DHCP_P4
#define P4_PROTOCOL_HEADERS_DHCP_P4

const bit<32> DHCP_MAGIC_COOKIE = 32w0x63825363;
const bit<16> DHCP_SERVER_PORT = 67;
const bit<16> DHCP_CLIENT_PORT = 68;
const bit<16> DHCP_FLAG_BROADCAST = 16w0x8000;
const bit<8> DHCP_BOOTREQUEST = 1;
const bit<8> DHCP_BOOTREPLY = 2;
const bit<8> DHCP_CLIENT_ID_IAID_DUID = 255;

// Core RFC 2131 message types. Other registered values remain eight-bit
// wire values and can be dispatched by the enclosing DHCP implementation.
enum bit<8> dhcp_message_type {
    DHCPDISCOVER = 1,
    DHCPOFFER = 2,
    DHCPREQUEST = 3,
    DHCPDECLINE = 4,
    DHCPACK = 5,
    DHCPNAK = 6,
    DHCPRELEASE = 7,
    DHCPINFORM = 8
}

// Selected option codes. PAD and END do not carry a length byte.
enum bit<8> dhcp_option_code {
    OPT_PAD = 0,
    OPT_SUBNET_MASK = 1,
    OPT_ROUTER = 3,
    OPT_DNS_SERVER = 6,
    OPT_HOSTNAME = 12,
    OPT_DOMAIN_NAME = 15,
    OPT_REQUESTED_IP = 50,
    OPT_IP_LEASE_TIME = 51,
    OPT_OVERLOAD = 52,
    OPT_MSG_TYPE = 53,
    OPT_SERVER_ID = 54,
    OPT_PARAM_REQ_LIST = 55,
    OPT_MAX_MESSAGE_SIZE = 57,
    OPT_RENEWAL_TIME = 58,
    OPT_REBINDING_TIME = 59,
    OPT_CLIENT_ID = 61,
    OPT_RELAY_AGENT_INFORMATION = 82,
    OPT_END = 255
}

/**
 * Fixed BOOTP fields (236 octets) and DHCP magic cookie (4 octets)
 * This complete header is 240 octets. Ordinary BOOTP without the DHCP
 * cookie requires a separate parsing path. The broadcast flag is 0x8000.
 * chaddr holds up to 16 hardware-address octets, with hlen specifying use.
 * Retain sname and file as raw fields when Option Overload uses them.
 */
header dhcp_header {
    bit<8> op;
    bit<8> htype;
    bit<8> hlen;
    bit<8> hops;
    bit<32> xid;
    bit<16> secs;
    bit<16> flags;
    bit<32> ciaddr;
    bit<32> yiaddr;
    bit<32> siaddr;
    bit<32> giaddr;
    bit<128> chaddr;
    bit<512> sname;
    bit<1024> file;
    bit<32> magic_cookie;
}

// Complete ordinary option. len counts data octets, from zero to 255.
// PAD and END use dhcp_marker instead. An option cannot cross an area bound.
header dhcp_option {
    bit<8> code;
    bit<8> len;
    varbit<2040> data;
}

header dhcp_marker {
    bit<8> code; // 0 for PAD, 255 for END
}

// Ordered storage for ordinary options and one-octet markers together.
// For an ordinary option, tail contains its length byte and data, requiring
// (len + 1) * 8 bits. For PAD and END, extract a zero-bit tail.
header dhcp_option_record {
    bit<8> code;
    varbit<2048> tail;
}

// These complete typed views include code and len. Validate both before
// extracting. Fragmented values stay in generic records for RFC 3396
// concatenation and decoding by the application.
header dhcp_msg_type_option {
    bit<8> code; // 53
    bit<8> len; // 1
    bit<8> type;
}

header dhcp_lease_time_option {
    bit<8> code; // 51
    bit<8> len; // 4
    bit<32> lease_time; // Unsigned seconds
}

header dhcp_overload_option {
    bit<8> code; // 52
    bit<8> len; // 1
    bit<8> overload; // 1: file, 2: sname, 3: both
}

// The identifier is an opaque client key. Its type is not required to match
// htype in the fixed header, and its remaining bytes need not be a MAC address.
// len includes type. This view uses (len - 1) * 8 variable bits.
header dhcp_client_id_option {
    bit<8> code; // 61
    bit<8> len;
    bit<8> type;
    varbit<2032> id;
}

// Alternative complete RFC 4361 client identifier. type is 255, followed
// by an opaque 32-bit IAID and a DUID. len includes type, IAID and DUID.
// This view uses (len - 5) * 8 variable bits. DUID semantics belong above P4.
header dhcp_client_id_iaid_duid_option {
    bit<8> code; // 61
    bit<8> len;
    bit<8> type; // 255
    bit<32> iaid;
    varbit<2000> duid;
}

header dhcp_param_req_option {
    bit<8> code; // 55
    bit<8> len;
    varbit<2040> options; // len option codes
}

// UDP is a separate eight-octet header. Client/server exchanges normally
// use 68/67. Relay/server exchanges can use 67 at both ends.
header dhcp_transport {
    bit<16> source_port;
    bit<16> dest_port;
    bit<16> length;
    bit<16> checksum;
}

header dhcp_relay_agent_option {
    bit<8> code; // 82
    bit<8> len;
    varbit<2040> suboptions;
}

// RFC 3046 suboptions have their own code, length and value. They do not
// use the DHCP PAD/END marker rules. The containing value bounds extraction.
header dhcp_relay_suboption {
    bit<8> code;
    bit<8> len;
    varbit<2040> data;
}

struct dhcp_metadata_t {
    bit<16> record_count; // Ordinary options, PADs and the terminating END
    bit<16> option_count; // Ordinary options only
    bit<16> pad_count; // PADs before END
    bit<32> option_bytes; // Main area consumed through END
    bit<8> message_type;
    bit<1> message_type_seen;
    bit<1> message_type_valid; // One main-area fragment with len == 1
    bit<1> overload_seen;
}

/**
 * Main option area parser
 * The cursor starts at op. payload_length is the validated UDP payload
 * length, excluding UDP and any outer padding. The enclosing parser checks
 * IP/UDP lengths, checksums and fragment completeness before calling this.
 * Relay traffic to UDP port 67 can also originate at UDP port 67.
 *
 * headers contains dhcp_header dhcp_header and dhcp_option_record[128]
 * dhcp_options. The stack must be empty on entry. metadata contains
 * dhcp_metadata_t dhcp. The 128-record storage limit is an example limit,
 * not a limit of DHCP. PADs and END share the stack with ordinary options.
 * Emit the fixed header and that stack. Bytes after END remain unparsed
 * and unchanged, including DHCP padding and any outer transport padding.
 *
 * sname and file remain unchanged. If Option Overload is present, the
 * application decodes the selected areas after the main area, in the order
 * main options, file, sname. It concatenates repeated option values in that
 * order before using them, as required by RFC 3396. No individual fragment
 * can cross an area boundary. Relay suboptions and client identifiers are
 * decoded by the application. Unknown option codes and values are retained.
 *
 * message_type is a dispatch hint for a single one-octet main-area option.
 * Repeated or differently sized message-type fragments clear that hint.
 * Overloaded messages also use the default application path. Required
 * options, semantic lengths, post-END padding and DHCP state are validated
 * above this parser. Address allocation, lease state and replies belong to
 * the enclosing DHCP implementation.
 */
/*
parser dhcp_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                   in bit<32> payload_length) {
    bit<32> remaining;
    bit<8> option_code;
    bit<8> value_bytes;
    bit<16> option_prefix;
    bit<24> message_type_prefix;
    bit<32> tail_bits;

    state start {
        hdr.dhcp_header.setInvalid();
        meta.dhcp.record_count = 0;
        meta.dhcp.option_count = 0;
        meta.dhcp.pad_count = 0;
        meta.dhcp.option_bytes = 0;
        meta.dhcp.message_type = 0;
        meta.dhcp.message_type_seen = 0;
        meta.dhcp.message_type_valid = 0;
        meta.dhcp.overload_seen = 0;
        verify(payload_length >= 240, error.HeaderTooShort);
        pkt.extract(hdr.dhcp_header);
        verify(hdr.dhcp_header.magic_cookie == DHCP_MAGIC_COOKIE, error.NoMatch);
        verify(hdr.dhcp_header.op == DHCP_BOOTREQUEST
               || hdr.dhcp_header.op == DHCP_BOOTREPLY, error.NoMatch);
        verify(hdr.dhcp_header.hlen <= 16, error.NoMatch);
        remaining = payload_length - 240;
        transition check_option;
    }

    state check_option {
        verify(remaining >= 1, error.HeaderTooShort);
        verify(meta.dhcp.record_count < 128, error.StackOutOfBounds);
        option_code = pkt.lookahead<bit<8>>();
        transition select(option_code) {
            0: parse_pad;
            255: parse_end;
            default: parse_option;
        }
    }

    state parse_pad {
        pkt.extract(hdr.dhcp_options.next, 0);
        meta.dhcp.record_count = meta.dhcp.record_count + 1;
        meta.dhcp.pad_count = meta.dhcp.pad_count + 1;
        meta.dhcp.option_bytes = meta.dhcp.option_bytes + 1;
        remaining = remaining - 1;
        transition check_option;
    }

    state parse_end {
        pkt.extract(hdr.dhcp_options.next, 0);
        meta.dhcp.record_count = meta.dhcp.record_count + 1;
        meta.dhcp.option_bytes = meta.dhcp.option_bytes + 1;
        transition accept;
    }

    state parse_option {
        verify(remaining >= 2, error.HeaderTooShort);
        option_prefix = pkt.lookahead<bit<16>>();
        value_bytes = option_prefix[7:0];
        verify((bit<32>) value_bytes <= remaining - 2, error.HeaderTooShort);
        if (option_code == 53) {
            if (meta.dhcp.message_type_seen == 0 && value_bytes == 1) {
                message_type_prefix = pkt.lookahead<bit<24>>();
                meta.dhcp.message_type = message_type_prefix[7:0];
                meta.dhcp.message_type_valid = 1;
            } else {
                meta.dhcp.message_type = 0;
                meta.dhcp.message_type_valid = 0;
            }
            meta.dhcp.message_type_seen = 1;
        }
        if (option_code == 52) {
            meta.dhcp.overload_seen = 1;
        }
        tail_bits = ((bit<32>) value_bytes + 1) * 8;
        pkt.extract(hdr.dhcp_options.next, tail_bits);
        meta.dhcp.record_count = meta.dhcp.record_count + 1;
        meta.dhcp.option_count = meta.dhcp.option_count + 1;
        meta.dhcp.option_bytes = meta.dhcp.option_bytes + 2 + (bit<32>) value_bytes;
        remaining = remaining - 2 - (bit<32>) value_bytes;
        transition check_option;
    }
}
*/

/**
 * DHCP application dispatch (v1model)
 * handler_port is the default application destination. The table selects
 * an application by BOOTP op and the main-area message-type hint. Packet
 * bytes are preserved. This example does not allocate addresses or reply.
 */
/*
control dhcp_control(inout headers hdr, inout metadata meta,
                     inout standard_metadata_t standard_metadata,
                     in bit<9> handler_port) {
    action send_dhcp(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action send_default() {
        standard_metadata.egress_spec = handler_port;
    }

    action drop_dhcp() {
        mark_to_drop(standard_metadata);
    }

    table dhcp_handlers {
        key = {
            hdr.dhcp_header.op: exact;
            meta.dhcp.message_type: exact;
        }
        actions = {
            send_dhcp;
            send_default;
        }
        default_action = send_default();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.dhcp_header.isValid()) {
            drop_dhcp();
        } else if (meta.dhcp.message_type_valid == 1
                   && meta.dhcp.overload_seen == 0) {
            dhcp_handlers.apply();
        } else {
            send_default();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_DHCP_P4
