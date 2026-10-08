#ifndef P4_PROTOCOL_HEADERS_SRV6_P4
#define P4_PROTOCOL_HEADERS_SRV6_P4

/**
 * Segment Routing over IPv6 (RFC 8754 and RFC 8986)
 * IPv6 段路由报头与端点处理示例
 * Include ipv6.p4 separately for the IPv6 base header.
 */

const bit<8> SRV6_ROUTING_TYPE = 4;

/**
 * Segment Routing Header Prefix (8 bytes)
 * Hdr Ext Len counts 8-byte units after this prefix. The complete SRH is
 * (Hdr Ext Len + 1) * 8 bytes, including the segment list and TLVs.
 */
header srv6_t {
    bit<8>  next_header;
    bit<8>  hdr_ext_len;
    bit<8>  routing_type;      // 4: SRH
    bit<8>  segments_left;
    bit<8>  last_entry;        // Last stored segment index, zero based
    bit<8>  flags;             // RFC 8754: transmit zero, ignore on receipt
    bit<16> tag;
};

/**
 * Segment List Entry (16 bytes)
 * The stored list has Last Entry + 1 entries. Index 0 is the final segment.
 * A reduced SRH omits the first visited segment, which is already in IPv6 DA.
 */
header srv6_segment_t {
    bit<128> sid;
};

/**
 * SRH TLV Prefix (2 bytes, except Pad1)
 * Length counts value bytes only. The high Type bit indicates mutability,
 * not an action for unknown types. Unrecognized types are ignored on receipt.
 */
header srv6_tlv_prefix_t {
    bit<8> type;
    bit<8> length;
};

/**
 * Ordered TLV Entry
 * Pad1 (type 0) has an empty body and occupies one byte.
 * Other types have a length byte followed by 0-255 value bytes in body.
 * This representation keeps Pad1 and ordinary TLVs in the same header stack.
 */
header srv6_tlv_t {
    bit<8> type;
    varbit<2048> body;
};

const bit<8> SRV6_TLV_PAD1 = 0;
const bit<8> SRV6_TLV_PADN = 4;
const bit<8> SRV6_TLV_HMAC = 5;

/**
 * HMAC TLV Value (excludes Type and Length)
 * The digest is in multiples of 8 bytes, up to 32 bytes. Local configuration
 * determines HMAC verification. Parse after validating the TLV value length.
 */
header srv6_hmac_t {
    bit<1>  d_bit;             // Reduced-list destination check control
    bit<15> reserved;          // Transmit zero
    bit<32> key_id;
    varbit<256> digest;
};

// Unprocessed SRH body when Segments Left is zero in the local End path.
header srv6_ignored_t {
    varbit<16320> body;        // Hdr Ext Len * 8 bytes
};

/*
 * IANA control-plane behavior identifiers, not SID function values or SRH flags.
 * PSP, USP and USD are configured SID behaviors. They are not bits in Flags.
 */
const bit<16> SRV6_END = 0x0001;
const bit<16> SRV6_END_X = 0x0005;
const bit<16> SRV6_END_T = 0x0009;
const bit<16> SRV6_END_DT4 = 0x0013;

// Parser output for the End example. These fields are local metadata.
struct srv6_metadata_t {
    bit<128> next_sid;
    bit<1>   next_sid_valid;
};

/**
 * P4 Parser Logic for a Local End Path
 * The cursor points to an SRH. Pass the remaining validated IPv6 payload
 * length as srh_available, after any preceding extension headers.
 * The headers struct contains srv6_t srh, srv6_segment_t[16] segments,
 * srv6_tlv_t[16] srh_tlvs and srv6_ignored_t srh_ignored.
 * Both stacks must be empty on entry. Their capacity is an example limit,
 * not a protocol limit. Increase it to suit the target and application.
 *
 * Active segments use the stored list and TLV framing. Reduced SRHs with
 * Segments Left = Last Entry + 1 are accepted. When Segments Left is zero,
 * End skips the list and TLVs, preserving the body for next-header processing.
 * TLV values stay opaque, including HMAC. The parent handles configured TLV
 * semantics, HMAC verification, IPv6 bounds, extension chains and parser errors.
 * Transit packets and other routing types need their own IPv6 processing path.
 */
/*
parser srv6_parser(packet_in pkt, inout headers hdr,
                   inout srv6_metadata_t srv6_meta,
                   in bit<16> srh_available) {
    bit<16> body_bytes;
    bit<16> segment_count;
    bit<16> segment_index;
    bit<16> segments_left;
    bit<16> tlv_left;
    bit<8> tlv_type;
    bit<16> tlv_prefix;
    bit<16> tlv_bytes;
    bit<32> tlv_body_bits;

    state start {
        hdr.srh_ignored.setInvalid();
        srv6_meta.next_sid = 0;
        srv6_meta.next_sid_valid = 0;
        verify(srh_available >= 8, error.HeaderTooShort);
        pkt.extract(hdr.srh);
        verify(hdr.srh.routing_type == SRV6_ROUTING_TYPE, error.NoMatch);
        body_bytes = (bit<16>) hdr.srh.hdr_ext_len * 8;
        verify(body_bytes <= srh_available - 8, error.HeaderTooShort);
        transition select(hdr.srh.segments_left) {
            0: skip_body;
            default: check_segments;
        }
    }

    state skip_body {
        pkt.extract(hdr.srh_ignored, (bit<32>) body_bytes * 8);
        transition accept;
    }

    state check_segments {
        segment_count = (bit<16>) hdr.srh.last_entry + 1;
        verify(segment_count * 16 <= body_bytes, error.NoMatch);
        verify((bit<16>) hdr.srh.segments_left <= segment_count, error.NoMatch);
        segment_index = 0;
        segments_left = segment_count;
        tlv_left = body_bytes - segment_count * 16;
        transition parse_segment;
    }

    state parse_segment {
        pkt.extract(hdr.segments.next);
        if (segment_index == (bit<16>) hdr.srh.segments_left - 1) {
            srv6_meta.next_sid = hdr.segments.last.sid;
            srv6_meta.next_sid_valid = 1;
        }
        segment_index = segment_index + 1;
        segments_left = segments_left - 1;
        transition select(segments_left) {
            0: check_tlvs;
            default: parse_segment;
        }
    }

    state check_tlvs {
        transition select(tlv_left) {
            0: accept;
            default: identify_tlv;
        }
    }

    state identify_tlv {
        tlv_type = pkt.lookahead<bit<8>>();
        transition select(tlv_type) {
            SRV6_TLV_PAD1: parse_pad1;
            default: parse_tlv;
        }
    }

    state parse_pad1 {
        pkt.extract(hdr.srh_tlvs.next, 32w0);
        tlv_left = tlv_left - 1;
        transition check_tlvs;
    }

    state parse_tlv {
        verify(tlv_left >= 2, error.HeaderTooShort);
        tlv_prefix = pkt.lookahead<bit<16>>();
        tlv_bytes = (bit<16>) tlv_prefix[7:0] + 2;
        verify(tlv_bytes <= tlv_left, error.HeaderTooShort);
        tlv_body_bits = ((bit<32>) tlv_prefix[7:0] + 1) * 8;
        pkt.extract(hdr.srh_tlvs.next, tlv_body_bits);
        tlv_left = tlv_left - tlv_bytes;
        transition check_tlvs;
    }
}
*/

/**
 * Basic End Behavior (v1model, RFC 8986)
 * Include ipv6.p4 and put ipv6_header ipv6 in the enclosing headers struct.
 * Only configured local End SIDs run this behavior. Next-hop lookup uses the
 * updated destination in the packet's IPv6 routing context.
 * End retains the SRH and leaves Flags, Tag, segment entries and TLVs intact.
 * It decrements Hop Limit once when advancing to the next segment.
 *
 * end_sid's local_port selects a local IPv6 handler for Segments Left zero.
 * That handler continues the next-header chain and applies the configured
 * upper-layer policy. It also handles SRv6 packets that arrive without an SRH.
 * The parent supplies the routing context, egress framing, domain access
 * controls and ICMP Time Exceeded/Parameter Problem responses before discard.
 * Packets needing those error responses are dropped by this example.
 * PSP, USP, USD and decapsulation require separate configured SID behaviors.
 */
/*
control srv6_end_control(inout headers hdr,
                         in srv6_metadata_t srv6_meta,
                         inout standard_metadata_t standard_metadata) {
    bit<1> process_end;
    bit<9> local_delivery_port;

    action end_sid(bit<9> local_port) {
        process_end = 1;
        local_delivery_port = local_port;
    }

    action forward_ipv6(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action drop_srv6() {
        mark_to_drop(standard_metadata);
    }

    table srv6_local_sids {
        key = {
            hdr.ipv6.dst_addr: exact;
        }
        actions = {
            end_sid;
            drop_srv6;
        }
        default_action = drop_srv6();
    }

    table srv6_next_hops {
        key = {
            hdr.ipv6.dst_addr: lpm;
        }
        actions = {
            forward_ipv6;
            drop_srv6;
        }
        default_action = drop_srv6();
    }

    apply {
        process_end = 0;
        local_delivery_port = 0;
        if (standard_metadata.parser_error != error.NoError
            || !hdr.ipv6.isValid() || !hdr.srh.isValid()) {
            drop_srv6();
        } else {
            srv6_local_sids.apply();
            if (process_end == 1) {
                if (hdr.srh.segments_left == 0) {
                    standard_metadata.egress_spec = local_delivery_port;
                } else if (hdr.ipv6.hop_limit <= 1
                           || srv6_meta.next_sid_valid == 0) {
                    drop_srv6();
                } else {
                    hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
                    hdr.srh.segments_left = hdr.srh.segments_left - 1;
                    hdr.ipv6.dst_addr = srv6_meta.next_sid;
                    srv6_next_hops.apply();
                }
            }
        }
    }
}
*/

#endif
