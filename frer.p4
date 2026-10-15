#ifndef P4_PROTOCOL_HEADERS_FRER_P4
#define P4_PROTOCOL_HEADERS_FRER_P4

/**
 * IEEE 802.1CB-2017 Redundancy Tag (Clause 7.8)
 * FRER 冗余标签与有界解析分流示例
 */
const bit<16> ETHERTYPE_FRER = 16w0xF1C1;

/* Complete R-TAG, six bytes including its EtherType.
 * Reserved is transmitted as zero and ignored on receipt.
 * Sequence Number carries the low 16 bits of sequence_number.
 * The original frame's Type/Length field follows the tag. Multiple R-TAGs
 * can occur in a frame, with placement determined by the configured layers.
 */
header frer_t {
    bit<16> tpid;
    bit<16> reserved;
    bit<16> sequence_num;
}

struct frer_headers_t {
    frer_t[4] rtag;
}

struct frer_metadata_t {
    bit<8> tag_count;
    bit<32> tag_bytes;
    bit<32> remaining_bytes;
    bit<16> next_type_or_length;
}

/**
 * R-TAG parsing and local delivery (P4_16, v1model).
 * The caller positions the cursor at the first 0xF1C1 EtherType, before
 * extracting that field, and supplies the bounded remaining frame length
 * excluding FCS. The example parses up to four consecutive R-TAGs. It leaves
 * the following Type/Length and payload at the cursor for the next parser.
 * VLAN tags can precede or follow an R-TAG according to the configured stack.
 * Emit rtag, then the original remainder to preserve the frame.
 *
 * stream_handle is local metadata from Stream identification. The selected
 * owner manages sequence generation, replication and recovery history with
 * its configured window and reset timers. Sequence generation runs once per
 * original frame, wrapping modulo 65536. All replicas carry the same sequence
 * number at each redundancy layer.
 */
/*
parser frer_parser(packet_in pkt, out frer_headers_t hdr,
                   out frer_metadata_t meta, in bit<32> frame_bytes) {
    state start {
        meta.tag_count = 0;
        meta.tag_bytes = 0;
        meta.remaining_bytes = frame_bytes;
        meta.next_type_or_length = 0;
        verify(meta.remaining_bytes >= 2, error.HeaderTooShort);
        meta.next_type_or_length = pkt.lookahead<bit<16>>();
        verify(meta.next_type_or_length == ETHERTYPE_FRER, error.NoMatch);
        transition parse_tag;
    }

    state parse_tag {
        verify(meta.tag_count < 4, error.StackOutOfBounds);
        verify(meta.remaining_bytes >= 6, error.HeaderTooShort);
        pkt.extract(hdr.rtag.next);
        meta.tag_count = meta.tag_count + 1;
        meta.tag_bytes = meta.tag_bytes + 6;
        meta.remaining_bytes = meta.remaining_bytes - 6;
        transition next_protocol;
    }

    state next_protocol {
        verify(meta.remaining_bytes >= 2, error.HeaderTooShort);
        meta.next_type_or_length = pkt.lookahead<bit<16>>();
        transition select(meta.next_type_or_length) {
            ETHERTYPE_FRER: parse_tag;
            default: accept;
        }
    }
}

control frer_control(inout frer_headers_t hdr, in frer_metadata_t meta,
                     inout standard_metadata_t standard_metadata,
                     in bit<32> stream_handle) {
    action deliver_frer(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    action drop_frer() {
        mark_to_drop(standard_metadata);
    }
    table frer_streams {
        key = {
            standard_metadata.ingress_port: exact;
            stream_handle: exact;
        }
        actions = { deliver_frer; drop_frer; }
        default_action = drop_frer();
    }
    apply {
        if (standard_metadata.parser_error != error.NoError) {
            drop_frer();
        } else {
            frer_streams.apply();
        }
    }
}
*/

#endif
