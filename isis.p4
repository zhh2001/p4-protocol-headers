/**
 * IS-IS (ISO/IEC 10589, RFC 1195)
 * 公共头、六字节系统 ID 的基础 PDU 和有界 TLV 解析示例
 */
#ifndef P4_PROTOCOL_HEADERS_ISIS_P4
#define P4_PROTOCOL_HEADERS_ISIS_P4

typedef bit<8> isisTlv_t;
typedef bit<5> isisPduType_t;

const bit<8> ISIS_NLPID = 8w0x83;
const bit<8> ISIS_VERSION = 1;
const bit<8> ISIS_COMMON_BYTES = 8;
const bit<8> ISIS_LAN_HELLO_BYTES = 27;
const bit<8> ISIS_P2P_HELLO_BYTES = 20;
const bit<8> ISIS_LSP_BYTES = 27;
const bit<8> ISIS_CSNP_BYTES = 33;
const bit<8> ISIS_PSNP_BYTES = 17;

const isisPduType_t ISIS_L1_LAN_HELLO = 15;
const isisPduType_t ISIS_L2_LAN_HELLO = 16;
const isisPduType_t ISIS_P2P_HELLO = 17;
const isisPduType_t ISIS_L1_LSP = 18;
const isisPduType_t ISIS_L2_LSP = 20;
const isisPduType_t ISIS_L1_CSNP = 24;
const isisPduType_t ISIS_L2_CSNP = 25;
const isisPduType_t ISIS_L1_PSNP = 26;
const isisPduType_t ISIS_L2_PSNP = 27;

const isisTlv_t ISIS_TLV_AREA_ADDR = 1;
const isisTlv_t ISIS_TLV_IS_NEIGHBORS = 2;
const isisTlv_t ISIS_TLV_ES_NEIGHBORS = 3;
const isisTlv_t ISIS_TLV_LAN_NEIGHBORS = 6;
const isisTlv_t ISIS_TLV_PADDING = 8;
const isisTlv_t ISIS_TLV_LSP_ENTRIES = 9;
const isisTlv_t ISIS_TLV_AUTH = 10;
const isisTlv_t ISIS_TLV_CHECKSUM = 12;
const isisTlv_t ISIS_TLV_EXTD_IS_REACH = 22;
const isisTlv_t ISIS_TLV_IP_INTERNAL_REACH = 128;
const isisTlv_t ISIS_TLV_PROTOCOLS_SUPPORTED = 129;
const isisTlv_t ISIS_TLV_IP_EXTERNAL_REACH = 130;
const isisTlv_t ISIS_TLV_IP_INTF = 132;
const isisTlv_t ISIS_TLV_EXTD_IP_REACH = 135;
const isisTlv_t ISIS_TLV_HOSTNAME = 137;
const isisTlv_t ISIS_TLV_IP_REACH = ISIS_TLV_IP_INTERNAL_REACH;
// The shorter IP_REACH name denotes internal reachability. 133 is illegal
// in the IANA TLV registry and does not identify an IPv4 reachability TLV.

// Eight-octet common header, before the PDU-specific fixed part.
// system_id_len: 0 means six octets, 1..8 give the explicit length and
// 255 means zero octets. Other encodings are illegal. The example below
// accepts only 0 and 6. Both version octets are 1 for these base PDUs.
// Reserved fields are transmitted zero and ignored on receipt.
// max_area_addr: 0 denotes the default of three. Other values and area
// compatibility require the receiving instance's configuration.
header isis_t {
    bit<8> nlpid;
    bit<8> length_indicator; // Common + PDU-specific fixed header, in octets
    bit<8> version;
    bit<8> system_id_len;
    bit<3> pdu_reserved;
    isisPduType_t pdu_type;
    bit<8> pdu_version;
    bit<8> reserved;
    bit<8> max_area_addr;
}

// The following fixed parts use a six-octet System ID and exclude isis_t.
// TLVs follow each fixed part, bounded by pdu_length, which includes isis_t.
// LAN IDs add a one-octet pseudonode component. SNP source IDs append a
// circuit octet that is zero. LSP IDs add pseudonode and fragment octets.

// Nineteen octets, shared by Level 1 and Level 2 LAN IIH.
header isis_lan_hello_t {
    bit<6> reserved;
    bit<2> circuit_type; // 1: L1, 2: L2, 3: L1 and L2, 0: reserved
    bit<48> source_id;
    bit<16> holding_time;
    bit<16> pdu_length;
    bit<1> priority_reserved;
    bit<7> priority;
    bit<56> lan_id;
}

// Twelve octets. P2P IIH advertises circuit_type, not a separate L1/L2 PDU.
header isis_p2p_hello_t {
    bit<6> reserved;
    bit<2> circuit_type;
    bit<48> source_id;
    bit<16> holding_time;
    bit<16> pdu_length;
    bit<8> local_circuit_id;
}

// Nineteen octets, shared by Level 1 and Level 2 LSP.
// The checksum is Fletcher over LSP ID through the last PDU octet. The
// common header, pdu_length and remaining_lifetime are outside its coverage.
// A lifetime of zero represents a purge and is not a framing error.
header isis_lsp_t {
    bit<16> pdu_length;
    bit<16> remaining_lifetime;
    bit<64> lsp_id;
    bit<32> sequence_number;
    bit<16> checksum;
    bit<1> partition_repair;
    bit<4> attached; // Error, expense, delay and default metric ATT bits
    bit<1> overload;
    bit<2> is_type;
}

// Twenty-five octets. Start/end IDs delimit the reported LSDB range.
header isis_csnp_t {
    bit<16> pdu_length;
    bit<56> source_id;
    bit<64> start_lsp_id;
    bit<64> end_lsp_id;
}

// Nine octets. Requested/acknowledged LSPs are in following TLV 9 entries.
header isis_psnp_t {
    bit<16> pdu_length;
    bit<56> source_id;
}

// Base IS-IS TLV framing. length counts value octets only, from 0 to 255.
// TLV placement, repeated instances and nested values depend on the type.
header isis_tlv_t {
    isisTlv_t type;
    bit<8> length;
}

header isis_opaque_tlv_t {
    isisTlv_t type;
    bit<8> length;
    varbit<2040> value;
}

// One sixteen-octet LSP Entries (9) value entry. The value length must be
// a multiple of sixteen. A single TLV can contain at most fifteen entries.
header isis_lsp_entry_t {
    bit<16> remaining_lifetime;
    bit<64> lsp_id;
    bit<32> sequence_number;
    bit<16> checksum;
}

// First value octet of Authentication (10). The remaining value follows
// the selected authentication format and is validated by the local handler.
header isis_auth_prefix_t {
    bit<8> authentication_type;
}

struct isis_metadata_t {
    bit<32> pdu_bytes;
    bit<32> parsed_bytes;
    bit<32> trailing_bytes; // Outside the declared PDU, retained unchanged
    bit<16> remaining;
    bit<8> tlv_count;
    bit<2> level; // 1 or 2 for level-specific PDUs, 0 for P2P IIH
}

/**
 * Single base IS-IS PDU parser, with six-octet System IDs
 * headers contains isis_t isis, isis_lan_hello_t isis_lan,
 * isis_p2p_hello_t isis_p2p, isis_lsp_t isis_lsp, isis_csnp_t isis_csnp,
 * isis_psnp_t isis_psnp and isis_opaque_tlv_t[8] isis_tlvs.
 * metadata contains isis_metadata_t isis. The enclosing parser identifies
 * the IS-IS carrier, supplies physically bounded payload_bytes and places
 * the cursor at NLPID 0x83. On ordinary 802.3 LANs it first handles the
 * Length field and LLC FE FE 03. IS-IS is not an IP or UDP payload.
 * Emit isis, the valid fixed part, isis_tlvs and remaining bytes in order.
 *
 * The nine base PDU types use their exact fixed header lengths. TLVs are
 * bounded by pdu_length, not Ethernet padding or bytes beyond this PDU.
 * At most eight top-level TLVs are extracted. This is a local capacity,
 * not a protocol limit. Excess entries produce a parser error. Unknown,
 * repeated and zero-length values retain their original framing and bytes.
 * The eight-bit lengths also permit a 255-octet value (RFC 9885).
 *
 * This is a decoder and local dispatch example. The handler validates
 * TLV value layouts and placement, circuit/area compatibility, LSP ranges,
 * Fletcher checksums, authentication and protocol state. Adjacencies, DIS
 * election, flooding, purges, LSDB updates and SPF require that state.
 * Other System ID lengths and the Flooding Scope PDUs of RFC 7356 require
 * different layouts and are outside this example. Reserved bits are kept.
 */
/*
parser isis_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                   in bit<32> payload_bytes) {
    bit<32> value_bytes;

    state start {
        hdr.isis.setInvalid();
        hdr.isis_lan.setInvalid();
        hdr.isis_p2p.setInvalid();
        hdr.isis_lsp.setInvalid();
        hdr.isis_csnp.setInvalid();
        hdr.isis_psnp.setInvalid();
        hdr.isis_tlvs[0].setInvalid();
        hdr.isis_tlvs[1].setInvalid();
        hdr.isis_tlvs[2].setInvalid();
        hdr.isis_tlvs[3].setInvalid();
        hdr.isis_tlvs[4].setInvalid();
        hdr.isis_tlvs[5].setInvalid();
        hdr.isis_tlvs[6].setInvalid();
        hdr.isis_tlvs[7].setInvalid();
        meta.isis.pdu_bytes = 0;
        meta.isis.parsed_bytes = 0;
        meta.isis.trailing_bytes = payload_bytes;
        meta.isis.remaining = 0;
        meta.isis.tlv_count = 0;
        meta.isis.level = 0;
        verify(payload_bytes >= (bit<32>) ISIS_COMMON_BYTES,
               error.HeaderTooShort);
        pkt.extract(hdr.isis);
        verify(hdr.isis.nlpid == ISIS_NLPID
               && hdr.isis.version == ISIS_VERSION
               && hdr.isis.pdu_version == ISIS_VERSION, error.NoMatch);
        verify(hdr.isis.system_id_len == 0 || hdr.isis.system_id_len == 6,
               error.NoMatch);
        transition select(hdr.isis.pdu_type) {
            ISIS_L1_LAN_HELLO: parse_lan;
            ISIS_L2_LAN_HELLO: parse_lan;
            ISIS_P2P_HELLO: parse_p2p;
            ISIS_L1_LSP: parse_lsp;
            ISIS_L2_LSP: parse_lsp;
            ISIS_L1_CSNP: parse_csnp;
            ISIS_L2_CSNP: parse_csnp;
            ISIS_L1_PSNP: parse_psnp;
            ISIS_L2_PSNP: parse_psnp;
            default: unsupported_type;
        }
    }

    state parse_lan {
        verify(hdr.isis.length_indicator == ISIS_LAN_HELLO_BYTES,
               error.NoMatch);
        verify(payload_bytes >= (bit<32>) ISIS_LAN_HELLO_BYTES,
               error.HeaderTooShort);
        pkt.extract(hdr.isis_lan);
        meta.isis.pdu_bytes = (bit<32>) hdr.isis_lan.pdu_length;
        meta.isis.parsed_bytes = (bit<32>) ISIS_LAN_HELLO_BYTES;
        meta.isis.level = hdr.isis.pdu_type == ISIS_L1_LAN_HELLO ? 2w1 : 2w2;
        transition check_length;
    }

    state parse_p2p {
        verify(hdr.isis.length_indicator == ISIS_P2P_HELLO_BYTES,
               error.NoMatch);
        verify(payload_bytes >= (bit<32>) ISIS_P2P_HELLO_BYTES,
               error.HeaderTooShort);
        pkt.extract(hdr.isis_p2p);
        meta.isis.pdu_bytes = (bit<32>) hdr.isis_p2p.pdu_length;
        meta.isis.parsed_bytes = (bit<32>) ISIS_P2P_HELLO_BYTES;
        transition check_length;
    }

    state parse_lsp {
        verify(hdr.isis.length_indicator == ISIS_LSP_BYTES, error.NoMatch);
        verify(payload_bytes >= (bit<32>) ISIS_LSP_BYTES,
               error.HeaderTooShort);
        pkt.extract(hdr.isis_lsp);
        meta.isis.pdu_bytes = (bit<32>) hdr.isis_lsp.pdu_length;
        meta.isis.parsed_bytes = (bit<32>) ISIS_LSP_BYTES;
        meta.isis.level = hdr.isis.pdu_type == ISIS_L1_LSP ? 2w1 : 2w2;
        transition check_length;
    }

    state parse_csnp {
        verify(hdr.isis.length_indicator == ISIS_CSNP_BYTES, error.NoMatch);
        verify(payload_bytes >= (bit<32>) ISIS_CSNP_BYTES,
               error.HeaderTooShort);
        pkt.extract(hdr.isis_csnp);
        meta.isis.pdu_bytes = (bit<32>) hdr.isis_csnp.pdu_length;
        meta.isis.parsed_bytes = (bit<32>) ISIS_CSNP_BYTES;
        meta.isis.level = hdr.isis.pdu_type == ISIS_L1_CSNP ? 2w1 : 2w2;
        transition check_length;
    }

    state parse_psnp {
        verify(hdr.isis.length_indicator == ISIS_PSNP_BYTES, error.NoMatch);
        verify(payload_bytes >= (bit<32>) ISIS_PSNP_BYTES,
               error.HeaderTooShort);
        pkt.extract(hdr.isis_psnp);
        meta.isis.pdu_bytes = (bit<32>) hdr.isis_psnp.pdu_length;
        meta.isis.parsed_bytes = (bit<32>) ISIS_PSNP_BYTES;
        meta.isis.level = hdr.isis.pdu_type == ISIS_L1_PSNP ? 2w1 : 2w2;
        transition check_length;
    }

    state check_length {
        verify(meta.isis.pdu_bytes >= meta.isis.parsed_bytes,
               error.HeaderTooShort);
        verify(meta.isis.pdu_bytes <= payload_bytes, error.HeaderTooShort);
        meta.isis.remaining = (bit<16>) (meta.isis.pdu_bytes
                                       - meta.isis.parsed_bytes);
        meta.isis.trailing_bytes = payload_bytes - meta.isis.pdu_bytes;
        transition next_tlv;
    }

    state next_tlv {
        transition select(meta.isis.remaining, meta.isis.tlv_count) {
            (0, _): accept;
            (_, 8): capacity_exceeded;
            default: parse_tlv;
        }
    }

    state parse_tlv {
        verify(meta.isis.remaining >= 2, error.HeaderTooShort);
        value_bytes = (bit<32>) (pkt.lookahead<bit<16>>() & 16w0x00ff);
        verify(value_bytes + 2 <= (bit<32>) meta.isis.remaining,
               error.HeaderTooShort);
        pkt.extract(hdr.isis_tlvs.next, value_bytes * 8);
        meta.isis.remaining = meta.isis.remaining - (bit<16>) value_bytes - 2;
        meta.isis.parsed_bytes = meta.isis.parsed_bytes + value_bytes + 2;
        meta.isis.tlv_count = meta.isis.tlv_count + 1;
        transition next_tlv;
    }

    state unsupported_type {
        verify(false, error.NoMatch);
        transition accept;
    }

    state capacity_exceeded {
        verify(false, error.StackOutOfBounds);
        transition accept;
    }
}
*/

/**
 * Local PDU delivery (v1model)
 * handler_port and table action ports name local protocol endpoints.
 * Keep the original frame and receiving interface context. This table
 * selects an application and does not perform IS-IS forwarding or SPF.
 */
/*
control isis_control(inout headers hdr,
                     inout standard_metadata_t standard_metadata,
                     in bit<9> handler_port) {
    action deliver(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action deliver_default() {
        standard_metadata.egress_spec = handler_port;
    }

    table pdu_handlers {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.isis.pdu_type: exact;
        }
        actions = {
            deliver;
            deliver_default;
        }
        default_action = deliver_default();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.isis.isValid()
            || (!hdr.isis_lan.isValid() && !hdr.isis_p2p.isValid()
                && !hdr.isis_lsp.isValid() && !hdr.isis_csnp.isValid()
                && !hdr.isis_psnp.isValid())) {
            mark_to_drop(standard_metadata);
        } else {
            pdu_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_ISIS_P4
