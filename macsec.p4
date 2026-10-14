#ifndef P4_PROTOCOL_HEADERS_MACSEC_P4
#define P4_PROTOCOL_HEADERS_MACSEC_P4

/**
 * MACsec (IEEE 802.1AE-2018, Clauses 9 and 10)
 * SecTAG、SCI 和 ICV 定义与本地分流示例
 * TCI follows Figure 9-4 as corrected by IEEE 802.1AE-2018/Cor 1-2020.
 * XPN retains the same SecTAG and carries only the low 32 bits of the PN.
 */

const bit<16> ETHERTYPE_MACSEC = 0x88E5;
const bit<8> MACSEC_GCM_ICV_BYTES = 16;
const bit<8> MACSEC_MIN_ICV_BYTES = 8;
const bit<8> MACSEC_MAX_ICV_BYTES = 16;
const bit<32> MACSEC_NON_SHORT_BYTES = 48;
const bit<16> MACSEC_ES_PORT_ID = 1;
const bit<16> MACSEC_SCB_PORT_ID = 0;

/* Six bytes after the MACsec EtherType. Ethernet carries that EtherType.
 * TCI/AN, from most to least significant bit: V ES SC SCB E C AN AN.
 * V = 0. SC indicates the optional eight-byte SCI. ES or SCB requires
 * SC = 0. E indicates confidentiality, C indicates changed Secure Data
 * or an ICV length other than 16. E = 1, C = 0 is reserved for the KaY.
 * AN selects one of four SAs in an SC. SL's upper two bits are zero.
 * A transmitter sets SL to Secure Data length for 1-47 bytes, otherwise 0.
 * PN carries 32 bits, including when the configured Cipher Suite uses XPN.
 * Including the preceding EtherType, SecTAG is eight or sixteen bytes.
 */
header macsec_sectag_t {
    bit<1> tci_v;
    bit<1> tci_es;
    bit<1> tci_sc;
    bit<1> tci_scb;
    bit<1> tci_e;
    bit<1> tci_c;
    bit<2> association_num;
    bit<2> reserved;
    bit<6> short_length;
    bit<32> packet_number;
}

/* Optional SCI, eight bytes: system MAC address and 16-bit port identifier.
 * If SC = 0, ES selects Source MAC || 0x0001, while SCB selects Source MAC
 * || 0x0000 and takes precedence over ES. With neither bit, the receive SC
 * comes from configured point-to-point peer context. SCI is used by the
 * Cipher Suite even when it is not transmitted.
 */
header macsec_sci_t {
    bit<48> mac_addr;
    bit<16> port_id;
}

/* Sixteen-byte ICV for GCM-AES-128/256 and GCM-AES-XPN-128/256.
 * Its position follows Secure Data, before any Ethernet padding or FCS.
 */
header macsec_icv_t {
    bit<128> icv;
}

/* Clause 9.11 permits Cipher Suite dependent ICV lengths of 8-16 bytes.
 * Extract with the length supplied by the configured suite, not a wire flag.
 */
header macsec_icv_variable_t {
    varbit<128> icv;
}

struct macsec_headers_t {
    macsec_sectag_t tag;
    macsec_sci_t sci;
}

struct macsec_metadata_t {
    bit<8> header_bytes;
    bit<64> sci;
    bool sci_known;
    bit<32> secure_data_bytes;
    bit<32> icv_offset;
    bit<8> icv_bytes;
    bit<32> padding_bytes;
    bool confidentiality;
    bool changed_text;
    bool extended_pn;
}

/**
 * SecY framing and local delivery example (P4_16, v1model).
 * The cursor follows EtherType 0x88E5. macsec_bytes counts bytes from TCI/AN
 * through the end of the received frame, including Ethernet padding and
 * excluding FCS. The caller supplies the validated frame bound, Source MAC,
 * configured receive Cipher Suite ICV length and XPN mode. GCM suites use 16
 * ICV bytes. implicit_sci/implicit_sci_known identify a configured peer SC
 * when SC, ES and SCB are all clear.
 *
 * The parser extracts SecTAG and optional SCI. Nonzero SL locates the ICV
 * before possible Ethernet padding. With SL = 0, Secure Data is at least 48
 * bytes and the ICV ends at the supplied frame bound. Data, ICV and padding
 * remain unchanged. Emit tag and sci before that untouched remainder.
 *
 * context_id identifies the receive SecY. Its configured SA handler checks
 * Cipher Suite flags, authenticates using MAC addresses and the complete
 * MACsec PDU, recovers the full PN for XPN, checks replay state and decrypts
 * content. The handler removes SecTAG, ICV and padding after validation,
 * then delivers User Data to the Controlled Port. E = 1, C = 0 uses the
 * separate KaY receive path. MKA, key installation and MAC Privacy contents
 * are handled by their protocol owners.
 */
/*
parser macsec_parser(packet_in pkt, out macsec_headers_t hdr,
                     out macsec_metadata_t meta, in bit<32> macsec_bytes,
                     in bit<48> source_mac, in bit<8> icv_bytes,
                     in bool extended_pn, in bit<64> implicit_sci,
                     in bool implicit_sci_known) {
    bit<32> available;

    state start {
        meta.header_bytes = 0;
        meta.sci = 0;
        meta.sci_known = false;
        meta.secure_data_bytes = 0;
        meta.icv_offset = 0;
        meta.icv_bytes = icv_bytes;
        meta.padding_bytes = 0;
        meta.confidentiality = false;
        meta.changed_text = false;
        meta.extended_pn = extended_pn;
        verify(icv_bytes >= MACSEC_MIN_ICV_BYTES
               && icv_bytes <= MACSEC_MAX_ICV_BYTES, error.NoMatch);
        verify(macsec_bytes >= 6, error.HeaderTooShort);
        pkt.extract(hdr.tag);
        verify(hdr.tag.tci_v == 0 && hdr.tag.reserved == 0, error.NoMatch);
        verify(hdr.tag.tci_sc == 0
               || (hdr.tag.tci_es == 0 && hdr.tag.tci_scb == 0), error.NoMatch);
        verify(hdr.tag.tci_e == 0 || hdr.tag.tci_c == 1, error.NoMatch);
        verify(hdr.tag.tci_c == 1 || icv_bytes == MACSEC_GCM_ICV_BYTES,
               error.NoMatch);
        verify(extended_pn || hdr.tag.packet_number != 0, error.NoMatch);
        meta.header_bytes = 6;
        meta.confidentiality = hdr.tag.tci_e == 1;
        meta.changed_text = hdr.tag.tci_c == 1;
        transition select(hdr.tag.tci_sc) {
            1: parse_sci;
            default: implicit_channel;
        }
    }

    state parse_sci {
        verify(macsec_bytes >= 14, error.HeaderTooShort);
        pkt.extract(hdr.sci);
        meta.header_bytes = 14;
        meta.sci = ((bit<64>)hdr.sci.mac_addr << 16) | (bit<64>)hdr.sci.port_id;
        meta.sci_known = true;
        transition frame_bounds;
    }

    state implicit_channel {
        if (hdr.tag.tci_scb == 1) {
            meta.sci = ((bit<64>)source_mac << 16) | (bit<64>)MACSEC_SCB_PORT_ID;
            meta.sci_known = true;
        } else if (hdr.tag.tci_es == 1) {
            meta.sci = ((bit<64>)source_mac << 16) | (bit<64>)MACSEC_ES_PORT_ID;
            meta.sci_known = true;
        } else {
            meta.sci = implicit_sci;
            meta.sci_known = implicit_sci_known;
        }
        transition frame_bounds;
    }

    state frame_bounds {
        available = macsec_bytes - (bit<32>)meta.header_bytes;
        verify(available >= (bit<32>)icv_bytes + 1, error.HeaderTooShort);
        transition select(hdr.tag.short_length) {
            0: non_short_frame;
            default: short_frame;
        }
    }

    state non_short_frame {
        meta.secure_data_bytes = available - (bit<32>)icv_bytes;
        verify(meta.secure_data_bytes >= MACSEC_NON_SHORT_BYTES,
               error.HeaderTooShort);
        meta.icv_offset = (bit<32>)meta.header_bytes + meta.secure_data_bytes;
        transition accept;
    }

    state short_frame {
        meta.secure_data_bytes = (bit<32>)hdr.tag.short_length;
        verify(available >= meta.secure_data_bytes + (bit<32>)icv_bytes,
               error.HeaderTooShort);
        meta.icv_offset = (bit<32>)meta.header_bytes + meta.secure_data_bytes;
        meta.padding_bytes = available - meta.secure_data_bytes - (bit<32>)icv_bytes;
        transition accept;
    }
}

control macsec_control(inout macsec_headers_t hdr,
                       in macsec_metadata_t meta,
                       inout standard_metadata_t standard_metadata,
                       in bit<32> context_id) {
    action deliver_macsec(bit<9> handler_port) {
        standard_metadata.egress_spec = handler_port;
    }

    action drop_macsec() {
        mark_to_drop(standard_metadata);
    }

    table receive_sa_handlers {
        key = {
            context_id: exact;
            meta.sci: exact;
            hdr.tag.association_num: exact;
        }
        actions = {
            deliver_macsec;
            drop_macsec;
        }
        default_action = drop_macsec();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.tag.isValid() || !meta.sci_known) {
            drop_macsec();
        } else {
            receive_sa_handlers.apply();
        }
    }
}
*/

#endif
