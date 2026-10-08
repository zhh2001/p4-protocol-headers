#ifndef P4_PROTOCOL_HEADERS_GRE_P4
#define P4_PROTOCOL_HEADERS_GRE_P4

/**
 * GRE Header Definition in P4
 * Generic Routing Encapsulation over IP protocol 47
 * Version 0 with checksum, key and sequence fields (RFC 2784 and RFC 2890).
 */

/* Masks for the first 16 bits of the GRE header */
enum bit<16> gre_flags {
    CHECKSUM_PRESENT = 0x8000,
    KEY_PRESENT      = 0x2000,
    SEQUENCE_PRESENT = 0x1000,
    STRICT_SOURCE    = 0x0800   // Legacy RFC 1701 flag, unsupported by this parser
};

/* GRE Payload Protocol Types */
enum bit<16> gre_protocol_type {
    IP       = 0x0800,  // IPv4
    IPV6     = 0x86DD,  // IPv6
    MPLS     = 0x8847,  // MPLS unicast
    ERSPAN   = 0x88BE,  // ERSPAN Type II
    ETHERNET = 0x6558   // Transparent Ethernet Bridging, also used by NVGRE
};

/**
 * GRE Base Header (4 bytes)
 * Optional fields follow in checksum, key, sequence order.
 * The complete GRE header is 4, 8, 12 or 16 bytes.
 */
header gre_header {
    bit<1>  checksum_present;
    bit<1>  reserved1;         // Legacy routing flag, transmit zero
    bit<1>  key_present;
    bit<1>  sequence_present;
    bit<9>  reserved2;         // Transmit zero, see receive rules below
    bit<3>  version;           // Version 0
    bit<16> protocol;          // Payload EtherType
};

/**
 * GRE Checksum Block (4 bytes, present when C = 1)
 * The checksum covers the GRE header and its entire payload.
 */
header gre_checksum_header {
    bit<16> checksum;
    bit<16> reserved;          // Transmit zero
};

/* GRE Key (4 bytes, present when K = 1) */
header gre_key_header {
    bit<32> key;
};

/* GRE Sequence Number (4 bytes, present when S = 1) */
header gre_sequence_header {
    bit<32> sequence;
};

/**
 * P4 Parser Logic for GRE
 * The packet cursor must point to the GRE base header.
 * Parse outer IP headers separately using ipv4.p4 or ipv6.p4.
 * The outer parser handles IP options, extensions and fragmentation.
 * The headers struct contains gre_header gre_header, gre_checksum_header
 * gre_checksum, gre_key_header gre_key and gre_sequence_header gre_sequence.
 *
 * This example supports version 0 without legacy routing fields.
 * Bits 1, 4 and 5 must be zero. Reserved bits 6-12 are ignored on receipt.
 * Unknown payload protocols are left for the enclosing pipeline to handle.
 * The enclosing pipeline handles parser errors, payload bounds, checksum
 * verification over the full GRE packet and sequence tracking.
 */
/*
parser gre_parser(packet_in pkt, inout headers hdr) {
    state start {
        hdr.gre_checksum.setInvalid();
        hdr.gre_key.setInvalid();
        hdr.gre_sequence.setInvalid();
        pkt.extract(hdr.gre_header);
        verify(hdr.gre_header.version == 0, error.NoMatch);
        verify(hdr.gre_header.reserved1 == 0
               && hdr.gre_header.reserved2[8:7] == 0, error.NoMatch);
        transition select(hdr.gre_header.checksum_present) {
            1: parse_checksum;
            default: check_key;
        }
    }

    state parse_checksum {
        pkt.extract(hdr.gre_checksum);
        transition check_key;
    }

    state check_key {
        transition select(hdr.gre_header.key_present) {
            1: parse_key;
            default: check_sequence;
        }
    }

    state parse_key {
        pkt.extract(hdr.gre_key);
        transition check_sequence;
    }

    state check_sequence {
        transition select(hdr.gre_header.sequence_present) {
            1: parse_sequence;
            default: parse_payload;
        }
    }

    state parse_sequence {
        pkt.extract(hdr.gre_sequence);
        transition parse_payload;
    }

    state parse_payload {
        transition select(hdr.gre_header.protocol) {
            gre_protocol_type.IP: parse_inner_ip;
            gre_protocol_type.IPV6: parse_inner_ipv6;
            gre_protocol_type.MPLS: parse_mpls;
            gre_protocol_type.ETHERNET: parse_inner_ethernet;
            gre_protocol_type.ERSPAN: parse_erspan;
            default: accept;
        }
    }

    // Add the payload states using their respective header definitions.
}
*/

/**
 * P4 Match-Action Pipeline for GRE (v1model)
 * Forward by payload protocol and optional key.
 * Key presence distinguishes an absent key from a key whose value is zero.
 * This example forwards the GRE packet without changing its headers.
 */
/*
control gre_control(inout headers hdr,
                    inout standard_metadata_t standard_metadata) {
    bit<1> key_present;
    bit<32> tunnel_key;

    action forward_gre(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action drop_gre() {
        mark_to_drop(standard_metadata);
    }

    table gre_processing {
        key = {
            hdr.gre_header.protocol: exact;
            key_present: exact;
            tunnel_key: exact;
        }
        actions = {
            forward_gre;
            drop_gre;
            NoAction;
        }
        default_action = drop_gre();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.gre_header.isValid()) {
            drop_gre();
        } else {
            key_present = 0;
            tunnel_key = 0;
            if (hdr.gre_key.isValid()) {
                key_present = 1;
                tunnel_key = hdr.gre_key.key;
            }
            gre_processing.apply();
        }
    }
}
*/

#endif
