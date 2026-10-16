#ifndef P4_PROTOCOL_HEADERS_UDP_P4
#define P4_PROTOCOL_HEADERS_UDP_P4

/**
 * UDP header and bounded parsing examples (RFC 768)
 * UDP 报头及有界解析示例
 */

/* Well-known UDP Ports */
enum bit<16> udp_ports {
    DNS = 53,          // Domain Name System
    DHCP_CLIENT = 68,  // DHCP Client
    DHCP_SERVER = 67,  // DHCP Server
    NTP = 123,         // Network Time Protocol
    SNMP = 161,        // Simple Network Management
    TFTP = 69          // Trivial File Transfer
};

/**
 * UDP Header (8 bytes)
 * Standard UDP header format
 */
header udp_header {
    bit<16> src_port;   // Source port number
    bit<16> dst_port;   // Destination port number
    bit<16> length;     // Header + data bytes, zero for UDP jumbograms
    bit<16> checksum;   // Optional for IPv4, normally required for IPv6
};

// Local parsing status, not part of the UDP wire header.
struct udp_metadata_t {
    bit<32> payload_bytes;   // UDP data present in this packet or first fragment
    bit<32> trailing_bytes;  // IP payload bytes after the end of the UDP datagram
    bool complete;          // False for a first fragment with more fragments
}

/**
 * Bounded UDP header parsing. The cursor points to UDP after IP protocol 17
 * classification, IP options and IPv6 extensions. udp_bytes is the validated,
 * physically present IP payload length from this cursor, excluding link padding.
 * Call only for an unfragmented packet, a reassembled packet or the first
 * fragment. more_fragments is the IPv4 MF or IPv6 Fragment M flag, false for
 * an unfragmented or reassembled packet. Pass hdr.udp_header and meta.udp to
 * the output parameters, using udp_header and udp_metadata_t for those members.
 *
 * Only the fixed header is extracted. payload_bytes bounds the UDP data present
 * here, and complete stays false when reassembly is needed. Payload parsing
 * uses that bound after the call. UDP data, trailing IP bytes and link padding
 * remain unchanged. UDP Length zero uses a separate RFC 2675 path.
 */
/*
parser udp_parser(packet_in pkt, out udp_header udp, out udp_metadata_t meta,
                  in bit<32> udp_bytes, in bool more_fragments) {
    state start {
        udp.setInvalid();
        meta.payload_bytes = 0;
        meta.trailing_bytes = 0;
        meta.complete = false;
        verify(udp_bytes >= 8, error.PacketTooShort);
        pkt.extract(udp);
        verify(udp.length >= 8, error.HeaderTooShort);
        if (!more_fragments) {
            verify((bit<32>)udp.length <= udp_bytes, error.PacketTooShort);
        }
        meta.payload_bytes = (bit<32>)udp.length - 8;
        if (meta.payload_bytes > udp_bytes - 8) {
            meta.payload_bytes = udp_bytes - 8;
        }
        meta.trailing_bytes = udp_bytes - 8 - meta.payload_bytes;
        meta.complete = !more_fragments;
        transition accept;
    }
}
*/

/**
 * P4 Match-Action Pipeline for UDP (v1model)
 * Call for traffic selected by the enclosing IP pipeline. headers contains
 * udp_header udp_header. A table hit can select an egress port, while a miss
 * preserves the existing decision. Parser or reported checksum errors drop
 * and exit ingress. Reassembly, fragment forwarding and checksum verification
 * use the enclosing pipeline's IP and endpoint context.
 */
/*
control udp_control(inout headers hdr,
                    inout standard_metadata_t standard_metadata) {
    action forward_udp(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action drop_udp() {
        mark_to_drop(standard_metadata);
        exit;
    }
    
    table udp_processing {
        key = {
            hdr.udp_header.dst_port: exact;
        }
        actions = {
            forward_udp;
            drop_udp;
            NoAction;
        }
        default_action = NoAction();
    }
    
    apply {
        if (standard_metadata.parser_error != error.NoError
            || standard_metadata.checksum_error == 1) {
            drop_udp();
        } else if (hdr.udp_header.isValid()) {
            udp_processing.apply();
        }
    }
}
*/

#endif
