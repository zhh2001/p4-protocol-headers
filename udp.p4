#ifndef P4_PROTOCOL_HEADERS_UDP_P4
#define P4_PROTOCOL_HEADERS_UDP_P4

/**
 * UDP Header Definition in P4
 * User Datagram Protocol for connectionless communication
 * 
 * Note: UDP provides minimal transport layer services with no reliability guarantees,
 *       commonly used for real-time and low-latency applications
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
    bit<16> length;     // Length of UDP header + data
    bit<16> checksum;   // Optional for IPv4, normally required for IPv6
};

/**
 * P4 Parser Logic for UDP
 * The packet cursor must point to the start of the UDP header.
 * Parse IP options and extension headers before calling this parser.
 * Only call it for unfragmented packets or the first fragment.
 * UDP jumbograms need a separate path for their zero length field.
 * Include ipv4.p4 or ipv6.p4 separately when parsing IP packets.
 * The enclosing pipeline handles parser errors, checksums and payload bounds.
 */
/*
parser udp_parser(packet_in pkt, inout headers hdr) {
    state start {
        transition parse_udp;
    }
    
    state parse_udp {
        pkt.extract(hdr.udp_header);
        verify(hdr.udp_header.length >= 8, error.HeaderTooShort);
        transition parse_udp_payload;
    }

    state parse_udp_payload {
        transition select(hdr.udp_header.dst_port) {
            udp_ports.DNS: parse_dns;
            udp_ports.NTP: parse_ntp;
            default: parse_payload;
        }
    }
    
    // Additional parse states for UDP payloads...
}
*/

/**
 * P4 Match-Action Pipeline for UDP (v1model)
 * Match the destination port after the UDP header has been parsed.
 */
/*
control udp_control(inout headers hdr,
                    inout standard_metadata_t standard_metadata) {
    action forward_udp(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    
    table udp_processing {
        key = {
            hdr.udp_header.dst_port: exact;
        }
        actions = {
            forward_udp;
            NoAction;
        }
        default_action = NoAction();
    }
    
    apply {
        if (hdr.udp_header.isValid()) {
            udp_processing.apply();
        }
    }
}
*/

#endif
