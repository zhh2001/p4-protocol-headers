#ifndef P4_PROTOCOL_HEADERS_DNS_P4
#define P4_PROTOCOL_HEADERS_DNS_P4

/**
 * DNS Header Definition in P4
 * Domain Name System protocol for name resolution
 * 
 * DNS messages use UDP or TCP on port 53.
 */

/* DNS Opcode Types */
enum bit<4> dns_opcode {
    QUERY  = 0,     // Standard query
    IQUERY = 1,    // Inverse query (obsolete)
    STATUS = 2,    // Server status request
    UPDATE = 5     // Dynamic update
};

/* DNS Response Codes */
enum bit<4> dns_rcode {
    NO_ERROR     = 0,  // No error condition
    FORMAT_ERROR = 1,  // Query format error
    SERV_FAIL    = 2,  // Server failure
    NXDOMAIN     = 3,  // Non-existent domain
    NOT_IMP      = 4,  // Not implemented
    REFUSED      = 5   // Query refused
};

/* DNS Query Types */
enum bit<16> dns_qtype {
    A = 1,        // IPv4 address
    NS = 2,       // Name server
    CNAME = 5,    // Canonical name
    SOA = 6,      // Start of authority
    MX = 15,      // Mail exchange
    AAAA = 28,    // IPv6 address
    ANY = 255     // All records
};

/**
 * DNS Header (12 bytes)
 * Fixed header for all DNS messages
 */
header dns_header {
    bit<16> transaction_id;  // Query/response matching
    bit<1>  qr;              // Query (0) or Response (1)
    bit<4>  opcode;          // Message type (dns_opcode)
    bit<1>  aa;              // Authoritative answer
    bit<1>  tc;              // Truncated
    bit<1>  rd;              // Recursion desired
    bit<1>  ra;              // Recursion available
    bit<1>  z;               // Reserved (must be zero)
    bit<1>  ad;              // Authentic Data
    bit<1>  cd;              // Checking Disabled
    bit<4>  rcode;           // Low four bits of the response code (dns_rcode)
    bit<16> qdcount;  // Question entries count
    bit<16> ancount;  // Answer RRs count
    bit<16> nscount;  // Authority RRs count
    bit<16> arcount;  // Additional RRs count
};

/**
 * DNS Name Label (1-64 bytes)
 * Extract with (bit<32>)length * 8 variable bits, where length is 0-63.
 * A zero-length label terminates an uncompressed name.
 * Read and check the length byte with lookahead before extraction.
 */
header dns_label {
    bit<8> length;       // Label data length (0-63 bytes)
    varbit<504> value;   // Label data
};

/**
 * DNS Name Compression Pointer (2 bytes)
 * A name ends with a zero-length label or a compression pointer.
 * The caller validates the pointer and the expanded name length (max 255 bytes).
 */
header dns_compression_pointer {
    bit<2> tag;          // Must be 3 (binary 11)
    bit<14> offset;      // Offset from the start of the DNS message
};

/**
 * DNS Question Fields (4 bytes)
 * Parse QNAME as labels or a compression pointer before these fields.
 */
header dns_question {
    bit<16> qtype;     // Query type (dns_qtype)
    bit<16> qclass;    // Query class (usually 1=IN)
};

/**
 * DNS Resource Record Fields (10 bytes)
 * Parse NAME before these fields, then extract dns_rdata using RDLENGTH.
 */
header dns_rr {
    bit<16> type;      // RR type (dns_qtype)
    bit<16> class;     // RR class
    bit<32> ttl;       // Time to live
    bit<16> rdlength;  // Resource data length
};

/**
 * DNS Resource Data (0-65535 bytes)
 * Extract with (bit<32>)rdlength * 8 variable bits.
 * Lower the capacity if required by the target or application.
 */
header dns_rdata {
    varbit<524280> rdata;  // Resource data, interpreted according to TYPE and CLASS
};

/**
 * DNS over TCP Length Prefix (2 bytes)
 * The length excludes this prefix. TCP framing and reassembly are separate.
 */
header dns_tcp_length {
    bit<16> length;       // DNS message length (bytes)
};

/**
 * P4 Parser Logic for DNS
 * This example extracts only the fixed DNS header and preserves section counts.
 * The packet cursor must point to the DNS transaction ID.
 * The caller selects DNS traffic and handles framing, bounds and parser errors.
 * For TCP, consume the length prefix after reassembling the DNS message.
 * Include udp.p4 or tcp.p4 separately when parsing transport headers.
 */
/*
parser dns_parser(packet_in pkt, inout headers hdr) {
    state start {
        pkt.extract(hdr.dns_header);
        transition accept;
    }
}
*/

/**
 * P4 Match-Action Pipeline for DNS (v1model)
 * Match only fields from the fixed DNS header.
 */
/*
control dns_control(inout headers hdr,
                    inout standard_metadata_t standard_metadata) {
    action forward_dns(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    
    table dns_processing {
        key = {
            hdr.dns_header.qr: exact;
            hdr.dns_header.opcode: exact;
            hdr.dns_header.rcode: exact;
        }
        actions = {
            forward_dns;
            NoAction;
        }
        default_action = NoAction();
    }
    
    apply {
        if (hdr.dns_header.isValid()) {
            dns_processing.apply();
        }
    }
}
*/

#endif
