/**
 * HTTP/1.1 Header Definition in P4
 * Hypertext Transfer Protocol version 1.1
 * 
 * Note: HTTP/1.1 is the most widely deployed HTTP version with persistent connections
 *       and chunked transfer encoding support
 */

/* HTTP/1.1 Methods */
enum bit<8> http_method {
    GET     = 0,
    POST    = 1,
    PUT     = 2,
    DELETE  = 3,
    HEAD    = 4,
    OPTIONS = 5,
    CONNECT = 6,
    TRACE   = 7,
    PATCH   = 8
};

/* HTTP/1.1 Connection Flags */
enum bit<8> http_connection_flags {
    CONN_CLOSE = 0x1,      // Connection: close
    CONN_KEEPALIVE = 0x2,  // Connection: keep-alive
    CHUNKED = 0x4          // Transfer-Encoding: chunked
};

/**
 * HTTP/1.1 Request Line (Variable length)
 * Start line for HTTP requests
 */
header http_request_line {
    bit<8> method;       // Request method (http_method)
    varbit<1024> uri;        // Request URI (variable length)
    varbit<1024> version;    // HTTP version (e.g. "HTTP/1.1")
};

/**
 * HTTP/1.1 Status Line (Variable length)
 * Start line for HTTP responses
 */
header http_status_line {
    varbit<1024> version;    // HTTP version
    bit<16> status_code;  // Status code (200, 404, etc.)
    varbit<1024> reason;     // Status text
};

/**
 * HTTP/1.1 Header Field (Variable length)
 * Single header key-value pair
 */
header http_header_field {
    varbit<1024> name;     // Header name
    varbit<1024> value;    // Header value
};

/**
 * HTTP/1.1 Chunk Header (Variable length)
 * Chunked transfer encoding metadata
 */
header http_chunk_header {
    bit<32> chunk_size;  // Chunk size in hex
    varbit<1024> ext;        // Optional chunk extensions
};

/**
 * TCP Transport Header (20 bytes)
 * Standard TCP header for HTTP/1.1
 */
header tcp_transport {
    bit<16> src_port;     // Source port
    bit<16> dst_port;     // Destination port (80 or 443)
    bit<32> seq_num;      // Sequence number
    bit<32> ack_num;      // Acknowledgment number
    bit<4>  data_offset;  // Data offset
    bit<6>  reserved;     // Reserved bits
    bit<6>  flags;        // TCP flags
    bit<16> window;       // Receive window
    bit<16> checksum;     // Checksum
    bit<16> urgent_ptr;   // Urgent pointer
};

/**
 * P4 Parser Logic for HTTP/1.1
 */
/*
parser http11_parser(packet_in pkt, out headers hdr) {
    state start {
        pkt.extract(hdr.tcp_transport);
        transition select(hdr.tcp_transport.dst_port) {
            80: parse_http11;  // HTTP
            443: parse_http11;  // HTTPS (after decryption)
            default: accept;
        }
    }
    
    state parse_http11 {
        // Peek first byte to determine request/response
        bit<8> first_byte;
        pkt.lookahead(first_byte);
        
        // Check if first character is letter (request) or 'H' (response)
        transition select(first_byte) {
            0x48: parse_status_line;  // 'H' from "HTTP/"
            default: parse_request_line;
        }
    }
    
    state parse_request_line {
        pkt.extract(hdr.http_request_line);
        transition parse_headers;
    }
    
    state parse_status_line {
        pkt.extract(hdr.http_status_line);
        transition parse_headers;
    }
    
    // Additional parse states for headers and body...
}
*/

/**
 * P4 Match-Action Pipeline for HTTP/1.1
 */
/*
control http11_control(inout headers hdr) {
    action process_request() {
        // Route based on HTTP method and URI
        route_http_request(
            hdr.http_request_line.method,
            hdr.http_request_line.uri
        );
    }
    
    action process_response() {
        // Handle response based on status code
        handle_http_response(
            hdr.http_status_line.status_code
        );
    }
    
    action parse_header_field() {
        // Process individual header field
        process_http_header(
            hdr.http_header_field.name,
            hdr.http_header_field.value
        );
    }
    
    action handle_chunked() {
        // Process chunked transfer encoding
        if (hdr.http_chunk_header.chunk_size == 0) {
            end_of_chunks();
        } else {
            process_chunk(hdr.http_chunk_header.chunk_size);
        }
    }
    
    table http11_processing {
        key = {
            hdr.tcp_transport.dst_port: exact;
            hdr.http_request_line.method: exact;  // For requests
            hdr.http_status_line.status_code: exact;  // For responses
        }
        actions = {
            process_request;
            process_response;
            parse_header_field;
            handle_chunked;
            NoAction;
        }
        default_action = NoAction;
    }
    
    apply {
        http11_processing.apply();
    }
}
*/
