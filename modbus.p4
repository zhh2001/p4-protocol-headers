#ifndef P4_PROTOCOL_HEADERS_MODBUS_P4
#define P4_PROTOCOL_HEADERS_MODBUS_P4

/**
 * Modbus TCP (Application Protocol V1.1b3, TCP/IP Implementation Guide V1.0b)
 * Modbus TCP 应用报头和 PDU，传输层使用独立的 tcp.p4 定义
 */
const bit<16> MODBUS_TCP_PORT = 502;
const bit<16> MODBUS_PROTOCOL_ID = 0;
const bit<16> MODBUS_MAX_PDU_LENGTH = 253;
const bit<16> MODBUS_MAX_ADU_LENGTH = 260;

/* Common function codes. Unknown functions need application-level handling. */
enum bit<8> modbus_function {
    READ_COILS               = 0x01,
    READ_DISCRETE_INPUTS     = 0x02,
    READ_HOLDING_REGISTERS   = 0x03,
    READ_INPUT_REGISTERS     = 0x04,
    WRITE_SINGLE_COIL        = 0x05,
    WRITE_SINGLE_REGISTER    = 0x06,
    WRITE_MULTIPLE_COILS     = 0x0F,
    WRITE_MULTIPLE_REGISTERS = 0x10
};

enum bit<8> modbus_exception {
    ILLEGAL_FUNCTION                 = 0x01,
    ILLEGAL_DATA_ADDRESS             = 0x02,
    ILLEGAL_DATA_VALUE               = 0x03,
    SERVER_DEVICE_FAILURE           = 0x04,
    ACKNOWLEDGE                     = 0x05,
    SERVER_DEVICE_BUSY              = 0x06,
    MEMORY_PARITY_ERROR             = 0x08,
    GATEWAY_PATH_UNAVAILABLE        = 0x0A,
    GATEWAY_TARGET_FAILED_TO_RESPOND = 0x0B
};

/**
 * Modbus Application Protocol Header (7 bytes)
 * Length counts Unit ID plus the PDU. The complete TCP ADU is Length + 6
 * bytes, not Length + 7. Protocol ID is zero for Modbus.
 * Unit ID identifies a downstream device when using a gateway. Direct TCP
 * devices commonly use 0xff or 0. Its interpretation is application-specific.
 */
header modbus_header {
    bit<16> transaction_id;
    bit<16> protocol_id;
    bit<16> length;
    bit<8>  unit_id;
};

/**
 * Normal Request or Response PDU (1-253 bytes)
 * Data remains opaque. Extract (MBAP Length - 2) * 8 variable bits after
 * checking the ADU bounds. A function code can have a zero-byte data field.
 * Addresses and multi-byte protocol fields use network byte order. Register
 * application values can have device-specific layouts.
 */
header modbus_pdu {
    bit<8>       function_code;
    varbit<2016> data;             // Up to 252 bytes, excluding the function code
};

/**
 * Exception Response PDU (2 bytes)
 * The function code is the requested code with bit 7 set. MBAP Length is 3.
 * This is an alternative to modbus_pdu, not an extra PDU appended to it.
 */
header modbus_exception_pdu {
    bit<8> function_code;
    bit<8> exception_code;
};

struct modbus_metadata_t {
    bit<7>  function_code;         // Base code without the exception bit
    bit<1>  is_exception;
    bit<16> data_length;           // Normal data bytes, or 1 for an exception code
};

/**
 * P4 Parser Logic for One Modbus TCP ADU
 * The cursor points to the MBAP header. Pass the byte count of one complete,
 * already framed ADU as adu_length. The headers struct contains modbus_header
 * modbus_header, modbus_pdu modbus_pdu and modbus_exception_pdu
 * modbus_exception_pdu. Metadata contains modbus_metadata_t modbus.
 *
 * TCP is a byte stream. Segment boundaries and PSH do not delimit Modbus
 * messages. The caller handles reassembly, retransmissions, stream offsets
 * and separation of multiple ADUs before invoking this parser. Partial ADUs
 * need buffering rather than being treated as complete malformed messages.
 * IP/TCP options, fragment handling, checksums and parser errors are separate.
 *
 * Ordinary data and unknown nonzero function codes remain opaque. The Modbus
 * application validates function-specific lengths, addresses, quantities, byte
 * counts, exception codes, Unit ID policy and transaction/connection pairing.
 * No serial CRC is appended to a Modbus TCP ADU.
 */
/*
parser modbus_parser(packet_in pkt, inout headers hdr, inout metadata meta,
                     in bit<16> adu_length) {
    bit<8> function_octet;
    bit<32> data_bits;

    state start {
        hdr.modbus_pdu.setInvalid();
        hdr.modbus_exception_pdu.setInvalid();
        meta.modbus.function_code = 0;
        meta.modbus.is_exception = 0;
        meta.modbus.data_length = 0;
        verify(adu_length >= 8, error.HeaderTooShort);
        verify(adu_length <= MODBUS_MAX_ADU_LENGTH, error.NoMatch);
        pkt.extract(hdr.modbus_header);
        verify(hdr.modbus_header.protocol_id == MODBUS_PROTOCOL_ID, error.NoMatch);
        verify(hdr.modbus_header.length >= 2
               && hdr.modbus_header.length <= MODBUS_MAX_PDU_LENGTH + 1,
               error.NoMatch);
        verify(hdr.modbus_header.length == adu_length - 6, error.HeaderTooShort);
        function_octet = pkt.lookahead<bit<8>>();
        verify(function_octet[6:0] != 0, error.NoMatch);
        meta.modbus.function_code = function_octet[6:0];
        meta.modbus.is_exception = function_octet[7:7];
        transition select(meta.modbus.is_exception) {
            0: parse_normal;
            1: parse_exception;
        }
    }

    state parse_normal {
        meta.modbus.data_length = hdr.modbus_header.length - 2;
        data_bits = (bit<32>) meta.modbus.data_length * 8;
        pkt.extract(hdr.modbus_pdu, data_bits);
        transition accept;
    }

    state parse_exception {
        verify(hdr.modbus_header.length == 3, error.NoMatch);
        pkt.extract(hdr.modbus_exception_pdu);
        meta.modbus.data_length = 1;
        transition accept;
    }
}
*/

/**
 * P4 Match-Action Pipeline for Modbus TCP (v1model)
 * Pass is_response from the established TCP connection's client/server roles.
 * Port numbers alone are insufficient, particularly with configured ports.
 * Select a handler by direction, Unit ID, base function code and exception bit.
 * Packets stay intact. Register access, exceptions and TCP responses belong to
 * the Modbus application, which retains the connection and transaction context.
 */
/*
control modbus_control(inout headers hdr, inout metadata meta,
                       inout standard_metadata_t standard_metadata,
                       in bit<1> is_response) {
    action send_modbus(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action drop_modbus() {
        mark_to_drop(standard_metadata);
    }

    table modbus_handlers {
        key = {
            is_response: exact;
            hdr.modbus_header.unit_id: exact;
            meta.modbus.function_code: exact;
            meta.modbus.is_exception: exact;
        }
        actions = {
            send_modbus;
            drop_modbus;
        }
        default_action = drop_modbus();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.modbus_header.isValid()
            || (!hdr.modbus_pdu.isValid() && !hdr.modbus_exception_pdu.isValid())
            || (is_response == 0 && meta.modbus.is_exception == 1)) {
            drop_modbus();
        } else {
            modbus_handlers.apply();
        }
    }
}
*/

#endif // P4_PROTOCOL_HEADERS_MODBUS_P4
