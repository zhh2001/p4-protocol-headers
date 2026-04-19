/**
 * DHCPv6 Header Definition in P4
 * IPv6 version of Dynamic Host Configuration Protocol
 * 动态主机配置协议v6
 */

/* DHCPv6 Message Types */
enum bit<8> dhcpv6_type {
    SOLICIT   = 1,
    ADVERTISE = 2,
    REQUEST   = 3,
    REPLY     = 7,
};

/**
 * DHCPv6 Header
 */
header dhcpv6 {
    bit<8>   msg_type;        // DHCPv6 message type (dhcpv6_type)
    bit<24>  transaction_id;  // Transaction identifier
    bit<16>  option_code;     // First option code
    bit<16>  option_len;      // Option length
    bit<128> client_id;       // DUID client identifier
    varbit<1024> options;       // Variable options
};
