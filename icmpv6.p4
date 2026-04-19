/**
 * ICMPv6 Header Definition in P4
 * ICMPv6 报头 P4 定义
 */
header icmpv6_t {
    /* Type - 8 bits
     * 类型 - 8 位
     * Identifies the general category of the message
     * 标识消息的通用类别
     * e.g. 1=Destination Unreachable, 128=Echo Request
     * 例如：1=目的地不可达，128=回显请求
     */
    bit<8> type;
    
    /* Code - 8 bits
     * 代码 - 8 位
     * Provides more specific information about the message
     * 提供关于消息的更具体信息
     * e.g. For Type=1 (Destination Unreachable):
     *      0=No route to destination, 1=Communication prohibited
     * 例如：对于类型=1(目的地不可达)：
     *      0=无路由到目的地，1=通信被禁止
     */
    bit<8> code;
    
    /* Checksum - 16 bits
     * 校验和 - 16 位
     * Error-checking field for the ICMPv6 message
     * ICMPv6消息的错误检查字段
     * Covers the ICMPv6 message plus IPv6 pseudo-header
     * 覆盖 ICMPv6 消息和 IPv6 伪头部
     */
    bit<16> checksum;
    
    /* Message Body - variable
     * 消息体 - 可变
     * Content depends on Type and Code
     * 内容取决于类型和代码
     */
    varbit<1024> message_body;  // Maximum ICMPv6 message size is typically 1232 bytes
                                // ICMPv6 消息最大大小通常为 1232 字节
}

/**
 * ICMPv6 Neighbor Discovery Option Header
 * ICMPv6 邻居发现选项报头
 * Used in Neighbor Solicitation/Advertisement messages
 * 用于邻居请求/通告消息
 */
header icmpv6_nd_option_t {
    /* Type - 8 bits
     * 类型 - 8 位
     * Identifies the option type
     * 标识选项类型
     * e.g. 1=Source Link-layer Address, 2=Target Link-layer Address
     * 例如：1=源链路层地址，2=目标链路层地址
     */
    bit<8> type;
    
    /* Length - 8 bits
     * 长度 - 8 位
     * Length of the option in 8-octet units (including Type and Length fields)
     * 选项长度以 8 字节为单位(包括类型和长度字段)
     */
    bit<8> length;
    
    /* Value - variable
     * 值 - 可变
     * Option data (length = (Length * 8) - 2)
     * 选项数据(长度 = (Length * 8) - 2)
     */
    varbit<1016> value;  // Maximum option size is 256 * 8=2048 bits minus 2 bytes for Type/Length
                         // 最大选项大小为 256 * 8 = 2048 位减去类型/长度的 2 字节
}

/**
 * ICMPv6 Echo Request/Reply Header
 * ICMPv6 回显请求/回复报头
 * Used in ping operations (Type 128=Request, 129=Reply)
 * 用于 ping 操作(类型128=请求，129=回复)
 */
header icmpv6_echo_t {
    /* Identifier - 16 bits
     * 标识符 - 16 位
     * Used to match requests with replies
     * 用于将请求与回复匹配
     * Often set to process ID in implementations
     * 在实现中通常设置为进程 ID
     */
    bit<16> identifier;
    
    /* Sequence Number - 16 bits
     * 序列号 - 16 位
     * Used to match requests with replies
     * 用于将请求与回复匹配
     * Incremented for each packet sent
     * 每发送一个数据包递增
     */
    bit<16> sequence_number;
    
    /* Data - variable
     * 数据 - 可变
     * Optional data included in echo request/reply
     * 包含在回显请求/回复中的可选数据
     */
    varbit<1024> data;  // Typically includes timestamp for RTT calculation
                        // 通常包含用于 RTT 计算的时间戳
}
