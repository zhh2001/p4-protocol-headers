/**
 * RESTCONF Header Definition in P4
 * RESTCONF协议P4定义
 * 
 * Note: RESTCONF is an HTTP-based protocol for managing network devices
 *       基于HTTP的网络设备管理协议定义
 */

/* RESTCONF Methods */
enum bit<8> restconf_method {
    OPTIONS = 0,    // 选项请求
    HEAD    = 1,    // 头部请求
    GET     = 2,    // 获取资源
    POST    = 3,    // 创建资源
    PUT     = 4,    // 更新资源
    PATCH   = 5,    // 部分更新
    DELETE  = 6     // 删除资源
}

/* RESTCONF Data Formats */
enum bit<8> restconf_format {
    XML  = 0,       // XML格式
    JSON = 1,       // JSON格式
    YANG = 2        // YANG格式
}

/**
 * RESTCONF Request Header
 * RESTCONF 请求头
 */
header restconf_request {
    /* Method - 8 bits
     * 方法 - 8位
     * HTTP method for RESTCONF
     * RESTCONF的HTTP方法
     */
    restconf_method method;
    
    /* API Version - 16 bits
     * API版本 - 16位
     * RESTCONF API version (major << 8 | minor)
     * RESTCONF API版本(主版本<<8 | 次版本)
     */
    bit<16> api_version;
    
    /* Content-Type - 8 bits
     * 内容类型 - 8位
     * Format of request payload
     * 请求负载的格式
     */
    restconf_format content_type;
    
    /* Accept - 8 bits
     * 接受类型 - 8位
     * Desired response format
     * 期望的响应格式
     */
    restconf_format accept;
    
    /* Path Depth - 16 bits
     * 路径深度 - 16位
     * Depth of YANG path in request
     * 请求中YANG路径的深度
     */
    bit<16> path_depth;
    
    /* Query Parameter Bitmap - 16 bits
     * 查询参数位图 - 16位
     * Bit flags for query parameters
     * 查询参数的位标志
     */
    bit<16> query_params;
    
    /* Content Length - 32 bits
     * 内容长度 - 32位
     * Length of request payload
     * 请求负载的长度
     */
    bit<32> content_length;
}

/**
 * RESTCONF Response Header
 * RESTCONF 响应头
 */
header restconf_response {
    /* Status Code - 16 bits
     * 状态码 - 16位
     * HTTP status code
     * HTTP 状态码
     */
    bit<16> status_code;
    
    /* Content-Type - 8 bits
     * 内容类型 - 8位
     * Format of response payload
     * 响应负载的格式
     */
    restconf_format content_type;
    
    /* Error Tag Length - 16 bits
     * 错误标签长度 - 16位
     * Length of error tag if any
     * 错误标签的长度(如果有)
     */
    bit<16> error_tag_length;
    
    /* Error Message Length - 16 bits
     * 错误消息长度 - 16位
     * Length of error message if any
     * 错误消息的长度(如果有)
     */
    bit<16> error_message_length;
    
    /* ETag Length - 16 bits
     * ETag长度 - 16位
     * Length of entity tag
     * 实体标签的长度
     */
    bit<16> etag_length;
    
    /* Location Length - 16 bits
     * 位置长度 - 16位
     * Length of location header
     * 位置头的长度
     */
    bit<16> location_length;
    
    /* Content Length - 32 bits
     * 内容长度 - 32位
     * Length of response payload
     * 响应负载的长度
     */
    bit<32> content_length;
}

/**
 * RESTCONF Path Segment
 * RESTCONF路径段
 */
header restconf_path_segment {
    /* Module Name Length - 16 bits
     * 模块名称长度 - 16位
     * Length of YANG module name
     * YANG模块名称的长度
     */
    bit<16> module_name_length;
    
    /* Node Name Length - 16 bits
     * 节点名称长度 - 16位
     * Length of YANG node name
     * YANG节点名称的长度
     */
    bit<16> node_name_length;
    
    /* Key Count - 16 bits
     * 键数量 - 16位
     * Number of key-value pairs
     * 键值对的数量
     */
    bit<16> key_count;
}

/**
 * RESTCONF Key-Value Pair
 * RESTCONF键值对
 */
header restconf_key_value {
    /* Key Length - 16 bits
     * 键长度 - 16位
     * Length of key name
     * 键名的长度
     */
    bit<16> key_length;
    
    /* Value Length - 16 bits
     * 值长度 - 16位
     * Length of key value
     * 键值的长度
     */
    bit<16> value_length;
}

/**
 * RESTCONF Error
 * RESTCONF错误
 */
header restconf_error {
    /* Error Type - 16 bits
     * 错误类型 - 16位
     * 1 = transport, 2 = protocol, etc.
     */
    bit<16> error_type;
    
    /* Error Tag - 16 bits
     * 错误标签 - 16位
     * Identifies the error condition
     * 标识错误条件
     */
    bit<16> error_tag;
    
    /* Error App Tag Length - 16 bits
     * 错误应用标签长度 - 16位
     * Length of application-specific tag
     * 应用特定标签的长度
     */
    bit<16> error_app_tag_length;
    
    /* Error Path Length - 16 bits
     * 错误路径长度 - 16位
     * Length of error path if any
     * 错误路径的长度(如果有)
     */
    bit<16> error_path_length;
    
    /* Error Message Length - 16 bits
     * 错误消息长度 - 16位
     * Length of error message
     * 错误消息的长度
     */
    bit<16> error_message_length;
}

/**
 * RESTCONF Transport Header (over HTTP)
 * RESTCONF传输头(基于HTTP)
 */
header restconf_http_header {
    /* HTTP Version - 16 bits
     * HTTP版本 - 16位
     * Major << 8 | Minor
     * 主版本<<8 | 次版本
     */
    bit<16> http_version;
    
    /* Header Count - 16 bits
     * 头数量 - 16位
     * Number of HTTP headers
     * HTTP头的数量
     */
    bit<16> header_count;
    
    /* Payload Length - 32 bits
     * 负载长度 - 32位
     * Length of HTTP payload
     * HTTP负载的长度
     */
    bit<32> payload_length;
}
