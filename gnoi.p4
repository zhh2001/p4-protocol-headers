/**
 * gNOI Header Definition in P4
 * gNOI协议P4定义
 * 
 * Note: gNOI provides operational RPCs for network devices
 *       网络设备操作接口协议定义
 */

/* gNOI Service Types */
enum bit<8> gnoi_service_type {
    OS_INSTALL = 0,     // 操作系统安装服务
    FILE       = 1,     // 文件管理服务
    SYSTEM     = 2,     // 系统服务
    PING       = 3,     // 网络诊断服务
    CERT_MGMT  = 4      // 证书管理服务
}

/* gNOI Operation Types */
enum bit<8> gnoi_operation {
    INSTALL  = 0,     // 安装操作
    ACTIVATE = 1,     // 激活操作
    VERIFY   = 2,     // 验证操作
    REMOVE   = 3,     // 移除操作
    STAT     = 4,     // 状态检查
    GET      = 5,     // 获取文件
    PUT      = 6      // 上传文件
}

/**
 * gNOI Message Header
 * gNOI消息头
 */
header gnoi_header {
    /* Service Type - 8 bits
     * 服务类型 - 8位
     * Identifies the gNOI service
     * 标识gNOI服务类型
     */
    gnoi_service_type service;
    
    /* Operation Type - 8 bits
     * 操作类型 - 8位
     * Service-specific operation
     * 服务特定的操作
     */
    gnoi_operation operation;
    
    /* Message ID - 32 bits
     * 消息ID - 32位
     * Unique message identifier
     * 唯一消息标识符
     */
    bit<32> message_id;
    
    /* Payload Length - 32 bits
     * 负载长度 - 32位
     * Length of message payload
     * 消息负载的长度
     */
    bit<32> payload_length;
}

/**
 * gNOI OS Install Service
 * gNOI操作系统安装服务
 */
header gnoi_os_install {
    /* Package Version Length - 16 bits
     * 包版本长度 - 16位
     * Length of OS package version
     * 操作系统包版本的长度
     */
    bit<16> version_length;
    
    /* Standby Supervisor - 8 bits
     * 备用管理引擎 - 8位
     * 0 = false, 1 = true
     * 0 = 主用, 1 = 备用
     */
    bit<8> standby;
    
    /* No Reboot - 8 bits
     * 不重启 - 8位
     * 0 = false, 1 = true
     * 0 = 安装后重启, 1 = 不重启
     */
    bit<8> no_reboot;
    
    /* Validate Only - 8 bits
     * 仅验证 - 8位
     * 0 = false, 1 = true
     * 0 = 实际安装, 1 = 仅验证
     */
    bit<8> validate_only;
}

/**
 * gNOI File Service
 * gNOI文件服务
 */
header gnoi_file {
    /* File Path Length - 16 bits
     * 文件路径长度 - 16位
     * Length of file path
     * 文件路径的长度
     */
    bit<16> path_length;
    
    /* File Size - 64 bits
     * 文件大小 - 64位
     * Size of file in bytes
     * 文件大小(字节)
     */
    bit<64> file_size;
    
    /* Hash Type - 8 bits
     * 哈希类型 - 8位
     * 0 = SHA256, 1 = SHA512, 2 = MD5
     */
    bit<8> hash_type;
    
    /* Hash Value Length - 16 bits
     * 哈希值长度 - 16位
     * Length of hash value
     * 哈希值的长度
     */
    bit<16> hash_length;
    
    /* Permissions - 16 bits
     * 权限 - 16位
     * Unix-style permissions
     * Unix风格权限
     */
    bit<16> permissions;
}

/**
 * gNOI System Service
 * gNOI系统服务
 */
header gnoi_system {
    /* Reboot Method - 8 bits
     * 重启方法 - 8位
     * 0 = COLD, 1 = POWERDOWN, etc.
     */
    bit<8> reboot_method;
    
    /* Delay - 32 bits
     * 延迟 - 32位
     * Seconds before reboot
     * 重启前的秒数
     */
    bit<32> delay;
    
    /* Message Length - 16 bits
     * 消息长度 - 16位
     * Length of reboot message
     * 重启消息的长度
     */
    bit<16> message_length;
    
    /* Subcomponents Count - 16 bits
     * 子组件数量 - 16位
     * Number of subcomponents
     */
    bit<16> subcomponent_count;
}

/**
 * gNOI Ping Service
 * gNOI网络诊断服务
 */
header gnoi_ping {
    /* Destination IP - 32 bits
     * 目的IP - 32位
     * IPv4 address to ping
     * 要ping的IPv4地址
     */
    bit<32> destination;
    
    /* Count - 16 bits
     * 计数 - 16位
     * Number of ping packets
     * ping包数量
     */
    bit<16> count;
    
    /* Interval - 32 bits
     * 间隔 - 32位
     * Nanoseconds between pings
     * ping间隔(纳秒)
     */
    bit<32> interval;
    
    /* Size - 16 bits
     * 大小 - 16位
     * Size of ping packet
     * ping包大小
     */
    bit<16> size;
    
    /* TTL - 8 bits
     * TTL - 8位
     * Time to live value
     * 生存时间值
     */
    bit<8> ttl;
}

/**
 * gNOI Certificate Management
 * gNOI证书管理
 */
header gnoi_cert_mgmt {
    /* Certificate ID Length - 16 bits
     * 证书ID长度 - 16位
     * Length of certificate ID
     * 证书ID的长度
     */
    bit<16> cert_id_length;
    
    /* Key Type - 8 bits
     * 密钥类型 - 8位
     * 0 = RSA, 1 = ECDSA, etc.
     */
    bit<8> key_type;
    
    /* Key Size - 16 bits
     * 密钥大小 - 16位
     * Size of key in bits
     * 密钥大小(位)
     */
    bit<16> key_size;
    
    /* Common Name Length - 16 bits
     * 通用名长度 - 16位
     * Length of certificate CN
     * 证书通用名的长度
     */
    bit<16> common_name_length;
    
    /* Validity Days - 32 bits
     * 有效期天数 - 32位
     * Certificate validity in days
     * 证书有效期(天)
     */
    bit<32> validity_days;
}

/**
 * gNOI Transport Header (over gRPC)
 * gNOI传输头(基于gRPC)
 */
header gnoi_transport_header {
    /* Frame Type - 8 bits
     * 帧类型 - 8位
     * 0 = DATA, 1 = HEADERS, etc.
     */
    bit<8> frame_type;
    
    /* Flags - 8 bits
     * 标志位 - 8位
     * gRPC frame flags
     * gRPC帧标志
     */
    bit<8> flags;
    
    /* Length - 24 bits
     * 长度 - 24位
     * Length of the frame payload
     * 帧负载的长度
     */
    bit<24> length;
    
    /* Stream ID - 32 bits
     * 流ID - 32位
     * Identifies the gRPC stream
     * 标识gRPC流
     */
    bit<32> stream_id;
}
