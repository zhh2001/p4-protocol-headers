typedef bit<32> ip4Addr_t;

// Routing Information Protocol  经典的距离向量路由协议，常用于小型网络
header rip_t {
    // 命令字段 (8 bits) - 1=请求 2=响应
    // Command (8 bits) - 1=Request 2=Response
    bit<8>   command;

    // 版本号 (8 bits) - 1=RIPv1 2=RIPv2
    // Version (8 bits) - 1=RIPv1 2=RIPv2
    bit<8>   version;

    // 保留字段 (16 bits) - 必须置 0
    // Reserved (16 bits) - Must be zero
    bit<16>  reserved;

    // 路由条目 (可变数量) - 最多 25 个条目
    // Routing entries (variable) - Max 25 entries
    // rip_entry_t[25] entries;  // (removed: nested header reference)
}

header rip_entry_t {
    // 地址族标识 (16 bits) - 2=IP 0xFFFF=认证
    // Address Family (16 bits) - 2=IP 0xFFFF=Auth
    bit<16>   address_family;

    // 路由标签 (16 bits) - 用于策略路由
    // Route tag (16 bits) - For policy routing
    bit<16>   route_tag;

    // IP 地址 (32 bits) - 目标网络地址
    // IP address (32 bits) - Destination network
    ip4Addr_t ip_address;

    // 子网掩码 (32 bits) - RIPv2 新增字段
    // Netmask (32 bits) - Added in RIPv2
    bit<32>   netmask;

    // 下一跳 (32 bits) - RIPv2 新增字段
    // Next hop (32 bits) - Added in RIPv2
    bit<32>   next_hop;

    // 度量值 (32 bits) - 跳数(1-15) 16=不可达
    // Metric (32 bits) - Hop count(1-15) 16=Unreachable
    bit<32>   metric;
}

// RIPv2 认证头
header rip_auth_t {
    // 认证类型 (16 bits) - 1=明文 2=MD5
    // Auth type (16 bits) - 1=Plaintext 2=MD5
    bit<16>  auth_type;

    // 认证数据 (16 bytes) - 密码或 MD5 摘要
    // Authentication (16 bytes) - Password or digest
    bit<128> auth_data;
}