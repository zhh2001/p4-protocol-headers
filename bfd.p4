/**********************************************************
 * BFD Header (RFC 5880)
 * 双向转发检测协议报头 - 快速链路故障检测
 * Bidirectional Forwarding Detection Header
 * Sub-second link failure detection for routing protocols
 **********************************************************/

header bfd_t {
    bit<3>  version;          // Protocol version (1)                    协议版本号 (固定为 1)
    bit<5>  diag;             // Diagnostic code                        诊断代码
    bit<2>  state;            // Session state (0=Admin 1=Down 2=Init 3=Up) 会话状态
    bit<1>  poll;             // Poll flag                              轮询标志
    bit<1>  final_;           // Final flag                             最终标志
    bit<1>  ctrl_plane_indep; // Control plane independent flag         控制平面独立标志
    bit<1>  auth_present;     // Authentication present                 认证存在标志
    bit<1>  demand;           // Demand mode flag                       需求模式标志
    bit<1>  multipoint;       // Multipoint flag (reserved, must be 0)  多点标志 (保留)
    bit<8>  detect_mult;      // Detection multiplier                   检测倍数
    bit<8>  length;           // Packet length                          报文长度
    bit<32> my_discriminator;    // My discriminator                    本端标识符
    bit<32> your_discriminator;  // Your discriminator                  对端标识符
    bit<32> desired_min_tx;      // Desired min TX interval (us)        期望最小发送间隔 (微秒)
    bit<32> required_min_rx;     // Required min RX interval (us)       要求最小接收间隔 (微秒)
    bit<32> required_min_echo;   // Required min echo RX interval (us) 要求最小回声接收间隔 (微秒)
}

// BFD 诊断代码常量 (RFC 5880)
const bit<5> BFD_DIAG_NONE           = 0;  // 无诊断
const bit<5> BFD_DIAG_CTRL_EXPIRED   = 1;  // 控制检测超时
const bit<5> BFD_DIAG_ECHO_FAILED    = 2;  // 回声功能失败
const bit<5> BFD_DIAG_NEIGH_DOWN     = 3;  // 邻居通告会话关闭
const bit<5> BFD_DIAG_FWD_RESET      = 4;  // 转发平面重置
const bit<5> BFD_DIAG_PATH_DOWN      = 5;  // 路径关闭
const bit<5> BFD_DIAG_CONCAT_DOWN    = 6;  // 级联路径关闭
const bit<5> BFD_DIAG_ADMIN_DOWN     = 7;  // 管理性关闭

// BFD 会话状态常量
const bit<2> BFD_STATE_ADMIN_DOWN = 0;  // 管理性关闭
const bit<2> BFD_STATE_DOWN       = 1;  // 会话关闭
const bit<2> BFD_STATE_INIT       = 2;  // 会话初始化
const bit<2> BFD_STATE_UP         = 3;  // 会话正常
