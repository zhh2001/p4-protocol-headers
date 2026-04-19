/**
 * YANG Model Header Definition in P4
 * YANG 模型头 P4 定义
 * 
 * Note: YANG is a data modeling language for network configuration
 *       网络配置数据建模语言定义
 */

/* YANG Node Types */
enum bit<8> yang_node_type {
    CONTAINER = 0,    // 容器节点
    LIST      = 1,    // 列表节点
    LEAF      = 2,    // 叶子节点
    LEAF_LIST = 3,    // 叶子列表节点
    CHOICE    = 4,    // 选择节点
    CASE      = 5     // 情况节点
}

/**
 * YANG Model Header
 * YANG 模型头
 */
header yang_header {
    /* Module Name Length - 16 bits
     * 模块名称长度 - 16 位
     * Length of the YANG module name
     * YANG 模块名称的长度
     */
    bit<16> module_name_length;
    
    /* Revision Length - 16 bits
     * 修订版本长度 - 16 位
     * Length of the revision date
     * 修订日期的长度
     */
    bit<16> revision_length;
    
    /* Node Count - 32 bits
     * 节点数量 - 32位
     * Number of nodes in this model
     * 模型中的节点数量
     */
    bit<32> node_count;
    
    /* Namespace Length - 16 bits
     * 命名空间长度 - 16 位
     * Length of the XML namespace
     * XML命名空间的长度
     */
    bit<16> namespace_length;
    
    /* Feature Count - 16 bits
     * 特性数量 - 16 位
     * Number of features supported
     * 支持的特性数量
     */
    bit<16> feature_count;
}

/**
 * YANG Node Header
 * YANG 节点头
 */
header yang_node {
    /* Node Type - 8 bits
     * 节点类型 - 8 位
     * Type of YANG node
     * YANG 节点类型
     */
    yang_node_type node_type;
    
    /* Name Length - 16 bits
     * 名称长度 - 16 位
     * Length of node name
     * 节点名称的长度
     */
    bit<16> name_length;
    
    /* Description Length - 16 bits
     * 描述长度 - 16 位
     * Length of node description
     * 节点描述的长度
     */
    bit<16> description_length;
    
    /* Config Flag - 8 bits
     * 配置标志 - 8 位
     * 0 = false, 1 = true
     * 0 = 非配置节点, 1 = 配置节点
     */
    bit<8> config_flag;
    
    /* Status - 8 bits
     * 状态 - 8 位
     * 0 = current, 1 = deprecated, 2 = obsolete
     * 0 = 当前, 1 = 废弃, 2 = 过时
     */
    bit<8> status;
    
    /* Mandatory Flag - 8 bits
     * 强制标志 - 8 位
     * 0 = false, 1 = true
     * 0 = 非强制, 1 = 强制
     */
    bit<8> mandatory_flag;
    
    /* Presence Flag - 8 bits
     * 存在标志 - 8 位
     * 0 = false, 1 = true
     * 0 = 不存在, 1 = 存在
     */
    bit<8> presence_flag;
}

/**
 * YANG Type Header
 * YANG 类型头
 */
header yang_type {
    /* Base Type - 16 bits
     * 基础类型 - 16 位
     * 0 = binary, 1 = bits, 2 = boolean, etc.
     * 0 = 二进制, 1 = 位, 2 = 布尔, 等等
     */
    bit<16> base_type;
    
    /* Name Length - 16 bits
     * 名称长度 - 16 位
     * Length of type name if derived
     * 派生类型名称的长度
     */
    bit<16> name_length;
    
    /* Units Length - 16 bits
     * 单位长度 - 16 位
     * Length of units string
     * 单位字符串的长度
     */
    bit<16> units_length;
    
    /* Default Value Length - 16 bits
     * 默认值长度 - 16 位
     * Length of default value
     * 默认值的长度
     */
    bit<16> default_length;
    
    /* Fraction Digits - 8 bits
     * 小数位数 - 8 位
     * For decimal64 types
     * decimal64 类型的小数位数
     */
    bit<8> fraction_digits;
    
    /* Range Count - 8 bits
     * 范围数量 - 8 位
     * Number of range constraints
     * 范围约束的数量
     */
    bit<8> range_count;
    
    /* Length Count - 8 bits
     * 长度数量 - 8 位
     * Number of length constraints
     * 长度约束的数量
     */
    bit<8> length_count;
    
    /* Pattern Count - 8 bits
     * 模式数量 - 8 位
     * Number of pattern constraints
     * 模式约束的数量
     */
    bit<8> pattern_count;
}

/**
 * YANG Container Node
 * YANG 容器节点
 */
header yang_container {
    /* Presence Length - 16 bits
     * 存在声明长度 - 16位
     * Length of presence statement
     */
    bit<16> presence_length;
    
    /* Child Node Count - 32 bits
     * 子节点数量 - 32位
     * Number of child nodes
     */
    bit<32> child_count;
    
    /* Must Constraint Count - 16 bits
     * Must约束数量 - 16位
     * Number of must constraints
     */
    bit<16> must_count;
    
    /* When Condition Length - 16 bits
     * When条件长度 - 16位
     * Length of when condition
     */
    bit<16> when_length;
}

/**
 * YANG List Node
 * YANG 列表节点
 */
header yang_list {
    /* Key Length - 16 bits
     * 键长度 - 16位
     * Length of key specification
     * 键规格的长度
     */
    bit<16> key_length;
    
    /* Unique Constraint Count - 16 bits
     * 唯一约束数量 - 16位
     * Number of unique constraints
     * 唯一约束的数量
     */
    bit<16> unique_count;
    
    /* Min Elements - 32 bits
     * 最小元素数 - 32位
     * Minimum number of list entries
     * 列表项的最小数量
     */
    bit<32> min_elements;
    
    /* Max Elements - 32 bits
     * 最大元素数 - 32位
     * Maximum number of list entries
     * 列表项的最大数量
     */
    bit<32> max_elements;
    
    /* Ordered By - 8 bits
     * 排序方式 - 8位
     * 0 = system, 1 = user
     * 0 = 系统排序, 1 = 用户排序
     */
    bit<8> ordered_by;
}

/**
 * YANG Leaf Node
 * YANG 叶子节点
 */
header yang_leaf {
    /* Type Length - 16 bits
     * 类型长度 - 16 位
     * Length of type statement
     * 类型声明的长度
     */
    bit<16> type_length;
    
    /* Units Length - 16 bits
     * 单位长度 - 16 位
     * Length of units statement
     * 单位声明的长度
     */
    bit<16> units_length;
    
    /* Default Length - 16 bits
     * 默认值长度 - 16 位
     * Length of default statement
     * 默认值声明的长度
     */
    bit<16> default_length;
}

/**
 * YANG Transport Header (over XML/JSON)
 * YANG传输头(基于XML/JSON)
 */
header yang_transport_header {
    /* Encoding - 8 bits
     * 编码 - 8 位
     * 0 = XML, 1 = JSON
     */
    bit<8> encoding;
    
    /* Namespace Length - 16 bits
     * 命名空间长度 - 16位
     * Length of namespace declaration
     * 命名空间声明的长度
     */
    bit<16> namespace_length;
    
    /* Payload Length - 32 bits
     * 负载长度 - 32位
     * Length of the payload
     */
    bit<32> payload_length;
}
