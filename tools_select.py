from tools.multi_args_tool import SupportDictArgsTool
from tools.alert_rule import query_alert_rule_result,alert_rule_request,AlertruleInput
from tools.brute_force import brute_force_request, BruteForceInput
from tools.account_security_monitor import account_security_monitor_request, AccountSecurityMonitorInput
from tools.network_attack_detection import network_attack_request, NetworkAttackInput
from tools.system_security_monitor import system_security_request, SystemSecurityInput
from tools.free_query import free_query_request, FreeQueryInput
from tools.ip_trace import ip_trace_request, IpTraceInput



# ========================================
# 工具注册：将工具函数包装为 SupportDictArgsTool
# ========================================
# 注册方式：
#   1. 从 tools.xxx 模块 import 函数和 Input 模型
#   2. 用 SupportDictArgsTool.from_function() 包装
#   3. 添加到 tools 列表
#   4. tool_names 自动提取所有工具名称供 Agent 路由使用
tools = [
    # 告警规则查询工具
    SupportDictArgsTool.from_function(
            func=alert_rule_request,
            name="alert_rule_request",
            description="支持获取告警规则的结果分析。参数：gid（可选，客户编号，不填则查询所有客户，参数为None）、start_time（可选，不选则为None,开始时间，格式YYYY-MM-DD HH:MM:SS）、end_time（可选，结束时间，不选则为None,格式YYYY-MM-DD HH:MM:SS）",
            args_schema=AlertruleInput,
        ),
    # 暴力破解检测工具
    SupportDictArgsTool.from_function(
            func=brute_force_request,
            name="brute_force_request",
            description="暴力破解检测工具，查询 Fortigate 防火墙登录失败记录。参数：user_problem（用户问题描述，必填）、start_time（可选，开始时间，格式 YYYY-MM-DD）、end_time（可选，结束时间，格式 YYYY-MM-DD）、filter_ip（可选，IP 过滤）、filter_user（可选，用户名过滤）、aggregate（可选，是否聚合统计）、group_by（可选，聚合分组字段）、gid（可选，设备组 ID，用于过滤特定设备组的日志）",
            args_schema=BruteForceInput,
        ),
    # 账户安全监控工具
    SupportDictArgsTool.from_function(
            func=account_security_monitor_request,
            name="account_security_monitor_request",
            description="账户安全监控工具，用于监控账户安全状态（账户创建、删除、权限变更等）。参数：user_problem（用户问题描述，可选）、start_time（可选，开始时间）、end_time（可选，结束时间）、filter_ip（可选，IP 过滤）、filter_user（可选，用户名过滤）、aggregate（可选，是否聚合统计）、group_by（可选，聚合分组字段）、gid（可选，设备组 ID，用于过滤特定设备组的日志）",
            args_schema=AccountSecurityMonitorInput,
        ),
    # 网络攻击检测工具
    SupportDictArgsTool.from_function(
            func=network_attack_request,
            name="network_attack_request",
            description="网络攻击检测工具，用于检测网络攻击行为（IPS 入侵检测）。参数：user_problem（用户问题描述，可选）、start_time（可选，开始时间）、end_time（可选，结束时间）、filter_ip（可选，IP 过滤）、filter_user（可选，用户名过滤）、aggregate（可选，是否聚合统计）、group_by（可选，聚合分组字段）、gid（可选，设备组 ID，用于过滤特定设备组的日志）",
            args_schema=NetworkAttackInput,
        ),
    # 系统安全监控工具
    SupportDictArgsTool.from_function(
            func=system_security_request,
            name="system_security_request",
            description="系统安全监控工具，用于监控系统安全状态（设备重启、关机、系统配置变更等事件）。参数：user_problem（用户问题描述，可选）、start_time（可选，开始时间）、end_time（可选，结束时间）、filter_ip（可选，IP 过滤）、filter_user（可选，用户名过滤）、aggregate（可选，是否聚合统计）、group_by（可选，聚合分组字段）、gid（可选，设备组 ID，用于过滤特定设备组的日志）",
            args_schema=SystemSecurityInput,
        ),
    # L2 自由 PPL 查询工具
    SupportDictArgsTool.from_function(
            func=free_query_request,
            name="free_query_request",
            description="L2 自由 PPL 查询工具，支持用户自由提问并自动生成 PPL 查询。【重要】参数：user_problem（用户原始问题，LLM 必须从用户输入中提取并传递此参数！）、ppl_query（可选，不传则由 LLM 自动生成，索引组合由 index_config.yaml 配置，必须使用 log_g*_<vendor>_<product> 模式）、gid（可选，设备组 ID，用于过滤特定设备组的日志，对应日志字段@gid）、start_date（可选，查询起始日期）、end_date（可选，查询结束日期）",
            args_schema=FreeQueryInput,
        ),
    # IP 溯源工具
    SupportDictArgsTool.from_function(
            func=ip_trace_request,
            name="ip_trace_request",
            description="IP 溯源工具，用于查询指定攻击 IP 在攻击时间前 N 分钟的完整活动链路（包括登录、网络连接、攻击行为等）。参数：ip（必填，攻击 IP 地址）、start_time（必填，溯源起始时间，攻击时间前 N 分钟，格式 YYYY-MM-DD HH:MM:SS）、end_time（必填，溯源结束时间，即攻击时间，格式 YYYY-MM-DD HH:MM:SS）、gid（可选，设备组 ID）",
            args_schema=IpTraceInput,
        ),
]

tool_names = [tool.name for tool in tools]


# ========================================
# 工具到场景的映射
# ========================================
# 每个工具归属于一个场景，Agent 调用工具时自动匹配对应场景提示词
# 新增场景时，在此添加工具名到场景名的映射
TOOL_TO_SCENE = {
    "alert_rule_request": "security_alert",    # 告警规则 → 安全告警场景
    "brute_force_request": "brute_force",       # 暴力破解 → 暴力破解场景
    "account_security_monitor_request": "account_security",  # 账户安全监控 → 账户安全场景
    "network_attack_request": "network_attack",      # 网络攻击检测 → 网络攻击场景
    "system_security_request": "system_security",    # 系统安全监控 → 系统安全场景
    "free_query_request": "free_query",        # 自由 PPL 查询 → L2 自由场景
    "ip_trace_request": "ip_trace",            # IP 溯源 → IP 溯源场景
}
