# -*- coding: utf-8 -*-
"""
自由 PPL 查询工具（L2 层）
允许用户通过自然语言自由提问，由 LLM 生成 PPL 查询语句
支持 3 次重试机制，失败后引导用户使用 L1 场景化提问

【压缩配置】（与其他工具统一）
- 压缩触发阈值：>= 15 条 或 问题包含统计类关键词
- max_tokens: 2000
- 返回数据条数：5 条
- compressed_count = original_count（压缩不改变实际记录数）
- 始终生成统计摘要

【Redis 缓存】
- 缓存 TTL：300 秒（5 分钟）
"""
import json
import re
import asyncio
import contextvars
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
from tools.common_config import query_es, ES_AUTH_USER, ES_AUTH_PASSWORD, ES_HOST, ES_PORT
from tools.tool_base import ToolCacheManager, CompressionConfig, request_ctx
from tools.ppl_guard import enforce_gid_permission
from utils.log_compressor import LogCompressor, generate_summary_statistics, format_summary_text


def _run_async(coro):
    """
    安全地运行异步协程，处理 contextvars 传播问题
    """
    try:
        loop = asyncio.get_running_loop()
        return loop.run_until_complete(coro)
    except RuntimeError:
        pass
    
    loop = asyncio.new_event_loop()
    try:
        ctx = contextvars.copy_context()
        import sys
        if sys.version_info >= (3, 11):
            return loop.run_until_complete(coro, context=ctx)
        else:
            return loop.run_until_complete(coro)
    except Exception as e:
        raise e
    finally:
        loop.close()


# 压缩配置（与其他工具统一）
COMPRESSION_CONFIG = CompressionConfig(
    threshold=3,
    max_tokens=2000,
    max_return_data=3,
)

# 固定的数据源前缀
BASE_INDEX_PATTERN = "log_g*_fortigate_firewall-*"

# L1 场景引导问题示例（按场景分类）
L1_GUIDE_QUESTIONS = {
    "brute_force": "2026 年 4 月有哪些暴力破解记录",
    "account_security": "最近 24 小时的账户变更情况",
    "network_attack": "查询 2026 年 5 月 10 日的网络攻击记录",
    "system_security": "显示 2026 年 4 月 20 日的系统安全监控记录"
}


class FreeQueryInput(BaseModel):
    """自由 PPL 查询工具输入参数模型"""
    ppl_query: Optional[str] = Field(default=None, description="PPL 查询语句（可选，不传则由 LLM 生成）")
    user_problem: Optional[str] = Field(default="", description="用户原始问题描述，用于 LLM 生成 PPL")
    start_date: Optional[str] = Field(default=None, description="查询起始日期（格式：YYYY-MM-DD，默认当月 1 号）")
    end_date: Optional[str] = Field(default=None, description="查询结束日期（格式：YYYY-MM-DD，默认为今天）")
    gid: Optional[str] = Field(default=None, description="设备组 ID（可选）")


def _generate_date_range(start_date_str: str, end_date_str: str) -> tuple:
    """
    根据时间范围生成具体的索引列表
    
    Returns:
        tuple: (index_list_str, single_day_index)
    """
    try:
        start_dt = datetime.strptime(start_date_str, '%Y-%m-%d')
        end_dt = datetime.strptime(end_date_str, '%Y-%m-%d')
    except ValueError:
        return BASE_INDEX_PATTERN, None
    
    indices = []
    current_dt = start_dt
    while current_dt <= end_dt:
        index_name = f"log_g*_fortigate_firewall-{current_dt.strftime('%Y.%m.%d')}"
        indices.append(index_name)
        current_dt += timedelta(days=1)
    
    index_list = ",".join(indices) if indices else BASE_INDEX_PATTERN
    single_day = indices[0] if len(indices) == 1 else None
    return index_list, single_day


def _apply_index_date_pruning(ppl_query: str, start_date: str = None, end_date: str = None) -> str:
    """
    将普通索引 pattern 转换为带日期的 pattern，实现 ES 索引层面的时间剪枝
    
    从 PPL 中提取 @timestamp_cst 过滤条件，或使用传入的日期参数生成对应的索引列表
    """
    print("开始应用索引日期剪枝")
    
    ge_pattern = r"@timestamp_cst\s*>=\s*'(\d{4}-\d{2}-\d{2})(?:\s+(\d{2}:\d{2}:\d{2}))?'"
    le_pattern = r"@timestamp_cst\s*<=\s*'(\d{4}-\d{2}-\d{2})(?:\s+(\d{2}:\d{2}:\d{2}))?'"
    
    ge_match = re.search(ge_pattern, ppl_query)
    le_match = re.search(le_pattern, ppl_query)
    
    # 优先从 PPL 中提取日期，如果没有则使用传入参数
    start_date_str = ge_match.group(1) if ge_match else start_date
    end_date_str = le_match.group(1) if le_match else end_date
    
    if not start_date_str and not end_date_str:
        print("未找到时间过滤条件，跳过索引剪枝")
        return ppl_query
    
    # 生成索引列表
    if start_date_str and end_date_str:
        index_list, single_day = _generate_date_range(start_date_str, end_date_str)
        if single_day:
            print(f"单日查询，使用索引：{single_day}")
            index_list = single_day
        else:
            print(f"多日查询，使用具体索引列表：{index_list}")
    elif start_date_str:
        index_list = f"log_g*_fortigate_firewall-{start_date_str.replace('-', '.')}"
        print(f"单日查询，使用索引：{index_list}")
    elif end_date_str:
        index_list = f"log_g*_fortigate_firewall-{end_date_str.replace('-', '.')}"
        print(f"单日查询，使用索引：{index_list}")
    else:
        return ppl_query
    
    # 替换 source 中的索引 pattern
    if '`' in ppl_query:
        ppl_query = re.sub(
            r"search\s+source=`[^`]+`",
            f"search source=`{index_list}`",
            ppl_query,
            count=1
        )
    else:
        ppl_query = re.sub(
            r"(search\s+source=)[^\s|]+",
            rf"\1`{index_list}`",
            ppl_query,
            count=1
        )
    
    print(f"剪枝后 PPL: {ppl_query[:200]}...")
    return ppl_query


def generate_ppl_by_llm(
    user_problem: str,
    attempt: int = 1,
    previous_error: str = None,
    start_date: str = None,
    end_date: str = None
) -> str:
    """
    调用 LLM 生成 PPL 查询语句
    
    Returns:
        str: PPL 查询语句
    """
    print("开始调用 LLM 生成 PPL 查询")
    from langchain_community.chat_models import ChatOpenAI
    
    now = datetime.now()
    today = now.strftime('%Y-%m-%d')
    yesterday = (now - timedelta(days=1)).strftime('%Y-%m-%d')
    first_day_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    first_day_of_month_str = first_day_of_month.strftime('%Y-%m-%d')
    last_7_days_start = (now - timedelta(days=6)).strftime('%Y-%m-%d')
    last_30_days_start = (now - timedelta(days=29)).strftime('%Y-%m-%d')
    last_24_hours_start = (now - timedelta(hours=24)).strftime('%Y-%m-%d')
    
    actual_start_date = start_date if start_date else first_day_of_month_str
    actual_end_date = end_date if end_date else today
    
    default_date_filter = f"@timestamp_cst >= '{first_day_of_month_str} 00:00:00'"
    
    error_hint = ""
    if previous_error:
        error_hint = f"\n\n【上次查询错误】{previous_error[:300]}\n请分析错误原因，调整 PPL 查询语句。"
    
    system_prompt = f"""你是一位精通 PPL（PipeQL）查询语句的安全数据分析专家。
你的任务是根据用户的自然语言问题，生成正确的 PPL 查询语句。

【当前日期信息】重要！请根据以下日期解析用户问题中的时间表达：
- 今天/当前：{today}
- 昨天：{yesterday}
- 最近 24 小时开始日期：{last_24_hours_start}
- 最近 7 天开始日期：{last_7_days_start}
- 最近 30 天开始日期：{last_30_days_start}
- 当月 1 号：{first_day_of_month_str}
- 用户指定起始日期：{actual_start_date}
- 用户指定结束日期：{actual_end_date}

【数据源】
- 基础索引模式：`log_g*_fortigate_firewall-*`
- 【重要】为了实现索引层面的时间剪枝，必须根据用户问题中的时间范围，使用带日期的索引 pattern：
  - 单日查询：使用 `log_g*_fortigate_firewall-YYYY.MM.DD*`，例如 `log_g*_fortigate_firewall-2026.06.02*`
  - 多日查询：使用通配符范围，例如 `log_g*_fortigate_firewall-{{2026.06.01..2026.06.07}}*`
  - 当用户说"今天"且只查单日时，索引 pattern 应为 `log_g*_fortigate_firewall-{today}*` → 实际生成如 `log_g*_fortigate_firewall-2026.06.02*`
  - 示例：查询"今天"的登录记录 → `search source=`log_g*_fortigate_firewall-2026.06.02*``
  - 示例：查询"最近 7 天" → `search source=`log_g*_fortigate_firewall-{{2026.05.27..2026.06.02}}*``
- 注意：带日期的索引 pattern 可以实现 ES 层面的索引剪枝，大幅提升查询性能

【常见日志类型和字段】
- 登录日志：subtype='system', action='login', status='failed', reason, srcip, remip, user（仅登录/VPN日志有remip）
- VPN日志：subtype='vpn', msg='SSL user failed to logged in', srcip, remip, user
- 账户操作：action='Add'/'Delete'/'password reset', cfgpath='user.local', user
- IPS 告警：type='utm', subtype='ips', level='alert', attack, srcip, dstip, dstport, action, url（IPS日志没有remip字段！）
- 系统事件：subtype='system', logdesc='Device rebooted'/'Device shutdown'/'Device initialized'
- 通用字段：@timestamp_cst, srcip, dstip, user, action, msg, @gid, devname, subtype, logdesc, type, level, severity

【remip 字段注意事项】⚠️
- remip 字段**只存在于登录日志和VPN日志中**（subtype='system' 或 subtype='vpn'）
- IPS告警、网络攻击日志（type='utm', subtype='ips'）**没有 remip 字段**
- 如果用户查询的是IPS/攻击类日志，请使用 srcip 和 dstip，不要使用 remip
- 如果不确定日志类型，优先使用 srcip 字段

【PPL 语法】
1. 时间过滤：@timestamp_cst >= 'YYYY-MM-DD HH:MM:SS' and @timestamp_cst <= 'YYYY-MM-DD HH:MM:SS'
2. IP 过滤：srcip = 'x.x.x.x'（优先使用 srcip，仅在登录/VPN日志时使用 remip）
3. 用户过滤：user = 'username'
4. 设备组过滤：@gid = '设备组 ID'
5. 字段选择：fields field1, field2, ...
6. 排序：sort - @timestamp_cst（降序）
7. 聚合：stats count() as cnt by field1, field2
8. 限制条数：head N（限制返回 N 条记录）
9. 条件过滤：| where 条件表达式（使用 and/or 连接）

【PPL 语法示例】
- 单日登录登出查询：
  search source=`log_g*_fortigate_firewall-2026.06.08*`
  | where @timestamp_cst >= '2026-06-08 00:00:00' and @timestamp_cst <= '2026-06-08 23:59:59'
  | where @gid = '12345'
  | where (action = 'login' or action = 'logout')
  | fields @timestamp_cst, action, user, srcip
  | sort - @timestamp_cst
  | head 100

- 统计查询：
  search source=`log_g*_fortigate_firewall-2026.06.08*`
  | where @timestamp_cst >= '2026-06-08 00:00:00' and @timestamp_cst <= '2026-06-08 23:59:59'
  | where @gid = '12345'
  | where (action = 'login' or action = 'logout')
  | stats count() as cnt
  | head 100

【重要语法规范】
1. **必须使用 `| where` 进行条件过滤**，不能直接在 search 后写条件
2. **多个条件使用 `and`/`or` 连接**，放在 `| where` 子句中
3. **字符串值必须用单引号包裹**，如 'login'、'12345'
4. **字段名不能有空格**，如 `@timestamp_cst`、`@gid`
5. **比较运算符**：=（等于）、!=（不等于）、>=（大于等于）、<=（小于等于）
6. **逻辑运算符优先级**：使用括号明确优先级，如 `(action = 'login' or action = 'logout')`

【时间解析规则】
- "今天" → @timestamp_cst >= '{today} 00:00:00'
- "昨天" → @timestamp_cst >= '{yesterday} 00:00:00'
- "最近 24 小时" → @timestamp_cst >= '{last_24_hours_start} 00:00:00'
- "最近 7 天" → @timestamp_cst >= '{last_7_days_start} 00:00:00'
- "最近 30 天" → @timestamp_cst >= '{last_30_days_start} 00:00:00'
- "本月" → @timestamp_cst >= '{first_day_of_month_str} 00:00:00'
- "2026 年" → @timestamp_cst >= '2026-01-01 00:00:00'
- "2026 年 4 月" → @timestamp_cst >= '2026-04-01 00:00:00'
- "2026 年 4 月 20 日" → @timestamp_cst >= '2026-04-20 00:00:00'

【安全限制 - 必须遵守】
1. **日期限制**：如果用户问题中没有明确的时间范围，必须添加默认时间过滤：
   - 默认查询从当月 1 号开始：`| where {default_date_filter}`
   - 如果用户已指定时间（如"今天"、"最近 7 天"、具体日期），使用用户指定的时间范围
   - 如果用户传入了 start_date/end_date 参数，优先使用这些参数
2. **返回条数限制**：必须在 PPL 末尾添加 `| head 100` 限制最大返回条数
3. **防止全表扫描**：不能生成没有 where 条件的纯全表查询

【输出要求】
- 只返回 PPL 查询语句本身，不要任何解释
- PPL 必须以 `search source=`log_g*_fortigate_firewall-*`` 开头
- 必须包含时间过滤条件（用户未指定时使用默认当月 1 号）
- 必须包含 `| head 100` 限制返回条数
{error_hint}
"""
    
    try:
        model = ChatOpenAI(
            streaming=False,
            verbose=False,
            openai_api_key='not empty',
            openai_api_base='http://10.180.158.20:18080/v1',
            model_name='Qwen/Qwen3-32B',
            temperature=0.1,
            max_tokens=2000
        )
        prompt_text = f"{system_prompt}\n\n用户问题：{user_problem}"
        print(f"[FREE_QUERY] [LLM] 请求长度: {len(prompt_text)} 字符")
        response = model.invoke(prompt_text)
        raw_content = response.content.strip()
        print(f"[FREE_QUERY] [LLM] 原始返回长度: {len(raw_content)} 字符")
        print(f"[FREE_QUERY] [LLM] 原始返回预览: {raw_content[:300] if raw_content else '(空)'}")
        
        # 提取代码块中的 PPL
        if "```" in raw_content:
            match = re.search(r'```(?:ppl)?\n?(.*?)\n?```', raw_content, re.DOTALL)
            if match:
                raw_content = match.group(1).strip()
        
        # 移除思考标签（）
        ppl_query = re.sub(r'<think>.*?</think>', '', raw_content, flags=re.DOTALL | re.IGNORECASE)
        # 如果还有未闭合的标签，也清理掉
        ppl_query = re.sub(r'<think>.*', '', ppl_query, flags=re.DOTALL)
        ppl_query = ppl_query.strip()
        
        # 【关键修复】LLM 返回空 PPL 时，使用默认查询回退
        if not ppl_query:
            print(f"[FREE_QUERY] [WARN] LLM 返回了空 PPL，使用默认查询回退")
            ppl_query = f"search source=`{BASE_INDEX_PATTERN}`\n| fields @timestamp_cst, msg, subtype, action\n| head 100"
        
        return ppl_query
    
    except Exception as e:
        print(f"LLM 生成 PPL 失败：{e}")
        return f"search source=`{BASE_INDEX_PATTERN}`\n| fields @timestamp_cst, msg, subtype, action\n| head 100"


def _normalize_ppl(ppl_query: str) -> str:
    """
    规范化 PPL 查询语句
    - 确保以 search source= 开头
    - 确保有时间过滤条件
    - 确保有 head 限制
    """
    # 【防御性检查】空查询直接返回默认查询
    if not ppl_query or not ppl_query.strip():
        print(f"[FREE_QUERY] [WARN] _normalize_ppl 收到空 PPL，使用默认查询")
        return f"search source=`{BASE_INDEX_PATTERN}`\n| fields @timestamp_cst, msg, subtype, action\n| head 100"
    
    # 确保以 search source= 开头
    if not ppl_query.startswith("search source="):
        ppl_query = f"search source=`{BASE_INDEX_PATTERN}`\n{ppl_query}"
    
    # 确保有时间过滤
    has_time_filter = (
        "@timestamp_cst >=" in ppl_query or 
        "@timestamp_cst <=" in ppl_query or
        "@timestamp_cst >" in ppl_query or
        "@timestamp_cst <" in ppl_query
    )
    
    if not has_time_filter:
        now = datetime.now()
        first_day_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        default_date_str = first_day_of_month.strftime('%Y-%m-%d 00:00:00')
        if "| where" not in ppl_query:
            last_pipe_idx = ppl_query.rfind("|")
            if last_pipe_idx != -1:
                ppl_query = (
                    ppl_query[:last_pipe_idx].rstrip() + 
                    f"\n| where @timestamp_cst >= '{default_date_str}'" + 
                    ppl_query[last_pipe_idx:]
                )
            else:
                ppl_query += f"\n| where @timestamp_cst >= '{default_date_str}'"
    
    # 确保有 head 限制
    if "| head" not in ppl_query and "|head" not in ppl_query:
        ppl_query += "\n| head 100"
    
    return ppl_query


def _build_compression_info(
    data: list,
    count: int,
    user_problem: str,
    compression_config: CompressionConfig
) -> tuple:
    """
    构建压缩信息（与其他工具统一）
    
    Returns:
        tuple: (compression_info, summary_text)
    """
    compression_info = {"compressed": False, "original_count": count}
    summary_text = ""
    
    # 始终生成统计摘要
    if data:
        summary_stats = generate_summary_statistics(data)
        summary_text = format_summary_text(summary_stats)
        print(f"[LogCompressor] 已生成统计摘要：原始记录{count}条，{summary_stats.get('unique_src_ip_count', 0)}个源 IP")
    
    # 判断是否需要压缩
    needs_compression = count >= compression_config.threshold or any(
        kw in user_problem for kw in compression_config.aggregate_keywords
    )
    
    if needs_compression and data:
        print(f"\n=== 触发日志压缩 ===")
        print(f"原始数据量：{count} 条")
        
        compressor = LogCompressor()
        compressed_text = compressor.compress_for_llm(
            logs=data,
            question=user_problem,
            max_tokens=compression_config.max_tokens,
            summary_text=summary_text
        )
        
        print(f"压缩后 Token 数：{compressor.estimate_tokens(compressed_text)}")
        
        compression_info = {
            "compressed": True,
            "original_count": count,
            "compressed_count": count,
            "compressed_text": compressed_text,
            "summary_text": summary_text
        }
    else:
        compression_info["summary_text"] = summary_text
    
    return compression_info, summary_text


def free_query_request(
    ppl_query: str = None,
    user_problem: str = "",
    start_date: str = None,
    end_date: str = None,
    gid: str = None,
) -> str:
    """
    自由 PPL 查询入口函数（L2 层）
    
    功能：
    1. 如果提供了 ppl_query，直接执行查询
    2. 如果没有提供 ppl_query，调用 LLM 自动生成
    3. 支持最多 3 次重试（如果查询失败）
    4. 3 次失败后，引导用户使用 L1 场景化提问
    
    Args:
        ppl_query: PPL 查询语句（可选，不传则由 LLM 自动生成）
        user_problem: 用户原始问题描述（必填）
        start_date: 查询起始日期（格式：YYYY-MM-DD，默认当月 1 号）
        end_date: 查询结束日期（格式：YYYY-MM-DD，默认为今天）
    
    Returns:
        str: JSON 格式的查询结果
    """
    auth_user = ES_AUTH_USER
    auth_password = ES_AUTH_PASSWORD
    
    # 验证用户问题
    if not user_problem:
        print(f"[FREE_QUERY] 错误：用户问题为空")
        return json.dumps({
            "error": "用户问题不能为空",
            "suggestion": "请描述您想查询的日志内容，例如：'今天有哪些登录失败记录'"
        }, ensure_ascii=False)
    
    # 【数据权限】从 contextvars 获取 gid_scope：入口校验 gid 参数 + 缓存按账号隔离
    from tools.tool_base import request_ctx
    from tools.ppl_guard import is_gid_empty, check_gid_allowed, build_denied_result
    gid_scope = request_ctx.get()
    allowed_gids = gid_scope.get("allowed_gids") if gid_scope else None
    if allowed_gids is not None and not is_gid_empty(gid) and not check_gid_allowed(gid, allowed_gids):
        print(f"[FREE_QUERY] [GID_GUARD] 越权拦截：gid={gid}，白名单：{allowed_gids}")
        return build_denied_result(gid, allowed_gids)

    # 【缓存检查】使用统一的 ToolCacheManager（login_account 加入 key，防止不同账号互相命中缓存）
    import hashlib
    login_account = ""
    allowed_gids_hash = ""
    if gid_scope:
        login_account = gid_scope.get("login_account", "")
        if allowed_gids:
            allowed_gids_hash = hashlib.md5(json.dumps(sorted(allowed_gids), sort_keys=True).encode()).hexdigest()[:8]

    cache_params = {
        "user_problem": user_problem,
        "ppl_query": ppl_query,
        "start_date": start_date,
        "end_date": end_date,
        "login_account": login_account,  # 按账号隔离缓存
        "allowed_gids_hash": allowed_gids_hash,  # 按权限范围隔离缓存
    }
    
    try:
        cached_data = _run_async(ToolCacheManager.get_cached_result("free_query", cache_params))
        
        if cached_data:
            steps = [{
                "step": 1,
                "title": "缓存命中",
                "detail": "相同查询已从缓存返回，无需重复查询 ES"
            }]
            result = {
                "steps": steps,
                "from_cache": True,
                **cached_data
            }
            return json.dumps(result, ensure_ascii=False)
    except Exception as e:
        print(f"缓存检查失败：{e}")
    
    print(f"\n{'='*60}")
    print(f"[FREE_QUERY] 开始处理自由 PPL 查询")
    print(f"[FREE_QUERY] 用户问题：{user_problem[:200] if user_problem else 'N/A'}")
    print(f"{'='*60}")
    
    # 重试机制：最多 3 次
    max_attempts = 3
    last_error = None
    attempt_steps = []
    
    for attempt in range(1, max_attempts + 1):
        print(f"\n--- 第 {attempt} 次尝试 ---")
        
        try:
            # 第 1 次尝试：使用传入的 ppl_query 或调用 LLM 生成
            if attempt == 1 and ppl_query:
                current_ppl = ppl_query.strip()
                ppl_source = "用户传入"
            else:
                current_ppl = generate_ppl_by_llm(
                    user_problem, attempt, last_error, start_date, end_date
                )
                ppl_source = "LLM 生成"
            
            # 规范化 PPL
            current_ppl = _normalize_ppl(current_ppl)

            # 应用索引日期剪枝（必须在权限校验之前：剪枝会把 source 重写回
            # log_g* 通配符形式，若先收窄索引会被剪枝覆盖掉）
            current_ppl = _apply_index_date_pruning(current_ppl, start_date, end_date)

            # 【数据权限】L2 层权限校验：从 contextvars 获取 gid_scope，
            # 在 PPL 送入 query_es 之前做 提取 -> 校验 -> 注入 -> 索引收窄
            from tools.tool_base import request_ctx
            gid_scope = request_ctx.get()
            if gid_scope:
                allowed_gids = gid_scope.get("allowed_gids") if gid_scope else None
                if allowed_gids is not None:
                    current_ppl, denied_msg = enforce_gid_permission(current_ppl, allowed_gids,
                        host=ES_HOST, port=ES_PORT, user=ES_AUTH_USER, password=ES_AUTH_PASSWORD)
                    if denied_msg:
                        # 区分越权拦截和索引不存在两种情况
                        from tools.ppl_guard import build_index_invalid_result
                        if "索引不存在" in denied_msg:
                            # 索引不存在 -> 返回 early-stop 结果
                            print(f"[FREE_QUERY] [GID_GUARD] 索引探测拦截：{denied_msg}")
                            denied_result = build_index_invalid_result(None, allowed_gids)
                            return json.dumps(denied_result, ensure_ascii=False)
                        else:
                            # 越权：返回固定模板提示 + suggestion（agent_chat 直推 final_answer）
                            denied_result = {
                                "__agent_stop__": True,
                                "steps": [
                                    {
                                        "step": 1,
                                        "title": f"尝试 {attempt}: PPL 生成与权限校验",
                                        "detail": f"PPL 来源：{ppl_source}",
                                        "is_code": False
                                    },
                                    {
                                        "step": 2,
                                        "title": "权限校验拦截",
                                        "detail": denied_msg,
                                        "is_code": False
                                    }
                                ],
                                "http_status": 403,
                                "error": denied_msg,
                                "suggestion": "",  # 置为空，避免 agent_chat.py 拼接 error + suggestion 导致重复
                                "count": 0,
                                "data": []
                            }
                            return json.dumps(denied_result, ensure_ascii=False)

            print(f"PPL 来源：{ppl_source}")
            print(f"PPL 查询：{current_ppl}")
            
            attempt_steps.append({
                "step": attempt,
                "title": f"尝试 {attempt}: 生成并执行 PPL",
                "detail": f"PPL 来源：{ppl_source}",
                "is_code": False
            })
            
            attempt_steps.append({
                "step": attempt,
                "title": f"PPL 查询语句",
                "detail": current_ppl,
                "is_code": True
            })
            
            # 执行 ES 查询
            result = query_es(current_ppl, auth_user, auth_password)
            
            ppl_query_str = result.get("ppl_query", current_ppl)
            error_msg = result.get("error", "")
            http_status = result.get("http_status", 0)
            data = result.get("data", [])
            count = result.get("count", 0)
            
            attempt_steps.append({
                "step": attempt,
                "title": f"查询结果",
                "detail": f"HTTP 状态码：{http_status}" + (f", 错误：{error_msg}" if error_msg else f", 返回 {count} 条记录"),
                "is_code": False
            })
            
            # 检查是否成功
            if http_status == 200 and not error_msg:
                # 【统一】使用与其他工具一致的压缩逻辑
                compression_info, summary_text = _build_compression_info(
                    data, count, user_problem, COMPRESSION_CONFIG
                )
                
                # 构建返回数据（只保留前 N 条，与其他工具统一为 5 条）
                final_data = data[:COMPRESSION_CONFIG.max_return_data]
                final_count = count
                
                # 步骤 4：根据是否压缩，显示不同的信息
                if compression_info.get("compressed"):
                    result_detail = f"原始记录 {count} 条，压缩后 {compression_info.get('compressed_count', 0)} 条"
                else:
                    result_detail = f"共查询到 {count} 条记录"
                
                final_steps = [
                    {
                        "step": 1,
                        "title": "用户问题",
                        "detail": user_problem
                    },
                    {
                        "step": 2,
                        "title": "生成 PPL 查询",
                        "detail": ppl_query_str,
                        "is_code": True
                    },
                    {
                        "step": 3,
                        "title": "执行 API 查询",
                        "detail": f"HTTP 状态码：{http_status}"
                    },
                    {
                        "step": 4,
                        "title": "返回结果",
                        "detail": result_detail
                    }
                ]
                
                final_result = {
                    "steps": final_steps,
                    "ppl_query": ppl_query_str,
                    "http_status": http_status,
                    "count": final_count,
                    "data": final_data,
                    "compression": compression_info,
                    "attempt": attempt
                }
                
                # 【缓存保存】使用统一的 ToolCacheManager
                cache_data = {
                    "steps": final_steps,
                    "ppl_query": ppl_query_str,
                    "http_status": http_status,
                    "count": final_count,
                    "data": final_data,
                    "compression": compression_info,
                    "attempt": attempt
                }
                try:
                    _run_async(ToolCacheManager.save_cached_result("free_query", cache_params, cache_data, ttl=300))
                    print(f"\n=== 缓存已保存 ===")
                except Exception as e:
                    print(f"缓存保存失败：{e}")
                
                return json.dumps(final_result, ensure_ascii=False)
            
            else:
                # 查询失败，记录错误，继续重试
                last_error = error_msg or f"HTTP {http_status}"
                print(f"查询失败：{last_error}")
                
        except Exception as e:
            last_error = str(e)
            print(f"异常：{last_error}")
            attempt_steps.append({
                "step": attempt,
                "title": f"尝试 {attempt}: 异常",
                "detail": str(e),
                "is_code": False
            })
    
    # 3 次尝试都失败了，返回引导信息
    print("\n=== 3 次尝试均失败，引导用户使用 L1 场景 ===")
    
    guide_steps = attempt_steps[-6:] if len(attempt_steps) >= 6 else attempt_steps
    
    guide_steps.append({
        "step": len(guide_steps) + 1,
        "title": "建议使用 L1 场景化提问",
        "detail": "由于自由查询生成 PPL 失败，建议您使用以下 L1 场景化提问方式：",
        "is_code": False
    })
    
    failure_text = (
        f"抱歉，自由查询工具 PPL 生成有误，当前无法完成您的查询。"
        f"\n\n" 
        f"**可能原因**："
        f"\n- 当前时段系统负载较高或 ES 集群暂时不可用"
        f"\n- 查询条件可能需要进一步明确"
        f"\n\n"
        f"**您可以尝试以下方式**："
        f"\n\n"
        f"1. **使用场景化提问**"
        f"\n   示例："
        f"\n   - `{L1_GUIDE_QUESTIONS['brute_force']}`"
        f"\n   - `{L1_GUIDE_QUESTIONS['account_security']}`"
        f"\n   - `{L1_GUIDE_QUESTIONS['network_attack']}`"
        f"\n   - `{L1_GUIDE_QUESTIONS['system_security']}`"
        f"\n\n"
        f"2. **稍后再试** - 系统可能暂时繁忙"
        f"\n\n"
        f"3. **简化查询条件** - 减少时间范围或过滤条件"
    )
    
    final_result = {
        "steps": guide_steps,
        "http_status": 500,
        "error": "PPL 生成失败，已重试 3 次",
        "suggestion": failure_text,
        "count": 0,
        "data": []
    }
    return json.dumps(final_result, ensure_ascii=False)