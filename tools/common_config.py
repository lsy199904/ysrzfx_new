"""
公共配置模块
包含 ES 连接配置、SSL 配置和公共工具函数

【统一认证配置】
所有工具的 ES 认证信息都从这里获取，不要在各工具文件中硬编码
"""
import ssl
import json
import re
import base64
import http.client
import pandas as pd
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List

# 导入电路断路器
from utils.circuit_breaker import es_circuit_breaker
from tools.ppl_guard import (
    enforce_gid_permission,
    is_gid_empty,
    normalize_allowed_gids,
    restrict_source_indices,
    validate_authorized_ppl_sources,
)
from tools.index_config import INDEX_SOURCE_PATTERN
from config import (
    ES_AUTH_PASSWORD,
    ES_AUTH_USER,
    ES_HOST,
    ES_PORT,
    ES_SCHEME,
    ES_VERIFY_SSL,
    require_config,
)

# 兼容旧代码的别名
OS_USER = ES_AUTH_USER
OS_PASSWORD = ES_AUTH_PASSWORD


def normalize_time_param(param_value: str, user_problem: str = "", is_start_time: bool = True) -> str:
    """
    【公共工具】统一的时间参数解析函数

    功能：
    1. 如果传入的参数已经是标准格式（YYYY-MM-DD HH:MM:SS），直接返回
    2. 如果参数为空，从 user_problem 中解析
    3. 如果参数不是标准格式，尝试用 parse_time_string 解析
    
    Args:
        param_value: 传入的时间参数值
        user_problem: 用户问题描述（用于 fallback 解析）
        is_start_time: 是否为开始时间（True 返回 00:00:00，False 返回 23:59:59）
    
    Returns:
        str: 标准格式的时间字符串（YYYY-MM-DD HH:MM:SS），无法解析时返回 None
    """
    def is_standard_time_format(time_str: str) -> bool:
        """检查时间字符串是否已经是标准格式 YYYY-MM-DD HH:MM:SS"""
        if not time_str:
            return False
        try:
            datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
            return True
        except ValueError:
            return False
    
    # 情况 1：参数为空，从 user_problem 解析
    if not param_value:
        return parse_time_string(user_problem, is_start_time=is_start_time)
    
    # 情况 2：参数已经是标准格式，直接返回
    if is_standard_time_format(param_value):
        return param_value
    
    # 情况 3：参数不是标准格式，尝试解析
    parsed = parse_time_string(param_value, is_start_time=is_start_time)
    return parsed if parsed else param_value

def _build_ssl_context():
    if ES_VERIFY_SSL:
        return ssl.create_default_context()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_default_certs()
    return context


def extract_ip_from_text(text: str) -> Optional[str]:
    """从文本中提取 IP 地址"""
    print("开始提取IP地址")
    if not text:
        return None
    ip_pattern = r'((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'
    match = re.search(ip_pattern, text)
    return match.group(1) if match else None


def extract_username_from_text(text: str) -> Optional[str]:
    """从文本中提取用户名"""
    print("开始提取用户名")
    if not text:
        return None
    patterns = [
        r'用户\s*([a-zA-Z0-9_]+)',
        r'用户名为\s*([a-zA-Z0-9_]+)',
        r'查询\s*([a-zA-Z0-9_]+)\s*的',
        r'username\s*([a-zA-Z0-9_]+)',
        r'用户[:：]\s*([a-zA-Z0-9_]+)',
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def extract_gid_from_text(text: str) -> Optional[str]:
    """从用户问题中提取字母数字形式的 gid。"""
    if not text:
        return None
    match = re.search(
        r"(?:gid|用户组|设备组)\s*(?:为|是|编号为|=|:|：)?\s*([A-Za-z0-9]+)",
        text,
        re.IGNORECASE,
    )
    return match.group(1) if match else None


def parse_time_string(time_str: str, is_start_time: bool = True) -> Optional[str]:
    """
    解析时间字符串，返回标准日期格式 YYYY-MM-DD HH:MM:SS（东八区时间）
    
    Args:
        time_str: 时间字符串
        is_start_time: 是否为开始时间（True 返回 00:00:00，False 返回 23:59:59）
                       对于相对时间表达（如"最近 24 小时"），返回精确时间
    
    Returns:
        Optional[str]: 标准日期格式字符串，无法解析时返回 None
    """
    print("开始解析时间字符串")
    if not time_str:
        return None
    
    # 【关键修复】使用带时区的 datetime 对象，确保获取正确的东八区时间
    # 系统时区可能未正确设置，需要手动处理时区
    from datetime import timezone, timedelta as td
    
    # 获取东八区时区对象
    cst_tz = timezone(td(hours=8))
    now = datetime.now(cst_tz)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    time_str = time_str.strip()
    time_str_lower = time_str.lower()
    
    # 先检查中文时间表达（不转小写，保持中文字符原样）
    # 【重要】按长度从长到短匹配，避免短字符串先匹配
    # 【关键修复】先匹配精确表达，再匹配正则，避免"最近 24 小时"被"近\s*(\d+)\s*小时"提前匹配
    
    # 1. 精确匹配"最近 24 小时" - 返回精确到小时的时间
    if "最近 24 小时" in time_str or "近 24 小时" in time_str or "24 小时" in time_str:
        if is_start_time:
            result_dt = now - timedelta(hours=24)
            return result_dt.strftime("%Y-%m-%d %H:%M:%S")
        else:
            return now.strftime("%Y-%m-%d %H:%M:%S")
    
    # 2. 解析"最近 N 小时"格式（通用匹配）- 返回精确时间
    recent_hour_match = re.search(r'近\s*(\d+)\s*小时', time_str)
    if recent_hour_match:
        hours = int(recent_hour_match.group(1))
        if is_start_time:
            result_dt = now - timedelta(hours=hours)
            return result_dt.strftime("%Y-%m-%d %H:%M:%S")
        else:
            return now.strftime("%Y-%m-%d %H:%M:%S")
    
    # 3. "今天" - 按天处理，开始时间返回 00:00:00，结束时间返回 23:59:59
    if "今天" in time_str or "today" in time_str_lower or time_str_lower == "now" or "当前" in time_str:
        if is_start_time:
            return today_start.strftime("%Y-%m-%d 00:00:00")
        else:
            return today_start.replace(hour=23, minute=59, second=59).strftime("%Y-%m-%d 23:59:59")
    
    # 4. "近 7 天/最近 7 天" - 按天处理，开始时间返回 00:00:00，结束时间返回 23:59:59
    if "近 7 天" in time_str or "近 7 天" in time_str or "最近 7 天" in time_str or "最近 7 天" in time_str or "last 7 days" in time_str_lower:
        if is_start_time:
            return (today_start - timedelta(days=6)).strftime("%Y-%m-%d 00:00:00")
        else:
            return today_start.replace(hour=23, minute=59, second=59).strftime("%Y-%m-%d 23:59:59")
    
    # 5. "近 30 天/最近 30 天" - 按天处理，开始时间返回 00:00:00，结束时间返回 23:59:59
    if "近 30 天" in time_str or "近 30 天" in time_str or "最近 30 天" in time_str or "最近 30 天" in time_str:
        if is_start_time:
            return (today_start - timedelta(days=29)).strftime("%Y-%m-%d 00:00:00")
        else:
            return today_start.replace(hour=23, minute=59, second=59).strftime("%Y-%m-%d 23:59:59")
    
    # 【关键修复】先匹配带时间点的日期格式，再匹配纯日期格式
    # 解析"YYYY 年 MM 月 DD 日 X 点"格式（带时间点）- 优先匹配
    # 使用 [点时] 字符类（不要使用 (点 | 时），中间的空格会导致匹配失败）
    # 【注意】使用半角问号？而不是全角问号？
    # 【关键】使用非捕获组 (?:...) 来正确匹配可选的分钟部分
    # 【新增】支持"早上/上午/下午/晚上/凌晨"等时间修饰词
    # 【新增】支持时间范围表达（如"8 点 -13 点"、"8 点到 13 点"）
    time_modifiers = ['早上', '上午', '下午', '晚上', '凌晨', '半夜', '清晨', '中午', '傍晚', '午夜']
    modifier_pattern = '|'.join(time_modifiers)
    
    # 【新增】先检查时间范围表达（如"8 点 -13 点"、"8 点到 13 点"、"8 点~22 点"）
    # 匹配"YYYY 年 MM 月 DD 日 X 点-Y 点"或"YYYY 年 MM 月 DD 日 X 点到 Y 点"或"YYYY 年 MM 月 DD 日 X 点~Y 点"格式
    # 分隔符支持：-、到、至、~
    time_range_match = re.search(
        rf'(\d{{4}})\s*年\s*(\d{{1,2}})\s*月\s*(\d{{1,2}})\s*日\s*(?:{modifier_pattern})?\s*(\d{{1,2}})\s*[点时]\s*[-到至~]\s*(\d{{1,2}})\s*[点时]?',
        time_str
    )
    if time_range_match:
        year, month, day = time_range_match.group(1), time_range_match.group(2), time_range_match.group(3)
        start_hour = int(time_range_match.group(4))
        end_hour = int(time_range_match.group(5))
        
        # 检查是否有时间修饰词（只影响开始时间）
        time_modifier = None
        modifier_match = re.search(rf'日\s*({modifier_pattern})', time_str)
        if modifier_match:
            time_modifier = modifier_match.group(1)
        
        # 根据时间修饰词调整开始时间的小时数
        if time_modifier:
            if time_modifier in ['下午', '晚上', '傍晚'] and start_hour < 12:
                start_hour += 12
            elif time_modifier in ['凌晨', '半夜', '午夜', '清晨'] and start_hour >= 12:
                start_hour -= 12
            elif time_modifier == '中午' and start_hour < 12:
                start_hour = 12
        
        # 结束时间处理：如果结束时间小于开始时间，可能是下午/晚上时间
        # 例如"早上 8 点 -13 点"，13 点已经是 24 小时制，不需要转换
        # 例如"下午 2 点 -5 点"，5 点需要转换为 17 点
        if end_hour < 12 and start_hour >= 12:
            # 开始时间是下午/晚上，结束时间可能也是下午/晚上（省略了修饰词）
            end_hour += 12
        elif end_hour < start_hour and end_hour < 12:
            # 结束时间小于开始时间且小于 12，可能是跨中午的情况
            # 例如"上午 10 点 -2 点"，2 点应该是 14 点
            if start_hour < 12:
                end_hour += 12
        
        if is_start_time:
            return f"{int(year):04d}-{int(month):02d}-{int(day):02d} {start_hour:02d}:00:00"
        else:
            return f"{int(year):04d}-{int(month):02d}-{int(day):02d} {end_hour:02d}:59:59"
    
    # 检查带分钟的时间范围（如"8 点 30 分 -13 点 30 分"）
    time_range_minute_match = re.search(
        rf'(\d{{4}})\s*年\s*(\d{{1,2}})\s*月\s*(\d{{1,2}})\s*日\s*(?:{modifier_pattern})?\s*(\d{{1,2}})\s*[点时]\s*(\d{{1,2}})\s*分\s*[-到至]\s*(\d{{1,2}})\s*[点时]?\s*(\d{{1,2}})?\s*分?',
        time_str
    )
    if time_range_minute_match:
        year, month, day = time_range_minute_match.group(1), time_range_minute_match.group(2), time_range_minute_match.group(3)
        start_hour = int(time_range_minute_match.group(4))
        start_minute = int(time_range_minute_match.group(5))
        end_hour = int(time_range_minute_match.group(6))
        end_minute = int(time_range_minute_match.group(7)) if time_range_minute_match.group(7) else 59
        
        if is_start_time:
            return f"{int(year):04d}-{int(month):02d}-{int(day):02d} {start_hour:02d}:{start_minute:02d}:00"
        else:
            return f"{int(year):04d}-{int(month):02d}-{int(day):02d} {end_hour:02d}:{end_minute:02d}:59"
    
    date_time_match = re.search(
        rf'(\d{{4}})\s*年\s*(\d{{1,2}})\s*月\s*(\d{{1,2}})\s*日\s*(?:{modifier_pattern})?\s*(\d{{1,2}})\s*[点时](?:\s*(\d{{1,2}})\s*分)?',
        time_str
    )
    if date_time_match:
        year, month, day = date_time_match.group(1), date_time_match.group(2), date_time_match.group(3)
        time_modifier = None
        # 检查是否有时间修饰词 - 使用更灵活的正则匹配
        modifier_match = re.search(rf'日\s*({modifier_pattern})', time_str)
        if modifier_match:
            time_modifier = modifier_match.group(1)
        
        hour = int(date_time_match.group(4))
        # group(5) 是分钟部分，可能为 None
        minute_str = date_time_match.group(5)
        minute = int(minute_str) if minute_str else 0
        
        # 【新增】根据时间修饰词调整小时数（12 小时制转 24 小时制）
        if time_modifier:
            if time_modifier in ['下午', '晚上', '傍晚'] and hour < 12:
                hour += 12
            elif time_modifier in ['凌晨', '半夜', '午夜', '清晨'] and hour >= 12:
                hour -= 12
            # 中午特殊处理：如果中午 12 点以下，调整为 12 点
            elif time_modifier == '中午' and hour < 12:
                hour = 12
        
        if is_start_time:
            return f"{int(year):04d}-{int(month):02d}-{int(day):02d} {hour:02d}:{minute:02d}:00"
        else:
            # 如果指定了分钟，结束时间为该分钟的最后 1 秒；否则为该小时的最后 1 秒
            if minute_str:
                return f"{int(year):04d}-{int(month):02d}-{int(day):02d} {hour:02d}:{minute:02d}:59"
            else:
                return f"{int(year):04d}-{int(month):02d}-{int(day):02d} {hour:02d}:59:59"
    
    # 匹配模式：2026-05-10 10 点、2026/05/10 10 点（带时间点）
    # 【关键】使用非捕获组 (?:...) 来正确匹配可选的分钟部分
    date_time_match2 = re.search(
        r'(\d{4})[-/](\d{1,2})[-/](\d{1,2})\s*(\d{1,2})\s*[点时](?:\s*(\d{1,2})\s*分)?',
        time_str
    )
    if date_time_match2:
        year, month, day = date_time_match2.group(1), date_time_match2.group(2), date_time_match2.group(3)
        hour = int(date_time_match2.group(4))
        # group(5) 是分钟部分，可能为 None
        minute_str = date_time_match2.group(5)
        minute = int(minute_str) if minute_str else 0
        
        if is_start_time:
            return f"{int(year):04d}-{int(month):02d}-{int(day):02d} {hour:02d}:{minute:02d}:00"
        else:
            # 如果指定了分钟，结束时间为该分钟的最后 1 秒；否则为该小时的最后 1 秒
            if minute_str:
                return f"{int(year):04d}-{int(month):02d}-{int(day):02d} {hour:02d}:{minute:02d}:59"
            else:
                return f"{int(year):04d}-{int(month):02d}-{int(day):02d} {hour:02d}:59:59"
    
    # 解析"XXXX 年"格式，返回该年 1 月 1 日（开始时间）或 12 月 31 日 23:59:59（结束时间）
    year_match = re.search(r'(\d{4})\s*年$', time_str)
    if year_match:
        year = int(year_match.group(1))
        if is_start_time:
            return f"{year}-01-01 00:00:00"
        else:
            return f"{year}-12-31 23:59:59"
    
    # 解析"XXXX 年 XX 月"格式
    year_month_match = re.search(r'(\d{4})\s*年\s*(\d{1,2})\s*月$', time_str)
    if year_month_match:
        year, month = year_month_match.groups()
        if is_start_time:
            return f"{int(year):04d}-{int(month):02d}-01 00:00:00"
        else:
            # 计算该月的最后一天
            if int(month) == 12:
                return f"{int(year):04d}-12-31 23:59:59"
            else:
                # 下个月 1 日减 1 天
                import calendar
                _, last_day = calendar.monthrange(int(year), int(month))
                return f"{int(year):04d}-{int(month):02d}-{last_day:02d} 23:59:59"
    
    # 解析标准日期格式（带时分秒）
    for fmt in ['%Y-%m-%d %H:%M:%S', '%Y/%m/%d %H:%M:%S']:
        try:
            dt = datetime.strptime(time_str.replace("'", ""), fmt)
            if is_start_time:
                return dt.replace(hour=0, minute=0, second=0).strftime("%Y-%m-%d %H:%M:%S")
            else:
                return dt.replace(hour=23, minute=59, second=59).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    
    # 解析"YYYY-MM-DD"或"YYYY/MM/DD"或"YYYY 年 MM 月 DD 日"格式（纯日期）
    date_match = re.search(r'(\d{4})[-/](\d{1,2})[-/](\d{1,2})', time_str)
    if date_match:
        year, month, day = date_match.groups()
        if is_start_time:
            return f"{int(year):04d}-{int(month):02d}-{int(day):02d} 00:00:00"
        else:
            return f"{int(year):04d}-{int(month):02d}-{int(day):02d} 23:59:59"
    
    # 解析"YYYY 年 MM 月 DD 日"格式（纯日期，不带时间点）
    year_month_day_match = re.search(r'(\d{4})\s*年\s*(\d{1,2})\s*月\s*(\d{1,2})\s*日\s*$', time_str)
    if year_month_day_match:
        year, month, day = year_month_day_match.groups()
        if is_start_time:
            return f"{int(year):04d}-{int(month):02d}-{int(day):02d} 00:00:00"
        else:
            return f"{int(year):04d}-{int(month):02d}-{int(day):02d} 23:59:59"
    
    # 解析"Xd"格式（X 天前）
    day_match = re.search(r'(\d+)d', time_str)
    if day_match:
        days = int(day_match.group(1))
        if is_start_time:
            return (today_start - timedelta(days=days-1)).strftime("%Y-%m-%d 00:00:00")
        else:
            return today_start.replace(hour=23, minute=59, second=59).strftime("%Y-%m-%d 23:59:59")
    
    return None


def _generate_index_list(start_time: str, end_time: str) -> str:
    """
    返回固定索引模式。

    新索引不按日期拆分，日期过滤统一通过 @timestamp 完成。
    
    Args:
        start_time: 开始时间（格式：YYYY-MM-DD HH:MM:SS 或 YYYY-MM-DD）
        end_time: 结束时间（格式：YYYY-MM-DD HH:MM:SS 或 YYYY-MM-DD）
    
    Returns:
        str: 索引列表字符串
    """
    return INDEX_SOURCE_PATTERN


def _to_utc_iso_format(dt: datetime) -> str:
    """
    将东八区时间转换为 UTC 时间（ISO 格式）
    OpenSearch 的 @timestamp 字段存储的是 UTC 时间，
    用户输入的是东八区时间，查询时需要将东八区减 8 小时转为 UTC
    
    Args:
        dt: datetime 对象（东八区时间）
    
    Returns:
        str: UTC 时间的 ISO 格式字符串（不带 Z 后缀）
    """
    # 东八区转 UTC：减去 8 小时
    utc_dt = dt - timedelta(hours=8)
    return utc_dt.strftime('%Y-%m-%dT%H:%M:%S')


def _convert_records_to_utc8(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    将查询返回的 UTC 时间记录转换为东八区时间
    OpenSearch 返回的 @timestamp 是 UTC 时间，需要加 8 小时转回东八区再给 LLM
    
    Args:
        records: 从 ES 查询返回的记录列表（UTC 时间）
    
    Returns:
        List[Dict[str, Any]]: 东八区时间的记录列表
    """
    converted = []
    for record in records:
        new_record = record.copy()
        # 转换 @timestamp 字段
        ts = new_record.get('@timestamp')
        if ts:
            try:
                # 解析时间字符串（可能带时区后缀，也可能不带）
                ts_str = str(ts)
                # 移除可能的时区后缀 Z 或 +00:00
                ts_clean = ts_str.replace('Z', '').replace('+00:00', '').strip()
                # 尝试解析
                if 'T' in ts_clean:
                    dt_utc = datetime.strptime(ts_clean, '%Y-%m-%dT%H:%M:%S')
                else:
                    dt_utc = datetime.strptime(ts_clean, '%Y-%m-%d %H:%M:%S')
                # UTC 转东八区：加 8 小时
                dt_cst = dt_utc + timedelta(hours=8)
                new_record['@timestamp'] = dt_cst.strftime('%Y-%m-%d %H:%M:%S')
            except (ValueError, TypeError):
                # 解析失败保留原值
                pass
        converted.append(new_record)
    return converted


def build_ppl_query(ppl_template: str, start_time: str = None, end_time: str = None,
                    filter_ip: str = None, filter_user: str = None,
                    gid: str = None, ip_field: str = "source.ip",
                    gid_scope: dict = None) -> str:
    """
    根据参数构建完整的 PPL 查询语句
    【性能优化】
    1. 时间过滤条件放在 search 命令中，避免无时间范围查询
    2. 索引按 gid 收窄，日期通过时间条件过滤
    3. 时间格式使用 ISO 格式（东八区时间转换为 UTC）

    【数据权限】
    gid_scope: 请求级 gid 白名单上下文，格式 {"login_account": str, "allowed_gids": list|None}
    - allowed_gids 为 None 表示不限制（admin），行为与旧版完全一致
    - 用户指定了 gid 且在白名单内 -> 正常拼接该 gid 条件
    - 用户未指定 gid -> 注入白名单 or 条件串
    - 越权 gid 由 ToolExecutor 入口拦截，正常情况下到不了这里（此处再防御一次）
    """
    print("开始构建 PPL 查询")
    ppl = ppl_template
    where_conditions = []
    time_conditions = []
    
    # 解析开始时间
    start_dt = None
    if start_time and start_time not in ('', 'None', 'none', 'null', 'Null'):
        try:
            start_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            try:
                start_dt = datetime.strptime(start_time, '%Y-%m-%d')
            except ValueError:
                # 如果仍然失败，尝试用 parse_time_string 解析（作为开始时间）
                parsed = parse_time_string(start_time, is_start_time=True)
                if parsed:
                    start_dt = datetime.strptime(parsed, '%Y-%m-%d %H:%M:%S')
    
    # 解析结束时间
    end_dt = None
    if end_time and end_time not in ('', 'None', 'none', 'null', 'Null'):
        try:
            end_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            try:
                end_dt = datetime.strptime(end_time, '%Y-%m-%d')
                # 如果是纯日期格式，结束时间设置为 23:59:59
                end_dt = end_dt.replace(hour=23, minute=59, second=59)
            except ValueError:
                # 如果仍然失败，尝试用 parse_time_string 解析（作为结束时间）
                parsed = parse_time_string(end_time, is_start_time=False)
                if parsed:
                    end_dt = datetime.strptime(parsed, '%Y-%m-%d %H:%M:%S')
    
    # 新索引不包含日期；日期过滤通过 @timestamp 完成。
    if start_dt:
        time_conditions.append(f"@timestamp >= '{_to_utc_iso_format(start_dt)}'")
    
    if end_dt:
        time_conditions.append(f"@timestamp <= '{_to_utc_iso_format(end_dt)}'")
    
    # 收集其他过滤条件（放在 where 子句中）
    if filter_ip and filter_ip not in ('', 'None', 'none', 'null', 'Null'):
        # 【修复】支持多字段过滤：如果 ip_field 是列表，则生成 OR 条件
        if isinstance(ip_field, list):
            ip_cond = " or ".join(f"{f} = '{filter_ip}'" for f in ip_field)
            where_conditions.append(f"({ip_cond})")
        else:
            where_conditions.append(f"{ip_field} = '{filter_ip}'")
    
    if filter_user and filter_user not in ('', 'None', 'none', 'null', 'Null'):
        where_conditions.append(f"source.user.name = '{filter_user}'")

    # 【数据权限】gid 白名单处理
    allowed_gids = None
    if gid_scope is not None:
        allowed_gids = gid_scope.get("allowed_gids")
    allowed_list = normalize_allowed_gids(allowed_gids) if allowed_gids is not None else None

    if not is_gid_empty(gid):
        # 用户/LLM 指定了 gid
        gid_str = str(gid).strip()
        if allowed_list is None or gid_str in allowed_list:
            where_conditions.append(f"@gid = '{gid_str}'")
        else:
            # 防御：越权 gid 不加入条件（正常情况下 ToolExecutor 入口已拦截）
            print(f"[GID_GUARD] 防御性拦截越权 gid：{gid_str}，白名单：{allowed_list}")
    elif allowed_list:
        # 未指定 gid 的受限用户：注入白名单 or 条件串（括号保证与外层 and 的优先级正确）
        gid_cond = " or ".join(f"@gid = '{g}'" for g in allowed_list)
        where_conditions.append(f"({gid_cond})")
    
    # 将时间过滤条件添加到 search 命令行末尾。
    # 将模板按行分割，在第一行（search 命令）末尾添加时间条件
    if time_conditions:
        lines = ppl.split('\n')
        if lines:
            # 在第一行末尾添加时间条件
            lines[0] = lines[0] + " " + " AND ".join(time_conditions)
            ppl = '\n'.join(lines)
    
    # 将其他过滤条件添加到 where 子句
    if where_conditions:
        ppl += f"\n| where " + " and ".join(where_conditions)

    # 【数据权限】索引层收窄：log_g* 通配符展开为白名单 gid 的具体索引
    if allowed_list:
        ppl = restrict_source_indices(ppl, allowed_list, specific_gid=gid if not is_gid_empty(gid) else None,
                                               host=ES_HOST, port=ES_PORT, user=ES_AUTH_USER, password=ES_AUTH_PASSWORD)

    return ppl


def build_aggregate_query(ppl_template: str, start_time: str = None, end_time: str = None,
                          group_by: str = "srcip", gid: str = None,
                          time_field: str = "@timestamp",
                          gid_scope: dict = None) -> str:
    """
    构建聚合查询的 PPL 语句（通用版本）
    【性能优化】
    1. 时间过滤条件放在 search 命令中，避免无时间范围查询
    2. 索引按 gid 收窄，日期通过时间条件过滤
    3. 时间格式使用 ISO 格式（东八区时间转换为 UTC）
    
    Args:
        ppl_template: 基础 PPL 模板（不包含时间过滤和聚合）
        start_time: 开始时间
        end_time: 结束时间
        group_by: 聚合分组字段
        time_field: 时间字段名
    
    Returns:
        str: 聚合查询 PPL 语句
    """
    print("开始构建聚合 PPL 查询")
    base_query = ppl_template
    
    # 移除末尾的 sort 和 fields 语句（如果有）
    lines = base_query.strip().split('\n')
    cleaned_lines = []
    for line in lines:
        line_lower = line.strip().lower()
        if not line_lower.startswith('| sort') and not line_lower.startswith('sort'):
            cleaned_lines.append(line)
    base_query = '\n'.join(cleaned_lines)
    
    # 解析开始时间和结束时间
    start_dt = None
    end_dt = None
    
    if start_time and start_time not in ('', 'None', 'none', 'null', 'Null'):
        try:
            if ' ' in start_time and ':' in start_time:
                start_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
            else:
                start_dt = datetime.strptime(start_time, '%Y-%m-%d')
                start_dt = start_dt.replace(hour=0, minute=0, second=0)
        except ValueError:
            parsed = parse_time_string(start_time, is_start_time=True)
            if parsed:
                start_dt = datetime.strptime(parsed, '%Y-%m-%d %H:%M:%S')
    
    if end_time and end_time not in ('', 'None', 'none', 'null', 'Null'):
        try:
            if ' ' in end_time and ':' in end_time:
                end_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S')
            else:
                end_dt = datetime.strptime(end_time, '%Y-%m-%d')
                end_dt = end_dt.replace(hour=23, minute=59, second=59)
        except ValueError:
            parsed = parse_time_string(end_time, is_start_time=False)
            if parsed:
                end_dt = datetime.strptime(parsed, '%Y-%m-%d %H:%M:%S')
    
    # 新索引不包含日期；日期过滤通过时间字段完成。
    time_conditions = []
    if start_dt:
        time_conditions.append(f"{time_field} >= '{_to_utc_iso_format(start_dt)}'")
    if end_dt:
        time_conditions.append(f"{time_field} <= '{_to_utc_iso_format(end_dt)}'")
    
    # 收集其他过滤条件（放在 where 子句中）
    where_conditions = []

    # 【数据权限】gid 白名单处理（与 build_ppl_query 同规则）
    allowed_gids = None
    if gid_scope is not None:
        allowed_gids = gid_scope.get("allowed_gids")
    allowed_list = normalize_allowed_gids(allowed_gids) if allowed_gids is not None else None

    if not is_gid_empty(gid):
        gid_str = str(gid).strip()
        if allowed_list is None or gid_str in allowed_list:
            where_conditions.append(f"@gid = '{gid_str}'")
        else:
            print(f"[GID_GUARD] 防御性拦截越权 gid：{gid_str}，白名单：{allowed_list}")
    elif allowed_list:
        gid_cond = " or ".join(f"@gid = '{g}'" for g in allowed_list)
        where_conditions.append(f"({gid_cond})")
    
    # 将时间过滤条件添加到 search 命令行末尾。
    # 将模板按行分割，在第一行（search 命令）末尾添加时间条件
    if time_conditions:
        lines = base_query.split('\n')
        if lines:
            # 在第一行末尾添加时间条件
            lines[0] = lines[0] + " " + " AND ".join(time_conditions)
            base_query = '\n'.join(lines)
    
    # 将其他过滤条件添加到 where 子句
    if where_conditions:
        base_query += f"\n| where " + " and ".join(where_conditions)

    # 【数据权限】索引层收窄：log_g* 通配符展开为白名单 gid 的具体索引
    if allowed_list:
        base_query = restrict_source_indices(base_query, allowed_list, specific_gid=gid if not is_gid_empty(gid) else None,
                                                  host=ES_HOST, port=ES_PORT, user=ES_AUTH_USER, password=ES_AUTH_PASSWORD)
    
    # 添加聚合
    if group_by == "user":
        base_query += "\n| stats count() as fail_count by user, devname"
    else:
        base_query += "\n| stats count() as fail_count by attack_src, user, devname"
    
    base_query += "\n| sort - fail_count"
    
    return base_query


def query_es(ppl_query: str, user: str = None, password: str = None, debug_info: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    执行 ES PPL 查询（集成电路断路器保护）
    
    Args:
        ppl_query: PPL 查询语句
        user: Elasticsearch 用户名
        password: Elasticsearch 密码
        debug_info: 调试信息字典，包含 tool_name, user_problem, start_time, end_time 等
    
    Returns:
        dict: 包含 ppl_query, data, count, error, http_status 的字典
    """
    # 【调试日志】记录查询入口信息
    print(f"\n{'='*60}")
    print(f"[ES_QUERY] 开始执行 ES PPL 查询")
    print(f"[ES_QUERY] 时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    if debug_info:
        print(f"[ES_QUERY] 调用工具：{debug_info.get('tool_name', 'unknown')}")
        print(f"[ES_QUERY] 用户问题：{debug_info.get('user_problem', 'N/A')[:200]}")
        print(f"[ES_QUERY] 开始时间：{debug_info.get('start_time', '未指定')}")
        print(f"[ES_QUERY] 结束时间：{debug_info.get('end_time', '未指定')}")
        print(f"[ES_QUERY] 过滤 IP: {debug_info.get('filter_ip', '无')}")
        print(f"[ES_QUERY] 过滤用户：{debug_info.get('filter_user', '无')}")

    # 最后一层权限防护：禁止绕过工具入口直接提交任意 PPL。
    # 管理员必须同样通过请求上下文进入，只是管理员上下文不受 gid 索引限制。
    from tools.tool_base import request_ctx
    gid_scope = request_ctx.get()
    if gid_scope is None:
        return {
            "ppl_query": ppl_query,
            "data": [],
            "count": 0,
            "error": "缺少数据权限上下文，拒绝执行 ES 查询",
            "http_status": 403,
        }

    is_admin = bool(gid_scope.get("is_admin", False))
    allowed_gids = gid_scope.get("allowed_gids")
    if not is_admin:
        if allowed_gids is None:
            return {
                "ppl_query": ppl_query,
                "data": [],
                "count": 0,
                "error": "缺少用户组权限信息，拒绝执行 ES 查询",
                "http_status": 403,
            }
        ppl_query, permission_error = enforce_gid_permission(
            ppl_query,
            allowed_gids,
            host=ES_HOST,
            port=ES_PORT,
            user=ES_AUTH_USER,
            password=ES_AUTH_PASSWORD,
        )
        if permission_error:
            return {
                "ppl_query": ppl_query,
                "data": [],
                "count": 0,
                "error": permission_error,
                "http_status": 403,
            }
        authorized, source_error = validate_authorized_ppl_sources(
            ppl_query,
            allowed_gids,
            is_admin=False,
        )
        if not authorized:
            return {
                "ppl_query": ppl_query,
                "data": [],
                "count": 0,
                "error": source_error,
                "http_status": 403,
            }

    user = user or ES_AUTH_USER
    password = password or ES_AUTH_PASSWORD
    user = require_config(user, "ES_AUTH_USER")
    password = require_config(password, "ES_AUTH_PASSWORD")
    
    # 【调试日志】记录认证信息
    print(f"[ES_QUERY] 认证用户：{user}")
    print("[ES_QUERY] 认证密码：已配置")
    
    # 【新增】检查电路断路器状态
    if es_circuit_breaker.is_open:
        stats = es_circuit_breaker.get_stats()
        error_msg = (
            f"ES 服务暂时不可用（电路断路器已断开）- "
            f"连续失败{stats['failure_count']}次，将在{stats['recovery_timeout']}秒后尝试恢复。"
            f"建议使用 L1 场景化提问方式。"
        )
        print(f"[ES_QUERY] [CircuitBreaker] ES 查询被拒绝：{error_msg}")
        print(f"{'='*60}\n")
        return {
            "ppl_query": ppl_query,
            "data": [],
            "count": 0,
            "error": error_msg,
            "http_status": 503,
            "circuit_breaker_open": True
        }
    
    auth_str = f"{user}:{password}"
    auth_b64 = base64.b64encode(auth_str.encode()).decode()
    
    # 【调试日志】记录 PPL 查询关键信息
    print(f"[ES_QUERY] PPL 查询长度：{len(ppl_query)} 字符")
    # 检查是否包含时间过滤条件
    has_time_filter = "@timestamp >=" in ppl_query or "@timestamp <=" in ppl_query or "@timestamp >" in ppl_query
    print(f"[ES_QUERY] 包含时间过滤：{'是' if has_time_filter else '否'}")
    if not has_time_filter:
        print(f"[ES_QUERY] [警告] PPL 查询缺少时间过滤条件，可能导致 ES 拒绝查询！")
    
    # 【优化】使用动态超时配置，默认 45 秒（适应大数据量查询）
    from utils.request_timeout import TimeoutConfig
    es_timeout = TimeoutConfig.ES_QUERY_TIMEOUT
    
    # 【调试日志】记录请求详情
    print(f"[ES_QUERY] 请求 URL: {ES_SCHEME}://{ES_HOST}:{ES_PORT}/_plugins/_ppl")
    print(f"[ES_QUERY] Auth Header: Basic {auth_b64[:15]}...{auth_b64[-10:]}")
    print(f"[ES_QUERY] 超时设置：{es_timeout}秒")
    
    try:
        connection_cls = (
            http.client.HTTPSConnection
            if ES_SCHEME.lower() == "https"
            else http.client.HTTPConnection
        )
        connection_args = {
            "host": ES_HOST,
            "port": ES_PORT,
            "timeout": int(es_timeout),
        }
        if connection_cls is http.client.HTTPSConnection:
            connection_args["context"] = _build_ssl_context()
        conn = connection_cls(**connection_args)
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {auth_b64}"
        }
        request_body = json.dumps({"query": ppl_query, "format": "json"})
        print(f"[ES_QUERY] 请求体大小：{len(request_body)} 字节")
        
        conn.request("POST", "/_plugins/_ppl", body=request_body, headers=headers)
        response = conn.getresponse()
        response_body = response.read().decode()
        conn.close()
        
        # 【调试日志】记录响应详情
        print(f"[ES_QUERY] 响应状态码：{response.status}")
        if response.status != 200:
            print(f"[ES_QUERY] 响应体预览：{response_body[:500]}")
        
        # 【新增】记录断路器状态
        if response.status == 200:
            es_circuit_breaker.record_success()
            result = json.loads(response_body)
            datarows = result.get("datarows", [])
            schema = result.get("schema", [])
            
            if not datarows:
                print(f"[ES_QUERY] 查询成功，返回 0 条记录")
                print(f"{'='*60}\n")
                return {"ppl_query": ppl_query, "http_status": response.status, "data": [], "count": 0}
            
            columns = [field.get("name") for field in schema]
            df = pd.DataFrame(datarows, columns=columns)
            records = df.to_dict('records')
            
            # 【恢复】统一在此处将 UTC 记录转换为东八区时间，确保下游工具（如溯源）能正确使用 CST 时间
            records = _convert_records_to_utc8(records)
            
            print(f"[ES_QUERY] 查询成功，返回 {len(records)} 条记录")
            print(f"{'='*60}\n")
            return {"ppl_query": ppl_query, "http_status": response.status, "data": records, "count": len(records)}
        else:
            es_circuit_breaker.record_failure()
            # 【关键修复】详细记录 401 错误的上下文信息
            if response.status == 401:
                print(f"[ES_QUERY] [401 错误] 认证失败！")
                print(f"[ES_QUERY] [401 错误] 可能原因:")
                print(f"[ES_QUERY] [401 错误]   1. 用户名或密码错误")
                print(f"[ES_QUERY] [401 错误]   2. ES 服务端配置了 IP 白名单限制")
                print(f"[ES_QUERY] [401 错误]   3. PPL 查询缺少时间过滤条件（ES 安全策略）")
                print(f"[ES_QUERY] [401 错误]   4. ES 服务端认证模块异常")
                print(f"[ES_QUERY] [401 错误] 请求详情:")
                print(f"[ES_QUERY] [401 错误]   - 用户：{user}")
                print(f"[ES_QUERY] [401 错误]   - PPL 长度：{len(ppl_query)}")
                print(f"[ES_QUERY] [401 错误]   - 有时间过滤：{has_time_filter}")
            print(f"{'='*60}\n")
            return {"ppl_query": ppl_query, "http_status": response.status, "error": f"HTTP {response.status}: {response_body[:500]}", "data": [], "count": 0}
    
    except Exception as e:
        es_circuit_breaker.record_failure()
        print(f"[ES_QUERY] 查询异常：{type(e).__name__}: {str(e)}")
        print(f"{'='*60}\n")
        # 【修复】异常返回时也要设置 http_status=0，便于调用方判断
        return {"ppl_query": ppl_query, "error": str(e), "data": [], "count": 0, "http_status": 0}
