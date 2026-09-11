# -*- coding: utf-8 -*-
"""
PPL 数据权限守卫（gid 白名单强制过滤）

安全原则：
1. 权限过滤在代码层强制注入，不依赖 LLM 提示词（提示词只是优化，不是防线）
2. 所有 PPL 在送入 query_es() 之前必须经过 enforce_gid_permission() 或
   build_ppl_query 的 gid_scope 参数处理
3. 双层限制：
   - 索引层：log_g* 通配符展开为白名单 gid 的具体索引（ES 只扫描有权索引，性能+粗粒度安全）
   - where 层：注入 @gid 过滤条件（正确性保证，适配任何 gid 格式）

名词说明：面向用户的文案统一使用「用户组」，对应日志字段 @gid / 索引前缀 log_g{gid}。
"""
import re
import time
from tools.index_config import INDEX_SOURCE_REGEX, build_index_names
from config import (
    ES_HOST,
    ES_PORT,
    ES_INDEX_TIMEOUT,
    ES_AUTH_USER,
    ES_AUTH_PASSWORD,
    ES_SCHEME,
    ES_VERIFY_SSL,
    INDEX_CACHE_TTL,
)

# ============================================
# 越权提示模板（固定文案，面向用户）
# ============================================
GID_DENIED_TEMPLATE = (
    "抱歉，您当前没有用户组 {gid} 的查询权限。"
    "您可查询的用户组为：{allowed}。"
    "如需查询该用户组的数据或申请更多权限，请联系系统管理员。"
)

GID_DENIED_L2_TEMPLATE = (
    "本次查询涉及您无权访问的用户组（{gid}），已终止查询。"
    "您可查询的用户组为：{allowed}。"
    "建议在问题中指定您有权限的用户组后重试。"
)

GID_ALL_INDEX_INVALID_TEMPLATE = (
    "您当前有权限的所有用户组（{allowed}）的索引均无法访问（索引不存在），"
    "请检查数据接入配置或联系系统管理员。"
)

GID_SPECIFIC_INDEX_INVALID_TEMPLATE = (
    "抱歉，用户组 {gid} 的日志索引不存在，无法查询。"
)


# gid 空值的多种表示（LLM 可能传字符串 "None" 等）
_GID_EMPTY_VALUES = ('', 'None', 'none', 'null', 'Null', 'NULL')

# 缓存已检查的索引存在性 {index_name: bool}
_index_cache = {}
_INDEX_CACHE_TTL = INDEX_CACHE_TTL
_PPL_SOURCE_RE = re.compile(
    r"(?i)\bsearch\s+source\s*=\s*(?:`([^`]*)`|([^\s|]+))"
)


def _check_index_exists(index_name: str, host: str = ES_HOST, port: int = ES_PORT, user: str = None, password: str = None) -> bool:
    """
    检查索引是否存在（带缓存）
    
    Args:
        index_name: 索引名称
        host: ES 主机
        port: ES 端口
        user: ES 用户名
        password: ES 密码
    
    Args:
        skip_gid_injection: 是否跳过 gid 条件注入（管理员有 allowed_gids 时使用）

    Returns:
        bool: 索引是否存在
    """
    # 检查缓存（带 TTL）
    if index_name in _index_cache:
        cached = _index_cache[index_name]
        if isinstance(cached, tuple) and len(cached) == 2:
            exists_cached, ts = cached
            if time.time() - ts < _INDEX_CACHE_TTL:
                return exists_cached
            # 过期则忽略，重新探测
        else:
            # 旧格式（裸 bool）兼容：直接返回
            return cached
    
    import ssl
    import base64
    import http.client
    
    if user and password:
        auth_str = f"{user}:{password}"
        auth_b64 = base64.b64encode(auth_str.encode()).decode()
    else:
        # 配置中心已统一加载 .env，并兼容 ES_USER/ES_PASSWORD 别名。
        auth_user = user or ES_AUTH_USER
        auth_pass = password or ES_AUTH_PASSWORD
        if auth_user and auth_pass:
            auth_str = f"{auth_user}:{auth_pass}"
            auth_b64 = base64.b64encode(auth_str.encode()).decode()
        else:
            # 无认证信息：仍发起匿名 HEAD 请求
            auth_b64 = ""
            print(f"[GID_GUARD] 警告：_check_index_exists 缺少 ES 认证信息，将尝试匿名 HEAD")
    
    try:
        connection_cls = (
            http.client.HTTPSConnection
            if ES_SCHEME.lower() == "https"
            else http.client.HTTPConnection
        )
        connection_args = {
            "host": host,
            "port": port,
            "timeout": ES_INDEX_TIMEOUT,
        }
        if connection_cls is http.client.HTTPSConnection:
            ctx = ssl.create_default_context()
            if not ES_VERIFY_SSL:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            connection_args["context"] = ctx
        conn = connection_cls(**connection_args)
        headers = {"Content-Type": "application/json"}
        if auth_b64:
            headers["Authorization"] = f"Basic {auth_b64}"
        # 使用 HEAD 请求检查索引存在性
        conn.request("HEAD", f"/{index_name}", headers=headers)
        resp = conn.getresponse()
        exists = resp.status == 200
        resp.read()  # 消耗响应体
        conn.close()
        
        # 缓存结果，并记录时间以便按 INDEX_CACHE_TTL 过期。
        _index_cache[index_name] = (exists, time.time())
        return exists
    except Exception as e:
        # 探测失败不能当作索引存在，否则网络或认证故障会绕过有效性探测。
        print(f"[GID_GUARD] 索引存在性探测异常 {index_name}: {e}")
        _index_cache[index_name] = (False, time.time())
        return False


def is_gid_empty(gid) -> bool:
    """判断 gid 参数是否为空"""
    if gid is None:
        return True
    return str(gid).strip() in _GID_EMPTY_VALUES


def normalize_allowed_gids(allowed_gids) -> list:
    """白名单统一转为字符串列表"""
    if not allowed_gids:
        return []
    return [str(g).strip() for g in allowed_gids if str(g).strip()]


def check_gid_allowed(gid, allowed_gids) -> bool:
    """
    校验单个 gid 是否在白名单内。

    Args:
        gid: 待校验的 gid（可为空，空视为通过，由注入逻辑兜底）
        allowed_gids: 白名单；None 表示不限制（admin）
    """
    if allowed_gids is None:
        return True
    if is_gid_empty(gid):
        return True
    return str(gid).strip() in normalize_allowed_gids(allowed_gids)


def build_denied_message(gid, allowed_gids, l2: bool = False) -> str:
    """构建越权提示文案（gid 可为单个值或列表）"""
    template = GID_DENIED_L2_TEMPLATE if l2 else GID_DENIED_TEMPLATE
    if isinstance(gid, (list, tuple)):
        gid_text = "、".join(str(g) for g in gid)
    else:
        gid_text = str(gid)
    return template.format(
        gid=gid_text,
        allowed="、".join(normalize_allowed_gids(allowed_gids)),
    )


def build_denied_result(gid, allowed_gids, l2: bool = False) -> str:
    """
    构建越权时的工具返回值（JSON 字符串）。

    注意：error 和 suggestion 设为相同内容，agent_chat.py 在 HTTP 非 200 时
    会将两者拼接输出，因此建议将 suggestion 置为空避免重复。
    """
    import json
    msg = build_denied_message(gid, allowed_gids, l2=l2)
    return json.dumps({
        "steps": [{
            "step": 1,
            "title": "权限校验",
            "detail": f"查询涉及无权访问的用户组：{gid}，已终止查询"
        }],
        "http_status": 403,
        "error": "",  # 不重复，final_answer 由 suggestion 触发
        "suggestion": msg,  # 触发 agent_chat 直推 final_answer，不经过 LLM
        "count": 0,
        "data": []
    }, ensure_ascii=False)


# ============================================
# PPL gid 条件提取 / 注入 / 索引收窄
# ============================================
def build_index_invalid_result(specific_gid, allowed_gids, pattern: str = None) -> str:
    """
    构建「索引不存在」时的工具返回值（JSON 字符串）。

    Args:
        specific_gid: 用户指定的具体 gid（None 表示用户未指定）
        allowed_gids: 白名单列表
        pattern: 探测的完整索引模式列表

    Args:
        skip_gid_injection: 是否跳过 gid 条件注入（管理员有 allowed_gids 时使用）

    Returns:
        str: JSON 字符串，含 suggestion 字段触发 agent_chat 直推 final_answer
    """
    import json
    if specific_gid:
        detail = f"用户组 {specific_gid} 的日志索引不存在"
        if pattern:
            detail += f"，实际探测索引模式：{pattern}"
        msg = f"{detail}，无法查询。"
    else:
        detail = f"您有权查询的用户组（{allowed_gids}）的日志索引均不存在"
        if pattern:
            detail += f"，实际探测索引模式：{pattern}"
        msg = f"{detail}，无法查询。"
    return json.dumps({
        "__agent_stop__": True,
        "steps": [{
            "step": 1,
            "title": "索引探测",
            "detail": detail
        }],
        "http_status": 404,
        "error": "",  # 不重复
        "suggestion": msg,  # 触发 agent_chat 直推 final_answer，不经过 LLM
        "count": 0,
        "data": []
    }, ensure_ascii=False)


def extract_ppl_gids(ppl: str) -> list:
    """从 PPL 文本中提取已声明的 @gid 条件值"""
    if not ppl:
        return []
    gids = re.findall(r"@gid\s*=\s*'([^']+)'", ppl)
    # 兼容 @gid in ('a','b') 形式
    for m in re.finditer(r"@gid\s+in\s*\(([^)]+)\)", ppl, re.IGNORECASE):
        gids.extend(re.findall(r"'([^']+)'", m.group(1)))
    return gids


def inject_gid_condition(ppl: str, allowed_gids) -> str:
    """
    在 search 行之后注入 gid 白名单过滤条件（仅在 PPL 未声明 gid 时调用）。

    注入位置选在第一行（search source=...）之后：
    - PPL 是管道语法，where 放最前可让越权数据在第一个环节被过滤
    - 不破坏后续的 stats / sort 语法（插在尾部反而会破坏聚合查询）
    
    【健壮性修复】处理 search 行末尾可能存在的管道符或空格
    """
    allowed = normalize_allowed_gids(allowed_gids)
    if not allowed:
        return ppl
    
    gid_cond = " or ".join(f"@gid = '{g}'" for g in allowed)
    lines = ppl.split("\n")
    
    # 找到 search 行（跳过可能的空行/前导空白）
    insert_idx = 0
    search_line_idx = -1
    for i, line in enumerate(lines):
        if line.strip().startswith("search"):
            search_line_idx = i
            insert_idx = i + 1
            break
    
    # 如果没找到 search 行，直接返回
    if search_line_idx == -1:
        return ppl
        
    # 如果 search 行末尾已经有管道符，不需要加前缀
    search_line = lines[search_line_idx]
    prefix = "" if search_line.rstrip().endswith("|") else "|"
    
    lines.insert(insert_idx, f"{prefix} where {gid_cond}")
    return "\n".join(lines)


def restrict_source_indices(ppl: str, allowed_gids, specific_gid: str = None,
                           host: str = ES_HOST, port: int = ES_PORT,
                           user: str = None, password: str = None) -> str:
    """
    索引层限制：把 YAML 配置生成的 wildcard 索引模式展开为有效具体索引。

    Args:
        ppl: PPL 查询语句
        allowed_gids: 白名单 gid 列表（None 表示不限制）
        specific_gid: 用户指定的具体 gid（可选）
        host: ES 主机
        port: ES 端口
        user: ES 用户名
        password: ES 密码

    Returns:
        str: 处理后的 PPL（索引不存在或全不存在时返回空字符串）
    """
    allowed = normalize_allowed_gids(allowed_gids)
    if not allowed:
        return ppl  # admin 模式：allowed_gids 为空，不做限制，原样返回

    # 决定要探测的 gid 列表
    if specific_gid and str(specific_gid).strip():
        gids_to_check = [str(specific_gid).strip()]
    else:
        gids_to_check = allowed

    if not INDEX_SOURCE_REGEX.search(ppl):
        return ppl  # 没有匹配到索引模式，原样返回

    valid_indices = []
    for g in gids_to_check:
        for index_name in build_index_names(g):
            if _check_index_exists(index_name, host, port, user, password):
                valid_indices.append(index_name)

    if not valid_indices:
        return ""

    result = INDEX_SOURCE_REGEX.sub(
        lambda match: ",".join(
            index_name
            for index_name in valid_indices
            if index_name.endswith(f"_{match.group(1)}")
        ),
        ppl,
    )
    # 某个组合没有有效索引时，清理 source 列表中的空项。
    result = re.sub(
        r"(?i)(search\s+source=`)([^`]+)(`)",
        lambda match: f"{match.group(1)}{','.join(
            part.strip() for part in match.group(2).split(',') if part.strip()
        )}{match.group(3)}",
        result,
        count=1,
    )
    result = re.sub(
        r"(?i)(search\s+source=)(?!`)([^\s|]+)",
        lambda match: f"{match.group(1)}{','.join(
            part.strip() for part in match.group(2).split(',') if part.strip()
        )}",
        result,
        count=1,
    )
    # 所有候选组合均无有效索引时，返回空字符串，让上层统一走 404 兜底。
    source_match = re.search(
        r"(?i)search\s+source=(?:`([^`]*)`|([^\s|]+))",
        result,
    )
    if source_match and not (source_match.group(1) or source_match.group(2) or "").strip():
        return ""
    return result


def validate_authorized_ppl_sources(
    ppl: str,
    allowed_gids,
    is_admin: bool = False,
) -> tuple[bool, str]:
    """校验最终 PPL 的 source 只能指向当前用户可访问的具体索引。"""
    if is_admin:
        return True, ""

    allowed = normalize_allowed_gids(allowed_gids)
    match = _PPL_SOURCE_RE.search(ppl or "")
    if not match:
        return False, "PPL 缺少合法的 search source"

    source_text = (match.group(1) or match.group(2) or "").strip()
    source_parts = [part.strip() for part in source_text.split(",") if part.strip()]
    if not source_parts:
        return False, "PPL 的 search source 为空"

    allowed_indices = {
        index_name
        for gid in allowed
        for index_name in build_index_names(gid)
    }
    unauthorized = [
        source for source in source_parts
        if source not in allowed_indices or "*" in source
    ]
    if unauthorized:
        return False, "PPL source 包含未授权索引"
    return True, ""


def enforce_gid_permission(ppl: str, allowed_gids,
                          host: str = ES_HOST, port: int = ES_PORT,
                          user: str = None, password: str = None,
                          start_time: str = None, end_time: str = None,
                           skip_gid_injection: bool = False,
                           requested_gid: str = None):
    """
    PPL 执行前的强制权限过滤（L1 和 L2 通用入口）。

    处理规则（对应需求流程图）：
    1. PPL 中已声明的 gid 若存在越权 -> 返回错误提示，调用方应终止查询
    2. 已声明的 gid 全部合法 -> 保持不动（不剥离重写，避免破坏复合条件）
    3. 未声明 gid -> 注入白名单 where 条件（skip_gid_injection=True 时跳过，用于管理员）
    4. 无论哪种情况，索引层都做通配符收窄（通配符→具体存在的索引）
    5. 指定 gid 但索引不存在 -> 返回 "索引不存在" 兜底提示
    6. 未指定 gid 且部分索引存在 -> 只展开存在的索引
    7. 未指定 gid 且全不存在 -> 返回 "全不存在" 兜底提示

    Args:
        skip_gid_injection: 是否跳过 gid 条件注入（管理员有 allowed_gids 时使用）

    Returns:
        tuple: (处理后的 ppl, 错误提示)。错误提示非 None 表示拦截。
    """
    if allowed_gids is None:
        return ppl, None

    allowed = normalize_allowed_gids(allowed_gids)
    specified = extract_ppl_gids(ppl)
    requested = None if is_gid_empty(requested_gid) else str(requested_gid).strip()
    if not skip_gid_injection:
        denied = [g for g in specified if g not in allowed]
        if requested and requested not in allowed:
            return ppl, build_denied_message(requested, allowed, l2=True)
        if denied:
            return ppl, build_denied_message(denied, allowed, l2=True)

    # 工具参数或用户原文提取出的 gid 优先于模型生成结果；
    # 即使模型漏写或写入了其他合法 gid，也必须追加精确约束。
    if requested and requested not in specified:
        ppl = inject_gid_condition(ppl, [requested])
        specified = [requested] + specified
    elif not specified and not skip_gid_injection:
        ppl = inject_gid_condition(ppl, allowed)

    # 决定 specific_gid：LLM/PPL 声明了 gid 则用第一个；未声明则为 None（探测整个白名单）
    specific_gid = requested or (specified[0] if specified else None)

    # 索引层收窄（无论是否已声明 gid）
    ppl = restrict_source_indices(
        ppl, allowed, specific_gid=specific_gid,
        host=host, port=port, user=user, password=password,
    )

    # 索引兜底分支：按 specific_gid 是否传入区分两种文案
    if not ppl.strip():
        if specific_gid:
            # 指定 gid 的索引不存在
            return ppl, GID_SPECIFIC_INDEX_INVALID_TEMPLATE.format(gid=specific_gid)
        else:
            # 白名单中所有 gid 的索引都不存在
            return ppl, GID_ALL_INDEX_INVALID_TEMPLATE.format(
                allowed="、".join(allowed)
            )

    return ppl, None


def check_index_existence(gid, allowed_gids, host: str = ES_HOST, port: int = ES_PORT,
                          user: str = None, password: str = None, start_time: str = None, end_time: str = None,
                           skip_gid_injection: bool = False):
    """
    独立索引存在性探测（用于 L1 工具 execute() 中 _build_ppl_query 之前）。
    不依赖 PPL 文本，直接基于 gid 和时间范围探测。
    
    探测策略：
    - 无论时间范围如何，都探测 gid 对应的全部 YAML 索引组合

    Args:
        skip_gid_injection: 是否跳过 gid 条件注入（管理员有 allowed_gids 时使用）

    Returns:
        tuple: (index_info_dict, exists_flag, error_message)
    """
    allowed = normalize_allowed_gids(allowed_gids)
    if not allowed:
        return {}, False, None  # 无白名单，无法探测

    is_specific = gid and str(gid).strip() and str(gid).strip() not in _GID_EMPTY_VALUES
    error_msg = None

    if is_specific:
        # 情况 1：用户指定了具体 gid
        gid_str = str(gid).strip()
        candidates = build_index_names(gid_str)
        valid_indices = [
            idx for idx in candidates
            if _check_index_exists(idx, host, port, user, password)
        ]
        exists = bool(valid_indices)
        index_info = {
            "gids_probed": [gid_str],
            "patterns_probed": candidates,
            "valid_indices": valid_indices,
            "pattern": ", ".join(candidates),
            "exists": exists
        }
        if not exists:
            error_msg = GID_SPECIFIC_INDEX_INVALID_TEMPLATE.format(gid=gid_str)
    else:
        # 情况 2：未指定 gid，探测白名单每个 gid
        gids_exist = []
        gids_not_exist = []
        patterns_probed = []
        valid_indices = []
        for g in allowed:
            candidates = build_index_names(g)
            patterns_probed.extend(candidates)
            valid_for_gid = [
                idx for idx in candidates
                if _check_index_exists(idx, host, port, user, password)
            ]
            if valid_for_gid:
                gids_exist.append(g)
                valid_indices.extend(valid_for_gid)
            else:
                gids_not_exist.append(g)

        index_info = {
            "gids_probed": list(allowed),
            "patterns_probed": patterns_probed,  # 完整记录每个 gid 的探测模式
            "pattern": ", ".join(patterns_probed),  # 用逗号分隔的字符串形式（用于展示）
            "valid_indices": valid_indices,
            "gids_with_data": gids_exist,
            "gids_without_data": gids_not_exist,
            "exists": len(gids_exist) > 0
        }
        if not gids_exist:
            error_msg = GID_ALL_INDEX_INVALID_TEMPLATE.format(allowed="、".join(allowed))

    return index_info, index_info.get("exists", False), error_msg
