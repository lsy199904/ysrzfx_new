# -*- coding: utf-8 -*-
"""
IP 溯源查询工具
用于查询指定 IP 在攻击前 5 分钟的完整活动链路

新增功能：
- build_graph_data(): 将原始活动数据转换为 ECharts 可用的 {nodes, edges} 格式
  * 节点类型枚举: attacker | host | process | user | oss
  * 关系类型枚举: connects_to | attacks | accesses | generates | controls
"""
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pydantic import BaseModel, Field
from tools.tool_base import ToolExecutor, CompressionConfig
from tools.index_config import INDEX_SOURCE_PATTERN
from config import (
    COMPRESSION_MAX_TOKENS,
    IP_TRACE_COMPRESSION_THRESHOLD,
    IP_TRACE_MAX_RETURN_DATA,
)

logger = logging.getLogger(__name__)

CST_TIMEZONE = timezone(timedelta(hours=8))


def parse_trace_timestamp(value: str, assume_utc: bool = False) -> datetime | None:
    """Parse a log timestamp and return an aware China Standard Time value."""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        normalized = text.replace("Z", "+00:00")
        if "T" in normalized or "+" in normalized[10:] or normalized.endswith("00:00"):
            parsed = datetime.fromisoformat(normalized)
        else:
            parsed = datetime.strptime(normalized, "%Y-%m-%d %H:%M:%S.%f")
    except ValueError:
        try:
            parsed = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc if assume_utc else CST_TIMEZONE)
    return parsed.astimezone(CST_TIMEZONE)


def normalize_trace_timestamp(value: str, assume_utc: bool = False) -> str | None:
    """Normalize a timestamp to ISO 8601 with an explicit +08:00 offset."""
    parsed = parse_trace_timestamp(value, assume_utc=assume_utc)
    return parsed.isoformat(timespec="seconds") if parsed else None


def trace_timestamp_sort_key(value: str):
    """Return a stable chronological key; invalid/missing timestamps sort last."""
    return parse_trace_timestamp(value) or datetime.max.replace(tzinfo=CST_TIMEZONE)


def record_trace_timestamp(record: dict) -> str:
    """Return a normalized CST timestamp for a trace record.

    Query responses may contain the raw Elasticsearch ``@timestamp`` field or
    an already materialized ``@timestamp_cst`` field.  The graph timeline must
    expose one consistent, timezone-aware representation regardless of which
    form the backend returned.
    """
    if not isinstance(record, dict):
        return ""
    value = record.get("@timestamp_cst") or record.get("@timestamp")
    normalized = normalize_trace_timestamp(value) if value else None
    return normalized or ""


def trace_query_time(value: str) -> str:
    """Convert an ISO trace time to the naive local format accepted by PPL builders."""
    parsed = parse_trace_timestamp(value)
    if not parsed:
        raise ValueError(f"invalid trace timestamp: {value}")
    return parsed.strftime("%Y-%m-%d %H:%M:%S")

# 节点颜色方案（用于 ECharts visualMap）
NODE_COLORS = {
    "attacker": "#FF4500",  # 橙红色 - 攻击源
    "host": "#1E90FF",      # 亮蓝色 - 主机
    "user": "#32CD32",      # 绿色 - 用户
    "process": "#FFD700",   # 金色 - 进程
    "oss": "#9370DB",       # 紫色 - 资产/服务
    "policy": "#FF6347",    # 番茄红 - 策略
    "action": "#40E0D0",    # 绿松石色 - 动作
    "subtype": "#FF69B4",   # 热粉色 - 子类型
    "app": "#00FF7F",       # 春绿色 - 应用
}

# 节点符号映射
NODE_SYMBOLS = {
    "attacker": "diamond",
    "host": "rect",
    "user": "circle",
    "process": "triangle",
    "oss": "roundRect",
    "policy": "pin",
    "action": "arrow",
    "subtype": "star",
    "app": "roundRect",
}

# 左侧为旧图谱代码字段，右侧为当前索引字段。
FIELD_ALIASES = {
    "subtype": ["fortinet.firewall.subtype"],
    "action": ["event.action"],
    # Current Pipeline stores the field in the ECS path. Keep top-level status
    # as a fallback for older indexed data.
    "status": ["fortinet.firewall.status", "status"],
    "msg": ["message"],
    "reason": ["event.reason"],
    "srcip": ["source.ip"],
    "remip": ["destination.ip"],
    "devname": ["observer.name"],
    "user": ["source.user.name"],
    "policyid": ["rule.id"],
    "dstport": ["destination.port"],
    "logdesc": ["rule.description"],
    "type": ["fortinet.firewall.type"],
    "attack": ["fortinet.firewall.attack"],
    "url": ["url.original"],
    "srccountry": ["fortinet.firewall.srccountry"],
    "cfgpath": ["fortinet.firewall.cfgpath"],
    "cfgobj": ["fortinet.firewall.cfgobj"],
    "devid": ["observer.serial_number"],
    "ui": ["fortinet.firewall.ui"],
    "dstip": ["destination.ip"],
    "app": ["fortinet.firewall.app"],
    "policyname": ["rule.name"],
    "host": ["@host"],
}


def _get_field(record: dict, field_names: list, default: str = "") -> str:
    """从记录中安全获取字段值（支持嵌套字段如 source.ip）"""
    candidates = []
    for name in field_names:
        candidates.append(name)
        candidates.extend(FIELD_ALIASES.get(name, []))
        for legacy_name, aliases in FIELD_ALIASES.items():
            if name in aliases:
                candidates.append(legacy_name)

    seen = set()
    for name in candidates:
        if name in seen:
            continue
        seen.add(name)
        # 尝试直接获取（扁平结构）
        val = record.get(name, default)
        if val and val != default:
            return str(val)
        
        # 尝试嵌套获取（嵌套结构如 source.ip）
        if '.' in name:
            parts = name.split('.')
            obj = record
            for part in parts:
                if isinstance(obj, dict):
                    obj = obj.get(part, None)
                else:
                    obj = None
                    break
            if obj and obj != default:
                return str(obj)
    
    return default


def _sanitize_nan(obj):
    """【修复】递归将 NaN/Infinity 转为 None（NaN 不是合法 JSON，会导致前端 JSON.parse 报错）"""
    import math
    if isinstance(obj, dict):
        return {k: _sanitize_nan(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_sanitize_nan(v) for v in obj]
    elif isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            return None
        return obj
    return obj


def _type_to_category(type_str: str) -> int:
    """类型字符串 → 分类索引（用于 ECharts category）"""
    type_to_idx = {
        "attacker": 0, "host": 1, "user": 2, "process": 3, "oss": 4,
        "policy": 5, "action": 6, "subtype": 7, "app": 8,
    }
    return type_to_idx.get(type_str, 9)




def _parse_action_name(action: str) -> str:
    """Return the original English action value."""
    if action is None:
        return ""
    value = str(action).strip()
    return value or "unknown_action"


def _parse_msg_info(msg: str) -> dict:
    result = {
        "entity_type": None,
        "entity_name": None,
        "entity_action": None,
        "login_success": None,
        "login_reason": None,
        "port": None,
        "protocol": None,
        "firewall_action": None,
        "firewall_rule": None,
        "is_probe": False,
        "is_brute_force": False,
    }
    if not msg:
        return result

    msg_lower = msg.lower()

    # 1. 检测端口
    port_match = re.search(r'port[:\s]+(\d+)', msg)
    if port_match:
        result["port"] = port_match.group(1)
        result["is_probe"] = True

    # 2. 检测协议
    protocols = ['IMAP', 'HTTPS', 'HTTP', 'SSH', 'FTP', 'SMB', 'DNS', 'SMTP', 'RDP', 'TELNET', 'POP3', 'POP']
    for proto in protocols:
        if proto.lower() in msg_lower:
            result["protocol"] = proto
            result["is_probe"] = True
            break

    # 3. 检测用户
    user_match = re.search(r'(?:for\s+user|local\s+user|user)\s+(\w+)', msg, re.IGNORECASE)
    if user_match:
        result["entity_type"] = "user"
        result["entity_name"] = user_match.group(1)

    # 4. 检测进程/命令
    proc_match = re.search(r'(?:process|command|executed)\s+[`"\']?([\w./-]+)', msg, re.IGNORECASE)
    if proc_match:
        result["entity_type"] = "process"
        result["entity_name"] = proc_match.group(1)

    # 5. 检测文件
    file_match = re.search(r'(?:file|path)\s+[`"\']?([\w./-]+\.[\w.]+)', msg, re.IGNORECASE)
    if file_match:
        result["entity_type"] = "file"
        result["entity_name"] = file_match.group(1)

    # 6. 检测登录结果
    if re.search(r'login\s+success|login\s+successful|successful\s+login', msg, re.IGNORECASE):
        result["login_success"] = True
        result["entity_action"] = "login_success"
    elif re.search(r'login\s+fail|login\s+unsuccessful', msg, re.IGNORECASE):
        result["login_success"] = False
        result["entity_action"] = "login_failed"
        if re.search(r'unknown\s+user|no\s+such\s+user', msg, re.IGNORECASE):
            result["login_reason"] = "unknown_user"
        elif re.search(r'incorrect|wrong|invalid|bad\s+password', msg, re.IGNORECASE):
            result["login_reason"] = "wrong_password"
        elif re.search(r'account\s+lock|locked\s+account|too\s+many', msg, re.IGNORECASE):
            result["login_reason"] = "account_locked"
        else:
            result["login_reason"] = "authentication_failed"
    elif re.search(r'login', msg, re.IGNORECASE):
        result["entity_action"] = "login"

    # 7. 检测防火墙动作
    if re.search(r'quarantin', msg, re.IGNORECASE):
        result["firewall_action"] = "quarantined"
        rule_match = re.search(r'(?:rule|policy|id|by)\s*[:#]?\s*([\d.]+)', msg)
        if rule_match:
            result["firewall_rule"] = rule_match.group(1)
    elif re.search(r'block|blocked|deny|denied', msg, re.IGNORECASE):
        result["firewall_action"] = "blocked"
        rule_match = re.search(r'(?:rule|policy|id|by)\s*[:#]?\s*([\d.]+)', msg)
        if rule_match:
            result["firewall_rule"] = rule_match.group(1)

    # 8. 检测爆破行为
    if re.search(r'brute|brute.?force|crack|repeated\s+fail', msg, re.IGNORECASE):
        result["is_brute_force"] = True

    # 9. 通用动作
    action_patterns = {
        "deleted": [r'deleted', r'delete'],
        "created": [r'created', r'create'],
        "updated": [r'updated', r'update'],
        "modified": [r'modified', r'modify'],
        "reset": [r'reset', r'restart'],
        "rebooted": [r'reboot', r'rebooted'],
        "shutdown": [r'shut\s*down', r'power.*off'],
        "downloaded": [r'downloaded', r'download'],
        "uploaded": [r'uploaded', r'upload'],
    }
    for action, patterns in action_patterns.items():
        if any(re.search(p, msg, re.IGNORECASE) for p in patterns):
            result["entity_action"] = action
            break

    return result

def _build_attack_stages(timeline: list, records: list) -> list:
    """
    将扁平的时间线事件按攻击阶段分组

    四个阶段：
    1. RECONNAISSANCE: 端口探测/扫描
    2. BRUTE_FORCE: 暴力破解尝试
    3. BLOCKED: 防火墙拦截/隔离
    4. RESOLUTION: 最终结果（成功登录/账户锁定/攻击结束）

    返回格式：
    [
        {
            "phase": "RECONNAISSANCE",
            "phase_name": "首次探测",
            "events": [...],
            "key_details": {"port": "22", "protocol": "SSH"}
        },
        ...
    ]
    """
    # 初始化四个阶段
    stages = [
        {"phase": "RECONNAISSANCE", "phase_name": "首次探测", "events": [], "key_details": {}},
        {"phase": "BRUTE_FORCE", "phase_name": "暴力破解", "events": [], "key_details": {}},
        {"phase": "BLOCKED", "phase_name": "防火墙拦截", "events": [], "key_details": {}},
        {"phase": "RESOLUTION", "phase_name": "最终结果", "events": [], "key_details": {}},
    ]

    # 按时间排序（使用 @timestamp 字段）
    sorted_records = sorted(records, key=lambda x: trace_timestamp_sort_key(record_trace_timestamp(x)))

    for record in sorted_records:
        # 直接从原始记录中解析 msg 字段
        msg = _get_field(record, ["msg", "message"])
        parsed = _parse_msg_info(msg)
        
        # 【增强】如果 msg 为空，尝试从 action 字段补充防火墙动作
        action = _get_field(record, ["action", "event.action"])
        if not msg and action:
            action_lower = action.lower()
            if "quarantin" in action_lower:
                parsed["firewall_action"] = "quarantined"
            elif "block" in action_lower or "deny" in action_lower:
                parsed["firewall_action"] = "blocked"

        # 构建事件信息（使用 timeline 中的字段）
        event_info = {
            "timestamp": record_trace_timestamp(record),
            "message": msg,
            "user": _get_field(record, ["user", "source.user.name", "username", "account"]),
            "action": _get_field(record, ["action", "event.action"]),
            "subtype": _get_field(record, ["subtype", "fortinet.firewall.subtype"]),
            "attacker": _get_field(record, ["attack_src", "srcip", "source.ip"]),
        }

        # 1. 端口探测阶段
        if parsed.get("is_probe") or parsed.get("port") or parsed.get("protocol"):
            stage = stages[0]
            stage["events"].append({
                "timestamp": event_info["timestamp"],
                "message": event_info["message"],
                "port": parsed.get("port"),
                "protocol": parsed.get("protocol"),
                "attacker": event_info["attacker"],
            })
            # 记录首次探测的关键信息
            if not stage["key_details"].get("port") and parsed.get("port"):
                stage["key_details"]["port"] = parsed.get("port")
            if not stage["key_details"].get("protocol") and parsed.get("protocol"):
                stage["key_details"]["protocol"] = parsed.get("protocol")

        # 2. 暴力破解阶段
        elif parsed.get("is_brute_force") or (
            parsed.get("login_success") is False and parsed.get("entity_type") == "user"
        ):
            stage = stages[1]
            stage["events"].append({
                "timestamp": event_info["timestamp"],
                "message": event_info["message"],
                "user": parsed.get("entity_name", "") or event_info["user"],
                "login_reason": parsed.get("login_reason"),
                "attacker": event_info["attacker"],
            })
            # 记录尝试的用户列表
            if parsed.get("entity_name"):
                stage["key_details"].setdefault("users", []).append(parsed["entity_name"])
                stage["key_details"]["users"] = list(set(stage["key_details"]["users"]))
            # 记录失败原因
            if parsed.get("login_reason") and "failure_reason" not in stage["key_details"]:
                stage["key_details"]["failure_reason"] = parsed["login_reason"]

        # 3. 防火墙拦截阶段
        elif parsed.get("firewall_action") in ["blocked", "quarantined"]:
            stage = stages[2]
            stage["events"].append({
                "timestamp": event_info["timestamp"],
                "message": event_info["message"],
                "action": parsed.get("firewall_action"),
                "rule": parsed.get("firewall_rule"),
                "attacker": event_info["attacker"],
            })
            if not stage["key_details"].get("action"):
                stage["key_details"]["event.action", "action"] = parsed.get("firewall_action")
            if not stage["key_details"].get("rule") and parsed.get("firewall_rule"):
                stage["key_details"]["rule"] = parsed.get("firewall_rule")

        # 4. 最终结果阶段
        elif parsed.get("login_success") is True:
            stage = stages[3]
            stage["events"].append({
                "timestamp": event_info["timestamp"],
                "message": event_info["message"],
                "user": parsed.get("entity_name", "") or event_info["user"],
                "attacker": event_info["attacker"],
            })
            stage["key_details"]["result"] = "success_login"
            stage["key_details"]["user"] = parsed.get("entity_name") or event_info["user"]

        elif parsed.get("entity_action") in ["deleted", "account_locked"]:
            stage = stages[3]
            stage["events"].append({
                "timestamp": event_info["timestamp"],
                "message": event_info["message"],
                "action": parsed.get("entity_action"),
                "user": parsed.get("entity_name", "") or event_info["user"],
            })
            stage["key_details"]["result"] = parsed.get("entity_action", "attack_ended")
            if parsed.get("entity_name"):
                stage["key_details"]["user"] = parsed.get("entity_name")

    # 过滤掉空阶段
    stages = [s for s in stages if s["events"]]

    # 补充阶段序号
    for i, stage in enumerate(stages, 1):
        stage["order"] = i

    return stages

def _calc_symbol_size(count: int, max_count: int) -> int:
    """根据出现次数计算节点大小（20-60 范围）"""
    if max_count == 0:
        return 30
    ratio = count / max_count
    return int(20 + ratio * 40)  # 20 ~ 60


def _add_node(nodes_map: dict, identifier: str, node_type: str, record: dict,
              id_prefix: str = "", name: str = None):
    """向节点映射中添加/更新节点"""
    if not identifier:
        return

    # 确定节点 ID
    nid = identifier  # 默认直接使用 identifier
    if node_type == "user" and not identifier.startswith("user_"):
        nid = f"user_{identifier}"
    elif id_prefix == "device" and not identifier.startswith("device_"):
        nid = f"device_{identifier}"

    # 提取时间戳
    ts = record_trace_timestamp(record)

    if nid in nodes_map:
        # 已存在，增加计数
        nodes_map[nid]["count"] = nodes_map[nid].get("count", 1) + 1
        # 合并攻击类型（使用 Fortigate 索引中实际存在的字段）
        attack_type = _get_field(record, ["fortinet.firewall.type", "type", "fortinet.firewall.subtype", "subtype", "message", "msg"])
        if attack_type and attack_type not in nodes_map[nid].get("attack_types", []):
            nodes_map[nid].setdefault("attack_types", []).append(str(attack_type))
        # 【新增】更新时间范围
        if ts:
            first_seen = nodes_map[nid].get("first_seen", "")
            last_seen = nodes_map[nid].get("last_seen", "")
            if not first_seen or ts < first_seen:
                nodes_map[nid]["first_seen"] = ts
            if not last_seen or ts > last_seen:
                nodes_map[nid]["last_seen"] = ts
            # 收集所有出现的时间戳（按时间排序）
            ts_list = nodes_map[nid].setdefault("timestamps", [])
            if ts not in ts_list:
                ts_list.append(ts)
                ts_list.sort()
    else:
        nodes_map[nid] = {
            "id": nid,
            "name": name or identifier,
            "type": node_type,
            "count": 1,
            "attack_types": [_get_field(record, ["fortinet.firewall.type", "type", "fortinet.firewall.subtype", "subtype", "message", "msg"])],
            "first_seen": ts,   # 【新增】首次出现时间
            "last_seen": ts,    # 【新增】最后出现时间
            "timestamps": [ts] if ts else [],  # 【新增】所有时间戳
        }


def _render_line_status(record: dict, direction: str) -> str:
    """Normalize record status for the two-lane render contract."""
    raw_status = _get_field(record, ["fortinet.firewall.status", "status"]).strip().lower()
    action = _get_field(record, ["event.action", "action"]).strip().lower()

    if direction == "lower":
        if raw_status in ("blocked", "block", "quarantine", "intercepted") or action in ("deny", "denied", "block", "blocked", "quarantine"):
            return "blocked"
        if raw_status in ("failed", "failure", "error"):
            return "failed"
        if raw_status in ("accept", "accepted", "pass", "passed", "allowed") or action in ("accept", "accepted", "pass", "passed", "allowed"):
            return "pass"
        if raw_status in ("success", "succeed", "ok", "normal"):
            return "success"
        return raw_status or "unknown"

    if raw_status in ("blocked", "block", "quarantine", "intercepted"):
        return "blocked"
    if raw_status in ("failed", "failure", "error", "deny", "denied"):
        return "failed"
    if raw_status in ("success", "succeed", "ok", "normal", "accept", "accepted", "pass", "passed", "allowed"):
        return "success"
    return raw_status or "unknown"


def _render_line_safe_part(value: str) -> str:
    """Create a stable URL/DOM-friendly line id fragment."""
    value = str(value or "").strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value).strip("-")
    return value or "unknown"


def _render_line_timestamp(value: str) -> str:
    """Normalize timestamps for the compact frontend contract."""
    text = str(value or "").strip()
    if not text:
        return ""
    # ``record_trace_timestamp`` returns an explicit +08:00 ISO value.  Keep
    # the established render-line display format while using the converted
    # CST wall-clock time.
    parsed = parse_trace_timestamp(text)
    if parsed:
        return parsed.strftime("%Y-%m-%d %H:%M:%S")
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            return datetime.strptime(text, fmt).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return text


def _build_render_lines(records: list) -> list:
    """Build compact, ordered paths for a frontend two-lane renderer.

    This is intentionally additive: the existing graph nodes and edges remain
    the source of truth for the force graph, while render_lines provides the
    ordered business path and per-path aggregation for a lane/flow view.
    """
    grouped = {}
    for record in records:
        if not isinstance(record, dict):
            continue

        attacker = _get_field(record, ["attack_src", "source.ip", "srcip"])
        target_ip = _get_field(record, ["destination.ip", "dstip", "remip"])
        user = _get_field(record, ["source.user.name", "user", "username", "account"])
        action = _get_field(record, ["event.action", "action"])
        event_reason = _get_field(record, ["event.reason", "reason"])
        subtype = _get_field(record, ["fortinet.firewall.subtype", "subtype"])
        oss = _get_field(record, ["observer.name", "devname", "device"])
        policy_id = _get_field(record, ["rule.id", "policyid"])
        policy_name = _get_field(record, ["rule.name", "policyname"])
        destination_port = _get_field(record, ["destination.port", "dstport"])
        # Normalize every timeline timestamp to CST first.  This handles raw
        # UTC values (including a trailing ``Z``) and already-materialized
        # ``@timestamp_cst`` values consistently.
        timestamp = _render_line_timestamp(record_trace_timestamp(record))
        # ``ip_trace`` is shared by brute-force, network-attack, account,
        # system-security, and direct IP-trace scenarios.  A detector-specific
        # role here would be wrong for every other caller.  Every returned row
        # is therefore one real hit from the global IP/window trace query.
        event_role = "global_hit"

        valid_user = user not in ("", "-", "None", "null", "nan", "N/A")
        direction = "upper" if valid_user else "lower"
        render_action = _parse_action_name(action)
        if direction == "lower" and action.strip().lower() in ("accept", "accepted", "allow", "allowed", "pass", "passed"):
            render_action = "traffic"
        status = _render_line_status(record, direction)

        line_identity_parts = [
            direction,
            attacker,
            user if valid_user else target_ip,
            render_action,
            subtype,
            destination_port,
            policy_id,
            status,
        ]
        base_id = "-".join(_render_line_safe_part(part) for part in line_identity_parts)

        steps = []
        if attacker:
            steps.append({"type": "attacker", "name": attacker})
        if valid_user:
            steps.append({"type": "user", "name": user})
        elif target_ip:
            steps.append({"type": "host", "name": target_ip})
        if render_action:
            steps.append({"type": "action", "name": render_action})
        if subtype:
            steps.append({"type": "subtype", "name": subtype})
        if oss:
            steps.append({"type": "oss", "name": oss})
        if direction == "lower" and policy_id:
            steps.append({"type": "policy", "name": policy_name or f"Policy {policy_id}"})

        key = (
            direction,
            attacker,
            target_ip if direction == "lower" else "",
            user if valid_user else "",
            render_action,
            subtype,
            oss,
            str(policy_id),
            str(policy_name),
            str(destination_port),
            status,
            event_role,
            str(event_reason),
        )
        line = grouped.setdefault(key, {
            "base_id": base_id,
            "direction": direction,
            "count": 0,
            "status": status,
            "event_role": event_role,
            "first_seen": "",
            "last_seen": "",
            "steps": steps,
            "details": {},
        })
        line["count"] += 1
        if timestamp:
            if not line["first_seen"] or timestamp < line["first_seen"]:
                line["first_seen"] = timestamp
            if not line["last_seen"] or timestamp > line["last_seen"]:
                line["last_seen"] = timestamp
        if direction == "lower":
            if target_ip:
                line["details"]["destination_ip"] = target_ip
            if destination_port:
                try:
                    line["details"]["destination_port"] = int(destination_port)
                except (TypeError, ValueError):
                    line["details"]["destination_port"] = destination_port
        if policy_id:
            line["details"]["rule_id"] = policy_id
        if policy_name:
            line["details"]["rule_name"] = policy_name
        if event_reason:
            line["details"]["event_reason"] = event_reason
        message = _get_field(record, ["message", "msg"])
        if message:
            line["details"]["message"] = message

    render_lines = []
    used_ids = set()
    for line in grouped.values():
        line_id = line["base_id"]
        if line_id in used_ids:
            # The complete aggregation key should already make IDs unique;
            # retain a deterministic suffix for malformed records with the
            # same normalized identity.
            suffix = 2
            candidate = f"{line_id}-{suffix}"
            while candidate in used_ids:
                suffix += 1
                candidate = f"{line_id}-{suffix}"
            line_id = candidate
        used_ids.add(line_id)

        output = {
            "line_id": line_id,
            "direction": line["direction"],
            "count": line["count"],
            "status": line["status"],
            "event_role": line["event_role"],
            "steps": line["steps"],
        }
        if line["first_seen"]:
            output["first_seen"] = line["first_seen"]
        if line["last_seen"]:
            output["last_seen"] = line["last_seen"]
        if line["details"]:
            output["details"] = line["details"]
        render_lines.append(output)

    return render_lines


def build_graph_data(raw_data: dict) -> dict:
    """
    将原始溯源数据转换为 {nodes, edges} 图结构

    增强版：充分利用查询到的所有字段构建更丰富的图结构
    - 节点类型：attacker, host, user, oss, policy, action, subtype, app
    - 关系类型：connects_to, attacks, accesses, generates, controls, hits_policy,
                 performs_action, belongs_to_subtype, uses_app, executes, affects

    Args:
        raw_data: ToolExecutor 返回的原始结果 dict

    Returns:
        dict: {"nodes": [...], "edges": [...], "stats": {...}}
    """
    if not raw_data or not isinstance(raw_data, dict):
        logger.warning("[build_graph_data] 原始数据为空或格式错误")
        return {"nodes": [], "edges": [], "stats": {"node_count": 0, "edge_count": 0, "type_distribution": {}}, "render_lines": []}

    # 获取实际数据（非压缩时取 data 数组）
    raw_records = raw_data.get("data", [])
    if not raw_records:
        logger.warning(f"[build_graph_data] 数据数组为空！raw_data keys: {list(raw_data.keys())}")
        # 打印完整 raw_data 用于调试
        logger.warning(f"[build_graph_data] 完整 raw_data: {json.dumps(raw_data, ensure_ascii=False)[:1000]}")
        return {"nodes": [], "edges": [], "stats": {"node_count": 0, "edge_count": 0, "type_distribution": {}}, "render_lines": []}
    
    # Materialize the same CST field used by the other query tools.  Keep the
    # raw @timestamp untouched for audit/debug output, while all graph
    # timeline/stage/edge logic can consume the normalized field consistently.
    records = []
    for raw_record in raw_records:
        if not isinstance(raw_record, dict):
            continue
        record = dict(raw_record)
        timestamp_cst = record_trace_timestamp(record)
        if timestamp_cst:
            record["@timestamp_cst"] = timestamp_cst
        records.append(record)

    logger.info(f"[build_graph_data] 开始处理 {len(records)} 条记录")
    # 打印第一条记录的键，用于调试字段映射
    if records:
        logger.info(f"[build_graph_data] 第一条记录 keys: {list(records[0].keys())}")

    # ========== 1. 构建节点去重映射 ==========
    nodes_map = {}

    for record in records:
        if not isinstance(record, dict):
            continue

        # ===== 提取基础节点 =====
        # 来源 IP（攻击者）
        src_ip = _get_field(record, ["attack_src", "source.ip", "srcip"])
        if src_ip:
            _add_node(nodes_map, src_ip, "attacker", record, "ip")

        # 远程 IP / 目标 IP
        # 新 ECS 索引中 remip 映射为 destination.ip；remip 仅作旧数据兼容。
        target_ip = _get_field(record, ["destination.ip", "dstip", "remip"])
        if target_ip:
            _add_node(nodes_map, target_ip, "host", record, "ip")

        # 用户名
        username = _get_field(record, ["source.user.name", "user", "username", "account"])
        if username and username not in ("-", "", "None", "null", "nan", "N/A"):
            _add_node(nodes_map, username, "user", record, "user", username)

        # 设备名（ECS 标准字段 observer.name，兼容旧字段 devname/device）
        devname = _get_field(record, ["observer.name", "devname", "device"])
        if devname:
            _add_node(nodes_map, devname, "oss", record, "device", devname)

        # ===== 提取策略节点 =====
        policy_id = _get_field(record, ["rule.id", "policyid"])
        policy_name = _get_field(record, ["rule.name", "policyname"])
        if policy_id and policy_id not in ("", "None", "null", "nan"):
            policy_display = policy_name if policy_name else f"Policy {policy_id}"
            policy_id_str = str(policy_id)
            _add_node(nodes_map, policy_id_str, "policy", record, "policy", policy_display)

        # ===== 提取动作节点 =====
        action = _get_field(record, ["event.action", "action"])
        if action and action not in ("", "None", "null", "nan"):
            action_display = _parse_action_name(action)
            action_id = f"action_{action.lower()}"
            _add_node(nodes_map, action_id, "action", record, "action", action_display)

        # ===== 提取子类型节点 =====
        subtype = _get_field(record, ["fortinet.firewall.subtype", "subtype"])
        if subtype and subtype not in ("", "None", "null", "nan"):
            subtype_id = f"subtype_{subtype.lower()}"
            _add_node(nodes_map, subtype_id, "subtype", record, "subtype", subtype)

        # ===== 提取应用节点 =====
        app = _get_field(record, ["application.name", "app"])
        if app and app not in ("", "None", "null", "nan"):
            app_id = f"app_{app.lower()}"
            _add_node(nodes_map, app_id, "app", record, "app", app)

        # ===== 从 msg 解析实体节点 =====
        msg = _get_field(record, ["message", "msg"])
        if msg:
            msg_info = _parse_msg_info(msg)
            if msg_info["entity_type"] and msg_info["entity_name"]:
                entity_type = msg_info["entity_type"]
                entity_name = msg_info["entity_name"]
                if entity_type == "user" and entity_name not in ("-", "", "None", "null"):
                    _add_node(nodes_map, entity_name, "user", record, "user", entity_name)
                elif entity_type == "process":
                    _add_node(nodes_map, entity_name, "process", record, "process", entity_name)
                elif entity_type == "file":
                    _add_node(nodes_map, entity_name, "file", record, "file", entity_name)

    # ========== 1.5 为节点计算状态（status）==========
    # 状态直接来自每条 ECS 记录，并按优先级合并到节点：
    # blocked > failed > success > normal。上行记录给 user/action/subtype
    # 打状态；没有 user 的防火墙响应记录给 host/action/subtype/policy 打状态。
    node_status_map = {}  # node_id -> status

    status_priority = {"": 0, "success": 1, "failed": 2, "blocked": 3}

    def _normalize_record_status(record: dict) -> str:
        raw_status = _get_field(record, ["fortinet.firewall.status", "status"]).strip().lower()
        if raw_status in ("success", "succeed", "ok", "normal"):
            return "success"
        if raw_status in ("failed", "failure", "error", "deny", "denied"):
            return "failed"
        if raw_status in ("blocked", "block", "quarantine", "intercepted"):
            return "blocked"
        if raw_status in ("accept", "accepted", "pass", "passed", "allowed"):
            return "success"
        # 部分 FortiGate 流量日志没有显式 status，但 event.action 本身
        # 已表达允许/拦截结果，用于补齐节点和边的绘图状态。
        action = _get_field(record, ["event.action", "action"]).strip().lower()
        if action in ("accept", "accepted", "pass", "passed", "allowed"):
            return "success"
        if action in ("deny", "denied", "block", "blocked", "quarantine"):
            return "blocked"

        # 某些登录日志只保留 message/event.reason，没有显式 status。
        # 这时仍要把失败状态同步到 user、action、subtype 以及对应边。
        msg = _get_field(record, ["message", "msg"]).lower()
        reason = _get_field(record, ["event.reason", "reason"]).lower()
        if any(keyword in reason for keyword in ("invalid", "fail", "locked", "timeout", "denied")):
            return "failed"
        if any(keyword in msg for keyword in ("login failed", "authentication failed", "access denied")):
            return "failed"
        return ""

    def _set_node_status(node_id: str, status: str) -> None:
        if not node_id or not status:
            return
        current = node_status_map.get(node_id, "")
        if status_priority.get(status, 0) >= status_priority.get(current, 0):
            node_status_map[node_id] = status

    for record in records:
        if not isinstance(record, dict):
            continue
        msg = _get_field(record, ["message", "msg"])
        parsed = _parse_msg_info(msg) if msg else {}
        action = _get_field(record, ["event.action", "action"])
        subtype = _get_field(record, ["fortinet.firewall.subtype", "subtype"])
        policy_id = _get_field(record, ["rule.id", "policyid"])
        record_status = _normalize_record_status(record)

        # 提取关联的用户名和目标 IP
        username = _get_field(record, ["source.user.name", "user", "username", "account"])
        target_ip = _get_field(record, ["destination.ip", "dstip", "remip"])
        user_id = f"user_{username}" if username and username not in ("-", "", "None", "null") else None
        action_id = f"action_{action.lower()}" if action else None
        subtype_id = f"subtype_{subtype.lower()}" if subtype else None

        # 上行账号安全事件：状态沿 user -> action -> subtype 传递。
        if user_id:
            _set_node_status(user_id, record_status)
            _set_node_status(action_id, record_status)
            _set_node_status(subtype_id, record_status)
        # 下行防火墙响应事件：状态沿 host -> action -> subtype/policy 传递。
        else:
            _set_node_status(target_ip, record_status)
            _set_node_status(action_id, record_status)
            _set_node_status(subtype_id, record_status)
            _set_node_status(str(policy_id) if policy_id else "", record_status)

        # --- 登录状态 ---
        if parsed.get("entity_type") == "user" and username:
            uid = f"user_{username}"
            if parsed.get("login_success") is True:
                _set_node_status(uid, "success")
            elif parsed.get("login_success") is False:
                _set_node_status(uid, "failed")

        # --- 删除/创建等操作状态 ---
        if parsed.get("entity_action") == "deleted":
            if parsed.get("entity_name"):
                _set_node_status(f"user_{parsed['entity_name']}", "success")

        # --- 防火墙动作 ---
        if action and action.lower() == "quarantine":
            # quarantine 动作本身标记为 blocked
            _set_node_status(f"action_{action.lower()}", "blocked")
            # 如果有关联的 policy，标记为 blocked
            policy_id = _get_field(record, ["rule.id", "policyid"])
            if policy_id:
                _set_node_status(str(policy_id), "blocked")
        elif action and action.lower() in ("accept", "pass", "allowed"):
            _set_node_status(f"action_{action.lower()}", "success")
            policy_id = _get_field(record, ["rule.id", "policyid"])
            if policy_id:
                _set_node_status(str(policy_id), "success")

        # --- host 节点状态继承 ---
        # 没有显式 status 时，仍兼容旧日志中的动作语义。
        if not record_status and not user_id and target_ip:
            if action and action.lower() in ("quarantine", "blocked"):
                _set_node_status(target_ip, "blocked")
            elif action and action.lower() in ("accept", "pass", "allowed"):
                _set_node_status(target_ip, "success")

    # ========== 1.6 为边计算状态（基于两端节点的状态）==========
    def _compute_edge_status(source_id, target_id, event_status: str = None):
        """根据两端节点的状态计算边的状态"""
        if event_status:
            return event_status
        src_status = node_status_map.get(source_id, "")
        tgt_status = node_status_map.get(target_id, "")
        
        # 边状态保留节点真实状态，不能把 blocked 改写成 failed。
        if src_status == "blocked" or tgt_status == "blocked":
            return "blocked"
        if src_status == "failed" or tgt_status == "failed":
            return "failed"
        if src_status == "success" or tgt_status == "success":
            return "success"
        return ""  # 未知状态

    # 计算每个节点的连接次数（用于 symbolSize）
    node_counts = {nid: info.get("count", 1) for nid, info in nodes_map.items()}
    max_count = max(node_counts.values()) if node_counts else 1

    # 将 nodes_map 转为列表，附加 status 字段
    nodes = []
    for nid, info in nodes_map.items():
        count = info.get("count", 1)
        symbol_size = _calc_symbol_size(count, max_count)

        nodes.append({
            "id": nid,
            "name": info.get("name", nid),
            "type": info["type"],
            "category": _type_to_category(info["type"]),
            "symbolSize": symbol_size,
            "value": count,
            "color": NODE_COLORS.get(info["type"], "#888888"),
            "symbol": NODE_SYMBOLS.get(info["type"], "circle"),
            # 附加额外属性
            "action_display": info.get("action_display", ""),
            "subtype": info.get("subtype", ""),
            "attack_types": info.get("attack_types", []),
            # 【新增】节点状态标记
            "status": node_status_map.get(nid, ""),
            # 【新增】时间标签（首次和最后出现时间）
            "first_seen": info.get("first_seen", ""),
            "last_seen": info.get("last_seen", ""),
        })

    # ========== 2. 构建边（关系）==========
    # 统一按 source + target + relation 去重。重复事件不会丢失状态：
    # blocked > failed > success > 空。
    edges = []
    edge_index = {}

    def _add_edge(source: str, target: str, relation: str, timestamp: str = "", edge_status: str = ""):
        if not source or not target:
            return
        key = (str(source), str(target), relation)
        existing = edge_index.get(key)
        if existing is None:
            edge = {
                "source": str(source),
                "target": str(target),
                "relation": relation,
                "timestamp": timestamp,
                "edge_status": edge_status or "",
            }
            edge_index[key] = edge
            edges.append(edge)
            return

        current_status = existing.get("edge_status", "")
        if status_priority.get(edge_status or "", 0) > status_priority.get(current_status, 0):
            existing["edge_status"] = edge_status
        if timestamp and (not existing.get("timestamp") or timestamp < existing["timestamp"]):
            existing["timestamp"] = timestamp

    # 按时间排序 records，确保边的代表时间稳定。
    sorted_records = sorted(
        [r for r in records if isinstance(r, dict)],
        key=lambda x: trace_timestamp_sort_key(record_trace_timestamp(x)),
    )

    for record in sorted_records:
        src_ip = _get_field(record, ["attack_src", "source.ip", "srcip"])
        target_ip = _get_field(record, ["destination.ip", "dstip", "remip"])
        username = _get_field(record, ["source.user.name", "user", "username", "account"])
        devname = _get_field(record, ["observer.name", "devname", "device"])
        policy_id = _get_field(record, ["rule.id", "policyid"])
        action = _get_field(record, ["event.action", "action"])
        ts = record_trace_timestamp(record)
        subtype = _get_field(record, ["fortinet.firewall.subtype", "subtype"])
        app = _get_field(record, ["application.name", "app"])
        msg = _get_field(record, ["message", "msg"])
        event_status = _normalize_record_status(record)

        if src_ip and target_ip and src_ip != target_ip:
            _add_edge(src_ip, target_ip, "connects_to", ts)

        user_id = f"user_{username}" if username and username not in ("-", "", "None", "null") else ""
        action_id = f"action_{action.lower()}" if action else ""
        subtype_id = f"subtype_{subtype.lower()}" if subtype else ""
        policy_id_str = str(policy_id) if policy_id and policy_id not in ("None", "null", "nan") else ""
        device_id = f"device_{devname}" if devname else ""

        if src_ip and user_id:
            _add_edge(src_ip, user_id, "uses_account", ts, event_status)
        if user_id and action_id:
            _add_edge(user_id, action_id, "performs_action", ts, event_status)
        if action_id and subtype_id:
            _add_edge(action_id, subtype_id, "has_subtype", ts, event_status)

        # 没有用户的记录视为下行响应链路。
        if not user_id and target_ip and action_id:
            _add_edge(target_ip, action_id, "responds_with", ts, event_status)
        if not user_id and action_id and policy_id_str:
            _add_edge(action_id, policy_id_str, "matched_policy", ts, event_status)
        if subtype_id and device_id:
            _add_edge(subtype_id, device_id, "targets_device", ts, event_status)
        if not user_id and device_id and policy_id_str:
            _add_edge(device_id, policy_id_str, "applies_policy", ts, event_status)

        if app and app not in ("None", "null", "nan") and action_id:
            app_id = f"app_{app.lower()}"
            _add_edge(action_id, app_id, "uses_app", ts, _compute_edge_status(action_id, app_id))

        if msg:
            msg_info = _parse_msg_info(msg)
            entity_type = msg_info.get("entity_type")
            entity_name = msg_info.get("entity_name")
            if entity_type == "user" and entity_name not in (None, "-", "", "None", "null") and action_id:
                _add_edge(
                    f"user_{entity_name}",
                    action_id,
                    "performs_action",
                    ts,
                    event_status,
                )
            elif entity_type == "process" and username and entity_name not in (None, "-", "", "None", "null"):
                _add_edge(f"user_{username}", entity_name, "executes", ts, event_status)
                if device_id:
                    _add_edge(entity_name, device_id, "runs_on", ts, event_status)

    # ========== 3. 统计信息 ==========
    type_dist = {}
    for node in nodes:
        t = node["type"]
        type_dist[t] = type_dist.get(t, 0) + 1

    relation_dist = {}
    for edge in edges:
        r = edge["relation"]
        relation_dist[r] = relation_dist.get(r, 0) + 1

    # 【新增】构建时间线（按时间排序的事件序列）
    timeline = []
    for i, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        ts = record_trace_timestamp(record)
        if not ts:
            continue
        # 提取该事件的关键信息
        event = {
            "index": i,
            "timestamp": ts,
            "action": _get_field(record, ["event.action", "action"]),
            "subtype": _get_field(record, ["fortinet.firewall.subtype", "subtype"]),
            "user": _get_field(record, ["source.user.name", "user", "username", "account"]),
            "devname": _get_field(record, ["observer.name", "devname", "device"]),
            "msg": _get_field(record, ["message", "msg"]),
            "policyid": _get_field(record, ["rule.id", "policyid"]),
        }
        # 提取动作中文显示
        if event["action"]:
            event["action_display"] = _parse_action_name(event["action"])
        timeline.append(event)
    # 按时间戳升序排序
    timeline.sort(key=lambda x: trace_timestamp_sort_key(x.get("timestamp", "")))

    # 计算时间线边界
    timeline_range = {}
    if timeline:
        timestamps = [e["timestamp"] for e in timeline if e.get("timestamp")]
        if timestamps:
            timeline_range = {
                "start": timestamps[0],
                "end": timestamps[-1],
                "event_count": len(timestamps),
            }

    # 【新增】构建攻击阶段分组
    attack_stages = _build_attack_stages(timeline, records)
    render_lines = _build_render_lines(records)

    return {
        "nodes": nodes,
        "edges": edges,
        "render_lines": render_lines,
        "timeline": timeline,            # 【新增】时间线事件序列（按时间排序）
        "timeline_range": timeline_range, # 【新增】时间范围
        "attack_stages": attack_stages,   # 【新增】攻击阶段分组
        "stats": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "type_distribution": type_dist,
            "relation_distribution": relation_dist,
        }
    }


def compact_graph_data(graph_data: dict) -> dict:
    """Expose only the render-line contract to the frontend."""
    if not isinstance(graph_data, dict):
        return {"render_lines": [], "stats": {}}

    render_lines = [
        dict(line) for line in graph_data.get("render_lines", [])
        if isinstance(line, dict)
    ]
    source_stats = graph_data.get("stats", {})
    stats = dict(source_stats) if isinstance(source_stats, dict) else {}
    stats.pop("node_count", None)
    stats.pop("edge_count", None)
    stats["event_count"] = sum(
        int(line.get("count", 0) or 0) for line in render_lines
    )
    stats["line_count"] = len(render_lines)
    stats["upper_line_count"] = sum(
        1 for line in render_lines if line.get("direction") == "upper"
    )
    stats["lower_line_count"] = sum(
        1 for line in render_lines if line.get("direction") == "lower"
    )
    return {
        "render_lines": render_lines,
        "stats": stats,
    }


# 通用溯源 PPL 模板
# 【重要】仅保留 IP 基础过滤 + 关键字段筛选。
# 时间条件由 build_ppl_query() 统一注入到 search 命令行。
# 【字段对齐】先按 ECS 字段生成 attack_src，再使用 attack_src 做溯源关联。
# host 节点来自 destination.ip，设备节点来自 observer.name。
IP_TRACE_PPL_TEMPLATE = f"""search source=`{INDEX_SOURCE_PATTERN}`
| eval attack_src = if(isnotnull(source.ip), cast(source.ip AS STRING), cast(destination.ip AS STRING))
| fields @timestamp, source.ip, destination.ip, attack_src, destination.port, event.action, event.reason, message, fortinet.firewall.subtype, fortinet.firewall.status, fortinet.firewall.type, fortinet.firewall.attack, source.user.name, observer.name, observer.serial_number, rule.id, rule.name, rule.description, url.original, @gid"""


# 溯源查询压缩配置
# 溯源数据通常较少，不需要额外压缩
IP_TRACE_COMPRESSION_CONFIG = CompressionConfig(
    threshold=IP_TRACE_COMPRESSION_THRESHOLD,
    max_tokens=COMPRESSION_MAX_TOKENS,
    max_return_data=IP_TRACE_MAX_RETURN_DATA,
)


def ip_trace_request(
    ip: str,
    start_time: str = None,
    end_time: str = None,
    gid: str = None,
) -> dict:
    """
    IP 溯源查询统一入口
    
    Args:
        ip: 攻击源 IP 地址
        start_time: 溯源起始时间（攻击时间 -5 分钟）
        end_time: 溯源结束时间（攻击时间）
        gid: 设备组 ID（可选）
    
    Returns:
        dict: 包含溯源信息的结构化数据
    """
    if not ip:
        return {
            "trace_info": {
                "status": "error",
                "message": "未提供攻击 IP，无法执行溯源查询"
            }
        }
    
    # 构造 PPL 模板（已无占位符，由 build_ppl_query 统一处理 IP 过滤和时间条件）
    ppl_template = IP_TRACE_PPL_TEMPLATE

    # 执行查询
    # The query builder accepts local naive timestamps, while trace metadata
    # keeps the explicit +08:00 ISO window for the frontend and logs.
    query_start_time = trace_query_time(start_time) if start_time else start_time
    query_end_time = trace_query_time(end_time) if end_time else end_time
    executor = ToolExecutor(
        tool_name="ip_trace",
        ppl_template=ppl_template,
        user_problem=f"IP 溯源查询：{ip}",
        start_time=query_start_time,
        end_time=query_end_time,
        filter_ip=ip,  # 同时传入 filter_ip 以便 ToolExecutor 处理
        gid=gid,
        compression_config=IP_TRACE_COMPRESSION_CONFIG,
        ip_field=["source.ip", "destination.ip"],  # 同时过滤源/目标 IP，捕获上行和下行记录
        cache_version="v3",
    )
    
    result = executor.execute()
    
    # 构造返回结构
    return _build_trace_result(result, ip, start_time, end_time)


def build_trace_window(attack_time: str, pre_minutes: int = 5) -> dict:
    """
    根据攻击时间构建溯源时间窗口（前 N 分钟）
    
    Args:
        attack_time: 攻击时间，格式 YYYY-MM-DD HH:MM:SS 或 YYYY-MM-DD
        pre_minutes: 追溯前多少分钟，默认 5
    
    Returns:
        dict: {"start_time": "...", "end_time": "..."}
    """
    attack_datetime = parse_trace_timestamp(attack_time)
    if attack_datetime is None:
        raise ValueError(f"invalid attack timestamp: {attack_time}")
    
    # 计算时间窗口
    start_time = attack_datetime - timedelta(minutes=pre_minutes)
    end_time = attack_datetime
    
    return {
        "start_time": start_time.isoformat(timespec="seconds"),
        "end_time": end_time.isoformat(timespec="seconds"),
    }


def build_trace_window_range(
    first_time: str,
    last_time: str,
    pre_minutes: int = 30,
    post_minutes: int = 30,
) -> dict:
    """Build a trace window around the complete observed event range.

    Automatic tracing must cover the full observed campaign for one IP rather
    than stopping at its earliest event. Callers pass timestamps already
    normalized to their query timezone.
    """
    first = parse_trace_timestamp(first_time)
    last = parse_trace_timestamp(last_time)
    if first is None or last is None:
        raise ValueError(f"invalid trace range: {first_time} ~ {last_time}")
    if last < first:
        first, last = last, first
    return {
        "start_time": (first - timedelta(minutes=pre_minutes)).isoformat(timespec="seconds"),
        "end_time": (last + timedelta(minutes=post_minutes)).isoformat(timespec="seconds"),
    }


def is_full_day_range(start_time: str, end_time: str) -> bool:
    """Return whether the caller explicitly requested one complete calendar day."""
    start = str(start_time or "").strip()
    end = str(end_time or "").strip()
    if not start or not end:
        return False
    start_date = start[:10]
    end_date = end[:10]
    if start_date != end_date:
        return False
    return (
        start in {start_date, f"{start_date} 00:00:00", f"{start_date}T00:00:00"}
        and end in {end_date, f"{end_date} 23:59:59", f"{end_date}T23:59:59"}
    )


def _build_trace_result(raw_result: str, ip: str, start_time: str, end_time: str) -> dict:
    """
    构造溯源结果的结构化格式

    Args:
        raw_result: ToolExecutor 返回的原始结果
        ip: 被溯源的 IP
        start_time: 溯源起始时间
        end_time: 溯源结束时间

    Returns:
        dict: 标准化溯源数据结构
    """
    # 解析原始结果，提取 data 数组用于构建图数据
    graph_data = {}
    raw_data = {}
    try:
        raw_data = json.loads(raw_result) if isinstance(raw_result, str) else raw_result
        logger.info(f"[build_trace_result] raw_result 前 500 字符: {raw_result[:500]}")
        logger.info(f"[build_trace_result] raw_data keys: {list(raw_data.keys()) if isinstance(raw_data, dict) else 'N/A'}")
        logger.info(f"[build_trace_result] raw_data.get('data') 类型: {type(raw_data.get('data'))}, 长度: {len(raw_data.get('data', [])) if isinstance(raw_data.get('data'), list) else 'N/A'}")
        
        if raw_data and isinstance(raw_data, dict) and raw_data.get("data"):
            # 【修复】构建图前先清洗 NaN/Infinity
            raw_data = _sanitize_nan(raw_data)
            for record in raw_data.get("data", []):
                if isinstance(record, dict):
                    timestamp_cst = record_trace_timestamp(record)
                    if timestamp_cst:
                        record["@timestamp_cst"] = timestamp_cst
            graph_data = compact_graph_data(build_graph_data(raw_data))
            logger.info(
                "[build_trace_result] graph_data 构建结果: "
                f"render_lines={len(graph_data.get('render_lines', []))}"
            )
        else:
            logger.warning(f"[build_trace_result] raw_data 为空或 data 字段缺失/为空")
    except Exception as e:
        logger.warning(f"[build_trace_result] 构建图数据失败：{e}", exc_info=True)

    http_status = raw_data.get("http_status", 0) if isinstance(raw_data, dict) else 0
    error = raw_data.get("error", "") if isinstance(raw_data, dict) else ""
    status = "success" if http_status == 200 and not error else "error"

    # 【修复】整个返回结构清洗 NaN
    return _sanitize_nan({
        "trace_info": {
            "ip": ip,
            "time_window": f"{start_time} ~ {end_time}",
            "start_time": start_time,
            "end_time": end_time,
            "activities": raw_result,
            "status": status,
            "error": error,
            "graph_data": graph_data,
        }
    })


class IpTraceInput(BaseModel):
    """IP 溯源工具输入参数模型"""
    ip: str = Field(description="要溯源的攻击 IP 地址（必填）")
    start_time: str = Field(default=None, description="溯源起始时间，格式：YYYY-MM-DD HH:MM:SS")
    end_time: str = Field(default=None, description="溯源结束时间，格式：YYYY-MM-DD HH:MM:SS")
    gid: str = Field(default=None, description="设备组 ID（可选）")
