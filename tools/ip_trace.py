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
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
from tools.tool_base import ToolExecutor, CompressionConfig

logger = logging.getLogger(__name__)

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


def _get_field(record: dict, field_names: list, default: str = "") -> str:
    """从记录中安全获取字段值"""
    for name in field_names:
        val = record.get(name, default)
        if val and val != default:
            return str(val)
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
    """从 action 字段解析友好的动作名称"""
    action_map = {
        "accept": "允许",
        "deny": "拒绝",
        "blocked": "阻断",
        "pass": "通过",
        "log": "记录",
        "login": "登录",
        "logout": "登出",
        "delete": "删除",
        "create": "创建",
        "update": "更新",
        "modify": "修改",
    }
    action_lower = action.lower() if action else ""
    return action_map.get(action_lower, action or "未知动作")


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

    # 按时间排序（使用 @timestamp_cst 字段）
    sorted_records = sorted(records, key=lambda x: x.get("@timestamp_cst", ""))

    for record in sorted_records:
        # 直接从原始记录中解析 msg 字段
        msg = record.get("msg", "") or ""
        parsed = _parse_msg_info(msg)
        
        # 【增强】如果 msg 为空，尝试从 action 字段补充防火墙动作
        action = record.get("action", "") or ""
        if not msg and action:
            action_lower = action.lower()
            if "quarantin" in action_lower:
                parsed["firewall_action"] = "quarantined"
            elif "block" in action_lower or "deny" in action_lower:
                parsed["firewall_action"] = "blocked"

        # 构建事件信息（使用 timeline 中的字段）
        event_info = {
            "timestamp": record.get("@timestamp_cst", ""),
            "message": msg,
            "user": record.get("user", "") or record.get("username", "") or "",
            "action": record.get("action", ""),
            "subtype": record.get("subtype", ""),
            "attacker": record.get("attack_src", "") or record.get("srcip", ""),
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
                stage["key_details"]["action"] = parsed.get("firewall_action")
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
    ts = record.get("@timestamp_cst", "") or ""

    if nid in nodes_map:
        # 已存在，增加计数
        nodes_map[nid]["count"] = nodes_map[nid].get("count", 1) + 1
        # 合并攻击类型（使用 Fortigate 索引中实际存在的字段）
        attack_type = _get_field(record, ["type", "subtype", "msg"])
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
            "attack_types": [_get_field(record, ["type", "subtype", "msg"])],
            "first_seen": ts,   # 【新增】首次出现时间
            "last_seen": ts,    # 【新增】最后出现时间
            "timestamps": [ts] if ts else [],  # 【新增】所有时间戳
        }


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
        return {"nodes": [], "edges": [], "stats": {"node_count": 0, "edge_count": 0, "type_distribution": {}}}

    # 获取实际数据（非压缩时取 data 数组）
    records = raw_data.get("data", [])
    if not records:
        logger.warning("[build_graph_data] 数据数组为空")
        return {"nodes": [], "edges": [], "stats": {"node_count": 0, "edge_count": 0, "type_distribution": {}}}

    # ========== 1. 构建节点去重映射 ==========
    nodes_map = {}

    for record in records:
        if not isinstance(record, dict):
            continue

        # ===== 提取基础节点 =====
        # 来源 IP（攻击者）
        src_ip = _get_field(record, ["srcip"])
        if src_ip:
            _add_node(nodes_map, src_ip, "attacker", record, "ip")

        # 远程 IP / 目标 IP
        rem_ip = _get_field(record, ["remip"])
        dst_ip = _get_field(record, ["dstip"])
        target_ip = rem_ip or dst_ip
        if target_ip:
            _add_node(nodes_map, target_ip, "host", record, "ip")

        # 用户名
        username = _get_field(record, ["user", "username", "account"])
        if username and username not in ("-", "", "None", "null", "nan", "N/A"):
            _add_node(nodes_map, username, "user", record, "user", username)

        # 设备名
        devname = _get_field(record, ["devname", "device"])
        if devname:
            _add_node(nodes_map, devname, "oss", record, "device", devname)

        # ===== 提取策略节点 =====
        policy_id = _get_field(record, ["policyid"])
        policy_name = _get_field(record, ["policyname"])
        if policy_id and policy_id not in ("", "None", "null", "nan"):
            policy_display = policy_name if policy_name else f"Policy {policy_id}"
            policy_id_str = str(policy_id)
            _add_node(nodes_map, policy_id_str, "policy", record, "policy", policy_display)

        # ===== 提取动作节点 =====
        action = _get_field(record, ["action"])
        if action and action not in ("", "None", "null", "nan"):
            action_display = _parse_action_name(action)
            action_id = f"action_{action.lower()}"
            _add_node(nodes_map, action_id, "action", record, "action", action_display)

        # ===== 提取子类型节点 =====
        subtype = _get_field(record, ["subtype"])
        if subtype and subtype not in ("", "None", "null", "nan"):
            subtype_id = f"subtype_{subtype.lower()}"
            _add_node(nodes_map, subtype_id, "subtype", record, "subtype", subtype)

        # ===== 提取应用节点 =====
        app = _get_field(record, ["app"])
        if app and app not in ("", "None", "null", "nan"):
            app_id = f"app_{app.lower()}"
            _add_node(nodes_map, app_id, "app", record, "app", app)

        # ===== 从 msg 解析实体节点 =====
        msg = _get_field(record, ["msg"])
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
    # 遍历所有 records，根据 msg 解析结果给节点打上状态标签
    node_status_map = {}  # node_id -> status
    for record in records:
        if not isinstance(record, dict):
            continue
        msg = _get_field(record, ["msg"])
        parsed = _parse_msg_info(msg) if msg else {}
        action = _get_field(record, ["action"])

        # 提取关联的用户名和目标 IP
        username = _get_field(record, ["user", "username", "account"])
        target_ip = _get_field(record, ["remip"]) or _get_field(record, ["dstip"])

        # --- 登录状态 ---
        if parsed.get("entity_type") == "user" and username:
            uid = f"user_{username}"
            if parsed.get("login_success") is True:
                node_status_map[uid] = "success"
            elif parsed.get("login_success") is False:
                node_status_map[uid] = "failed"

        # --- 删除/创建等操作状态 ---
        if parsed.get("entity_action") == "deleted":
            if parsed.get("entity_name"):
                node_status_map[f"user_{parsed['entity_name']}"] = "success"

        # --- 防火墙动作 ---
        if action and action.lower() == "quarantine":
            # quarantine 动作本身标记为 blocked
            node_status_map[f"action_{action.lower()}"] = "blocked"
            # 如果有关联的 policy，标记为 blocked
            policy_id = _get_field(record, ["policyid"])
            if policy_id:
                node_status_map[str(policy_id)] = "blocked"
        elif action and action.lower() in ("accept", "pass", "allowed"):
            node_status_map[f"action_{action.lower()}"] = "allowed"
            policy_id = _get_field(record, ["policyid"])
            if policy_id:
                node_status_map[str(policy_id)] = "allowed"

        # --- host 节点状态继承 ---
        if target_ip and target_ip in node_status_map:
            node_status_map[target_ip] = node_status_map[target_ip]
        elif target_ip and not node_status_map.get(target_ip):
            # 如果 target_ip 没有直接状态，但有关联的 action，也标记
            if action and action.lower() in ("quarantine", "blocked"):
                node_status_map[target_ip] = "blocked"
            elif action and action.lower() in ("accept", "pass", "allowed"):
                node_status_map[target_ip] = "allowed"

    # ========== 1.6 为边计算状态（基于两端节点的状态）==========
    def _compute_edge_status(source_id, target_id):
        """根据两端节点的状态计算边的状态"""
        src_status = node_status_map.get(source_id, "")
        tgt_status = node_status_map.get(target_id, "")
        
        # 如果任一节点是 blocked/failed，边标记为 failed
        if src_status in ("failed", "blocked") or tgt_status in ("failed", "blocked"):
            return "failed"
        if src_status == "allowed" or tgt_status == "allowed":
            return "allowed"
        if src_status == "success" and tgt_status == "success":
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
    # 核心思路：按拓扑层级构建边，而不是从攻击者放射状连接所有节点
    # 层级：attacker -> host -> device/user -> action/subtype/policy
    edges = []
    edge_set = set()  # 防止重复边

    # 按时间排序 records，确保边的顺序符合时间线
    sorted_records = sorted(
        [r for r in records if isinstance(r, dict)],
        key=lambda x: x.get("@timestamp_cst", "") or ""
    )

    for record in sorted_records:
        src_ip = _get_field(record, ["srcip"])
        rem_ip = _get_field(record, ["remip"])
        dst_ip = _get_field(record, ["dstip"])
        target_ip = rem_ip or dst_ip
        username = _get_field(record, ["user", "username", "account"])
        devname = _get_field(record, ["devname", "device"])
        policy_id = _get_field(record, ["policyid"])
        action = _get_field(record, ["action"])
        ts = record.get("@timestamp_cst", "") or ""
        subtype = _get_field(record, ["subtype"])
        app = _get_field(record, ["app"])
        msg = _get_field(record, ["msg"])

        # --- 第 1 层：IP 连接（攻击者 -> 目标） ---
        if src_ip and target_ip and src_ip != target_ip:
            edge_key = (src_ip, target_ip)
            if edge_key not in edge_set:
                edge_set.add(edge_key)
                edges.append({
                    "source": src_ip,
                    "target": target_ip,
                    "relation": "connects_to",
                    "timestamp": ts,
                    # 【新增】边状态
                    "edge_status": _compute_edge_status(src_ip, target_ip),
                })

        # --- 第 2 层：IP 与设备的关系 ---
        if devname:
            device_id = f"device_{devname}"
            # 攻击者 -> 设备（IP 访问设备）
            if src_ip:
                edge_key = (src_ip, device_id)
                if edge_key not in edge_set:
                    edge_set.add(edge_key)
                    edges.append({
                        "source": src_ip,
                        "target": device_id,
                        "relation": "accesses_device",
                        "timestamp": ts,
                        "edge_status": _compute_edge_status(src_ip, device_id),
                    })
            # 目标 IP -> 设备（目标 IP 所属设备）
            if target_ip:
                edge_key = (target_ip, device_id)
                if edge_key not in edge_set:
                    edge_set.add(edge_key)
                    edges.append({
                        "source": target_ip,
                        "target": device_id,
                        "relation": "belongs_to",
                        "timestamp": ts,
                        "edge_status": _compute_edge_status(target_ip, device_id),
                    })

        # --- 第 3 层：用户与设备/动作的关系 ---
        user_id = f"user_{username}" if username and username not in ("-", "", "None", "null") else None
        
        # 攻击者 -> 用户（IP 上的操作账户）
        if src_ip and user_id:
            edge_key = (src_ip, user_id)
            if edge_key not in edge_set:
                edge_set.add(edge_key)
                edges.append({
                    "source": src_ip,
                    "target": user_id,
                    "relation": "uses_account",
                    "timestamp": ts,
                    "edge_status": _compute_edge_status(src_ip, user_id),
                })

        # 用户 -> 设备（用户操作的设备）
        if user_id and devname:
            device_id = f"device_{devname}"
            edge_key = (user_id, device_id)
            if edge_key not in edge_set:
                edge_set.add(edge_key)
                edges.append({
                    "source": user_id,
                    "target": device_id,
                    "relation": "operates_on",
                    "timestamp": ts,
                    "edge_status": _compute_edge_status(user_id, device_id),
                })

        # 用户 -> 动作（用户执行的动作）
        if user_id and action:
            action_id = f"action_{action.lower()}"
            edge_key = (user_id, action_id)
            if edge_key not in edge_set:
                edge_set.add(edge_key)
                edges.append({
                    "source": user_id,
                    "target": action_id,
                    "relation": "performs_action",
                    "timestamp": ts,
                    "edge_status": _compute_edge_status(user_id, action_id),
                })

        # --- 第 4 层：动作 -> 子类型 / 策略的关系 ---
        if action and subtype:
            action_id = f"action_{action.lower()}"
            subtype_id = f"subtype_{subtype.lower()}"
            edge_key = (action_id, subtype_id)
            if edge_key not in edge_set:
                edge_set.add(edge_key)
                edges.append({
                    "source": action_id,
                    "target": subtype_id,
                    "relation": "has_subtype",
                    "timestamp": ts,
                    "edge_status": _compute_edge_status(action_id, subtype_id),
                })

        if action and policy_id and policy_id not in ("", "None", "null", "nan"):
            action_id = f"action_{action.lower()}"
            policy_id_str = str(policy_id)
            edge_key = (action_id, policy_id_str)
            if edge_key not in edge_set:
                edge_set.add(edge_key)
                edges.append({
                    "source": action_id,
                    "target": policy_id_str,
                    "relation": "matched_policy",
                    "timestamp": ts,
                    "edge_status": _compute_edge_status(action_id, policy_id_str),
                })
                edges.append({
                    "source": action_id,
                    "target": policy_id_str,
                    "relation": "matched_policy",
                    "timestamp": ts,
                })

        if devname and policy_id and policy_id not in ("", "None", "null", "nan"):
            device_id = f"device_{devname}"
            policy_id_str = str(policy_id)
            edge_key = (device_id, policy_id_str)
            if edge_key not in edge_set:
                edge_set.add(edge_key)
                edges.append({
                    "source": device_id,
                    "target": policy_id_str,
                    "relation": "applies_policy",
                    "timestamp": ts,
                    "edge_status": _compute_edge_status(device_id, policy_id_str),
                })

        # --- 应用关系（可选，不强制连接到攻击者） ---
        if app and app not in ("", "None", "null", "nan") and action:
            app_id = f"app_{app.lower()}"
            action_id = f"action_{action.lower()}"
            edge_key = (action_id, app_id)
            if edge_key not in edge_set:
                edge_set.add(edge_key)
                edges.append({
                    "source": action_id,
                    "target": app_id,
                    "relation": "uses_app",
                    "timestamp": ts,
                    "edge_status": _compute_edge_status(action_id, app_id),
                })

        # --- 从 msg 解析实体关系（增强版） ---
        if msg:
            msg_info = _parse_msg_info(msg)
            if msg_info["entity_type"] and msg_info["entity_name"]:
                entity_type = msg_info["entity_type"]
                entity_name = msg_info["entity_name"]

                # 如果解析出的是用户，添加到用户 -> 动作 的关系中
                if entity_type == "user" and entity_name not in ("-", "", "None", "null"):
                    entity_id = f"user_{entity_name}"
                    # 用户 -> 设备
                    if user_id and devname:
                        device_id = f"device_{devname}"
                        edge_key = (entity_id, device_id)
                        if edge_key not in edge_set:
                            edge_set.add(edge_key)
                            edges.append({
                                "source": entity_id,
                                "target": device_id,
                                "relation": "operates_on",
                                "timestamp": ts,
                                "edge_status": _compute_edge_status(entity_id, device_id),
                            })
                    # 用户 -> 动作
                    if action:
                        action_id = f"action_{action.lower()}"
                        edge_key = (entity_id, action_id)
                        if edge_key not in edge_set:
                            edge_set.add(edge_key)
                            edges.append({
                                "source": entity_id,
                                "target": action_id,
                                "relation": "performs_action",
                                "timestamp": ts,
                                "edge_status": _compute_edge_status(entity_id, action_id),
                            })

                elif entity_type == "process" and username and entity_name not in ("-", "", "None", "null"):
                    # 用户 -> 进程
                    user_id_current = f"user_{username}"
                    entity_id = entity_name
                    edge_key = (user_id_current, entity_id)
                    if edge_key not in edge_set:
                        edge_set.add(edge_key)
                        edges.append({
                            "source": user_id_current,
                            "target": entity_id,
                            "relation": "executes",
                            "timestamp": ts,
                            "edge_status": _compute_edge_status(user_id_current, entity_id),
                        })
                    # 进程 -> 设备
                    if devname:
                        device_id = f"device_{devname}"
                        edge_key = (entity_id, device_id)
                        if edge_key not in edge_set:
                            edge_set.add(edge_key)
                            edges.append({
                                "source": entity_id,
                                "target": device_id,
                                "relation": "runs_on",
                                "timestamp": ts,
                                "edge_status": _compute_edge_status(entity_id, device_id),
                            })

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
        ts = record.get("@timestamp_cst", "")
        if not ts:
            continue
        # 提取该事件的关键信息
        event = {
            "index": i,
            "timestamp": ts,
            "action": _get_field(record, ["action"]),
            "subtype": _get_field(record, ["subtype"]),
            "user": _get_field(record, ["user", "username", "account"]),
            "devname": _get_field(record, ["devname", "device"]),
            "msg": _get_field(record, ["msg"]),
            "policyid": _get_field(record, ["policyid"]),
        }
        # 提取动作中文显示
        if event["action"]:
            event["action_display"] = _parse_action_name(event["action"])
        timeline.append(event)
    # 按时间戳升序排序
    timeline.sort(key=lambda x: x.get("timestamp", ""))

    # 计算时间线边界
    timeline_range = {}
    if timeline:
        timestamps = [e["timestamp"] for e in timeline if e.get("timestamp")]
        if timestamps:
            timeline_range = {
                "start": min(timestamps),
                "end": max(timestamps),
                "event_count": len(timestamps),
            }

    # 【新增】构建攻击阶段分组
    attack_stages = _build_attack_stages(timeline, records)

    return {
        "nodes": nodes,
        "edges": edges,
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


# 通用溯源 PPL 模板
# 【重要】仅保留 IP 基础过滤 + 关键字段筛选。
# 时间条件由 build_ppl_query() 统一注入到 search 命令行实现索引剪枝。
# 【字段对齐】必须与 brute_force.py:40 保持一致，Fortigate 索引中实际存在这些字段：
#   @timestamp_cst, user, attack_src, srcip, remip, action, reason, msg, subtype, @gid, devname, policyid
# 【删除】以下字段在 Fortigate 索引中不存在，OpenSearch 会报 IllegalArgumentException：
#   app, policyname, hostname, srcport, proto, service, dstport
IP_TRACE_PPL_TEMPLATE = """search source=`log_g*_fortigate_firewall-*`
| fields @timestamp_cst, srcip, dstip, remip, action, reason, msg, subtype, type, user, devname, policyid, @gid, attack_src"""


# 溯源查询压缩配置
# 溯源数据通常较少，不需要额外压缩
IP_TRACE_COMPRESSION_CONFIG = CompressionConfig(
    threshold=15,
    max_tokens=2000,
    max_return_data=5,
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
    executor = ToolExecutor(
        tool_name="ip_trace",
        ppl_template=ppl_template,
        user_problem=f"IP 溯源查询：{ip}",
        start_time=start_time,
        end_time=end_time,
        filter_ip=ip,  # 同时传入 filter_ip 以便 ToolExecutor 处理
        gid=gid,
        compression_config=IP_TRACE_COMPRESSION_CONFIG,
        ip_field="srcip",  # 溯源使用 srcip 作为主字段
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
    try:
        # 尝试解析带时分秒的格式
        attack_datetime = datetime.strptime(attack_time, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        try:
            # 尝试解析仅日期格式
            attack_datetime = datetime.strptime(attack_time, '%Y-%m-%d')
            attack_datetime = attack_datetime.replace(hour=23, minute=59, second=59)
        except ValueError:
            # 使用当前时间
            attack_datetime = datetime.now()
    
    # 计算时间窗口
    start_time = attack_datetime - timedelta(minutes=pre_minutes)
    end_time = attack_datetime
    
    return {
        "start_time": start_time.strftime('%Y-%m-%d %H:%M:%S'),
        "end_time": end_time.strftime('%Y-%m-%d %H:%M:%S'),
    }


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
    try:
        raw_data = json.loads(raw_result) if isinstance(raw_result, str) else raw_result
        if raw_data and isinstance(raw_data, dict) and raw_data.get("data"):
            # 【修复】构建图前先清洗 NaN/Infinity
            raw_data = _sanitize_nan(raw_data)
            graph_data = build_graph_data(raw_data)
    except Exception as e:
        logger.warning(f"[build_trace_result] 构建图数据失败：{e}")

    # 【修复】整个返回结构清洗 NaN
    return _sanitize_nan({
        "trace_info": {
            "ip": ip,
            "time_window": f"{start_time} ~ {end_time}",
            "start_time": start_time,
            "end_time": end_time,
            "activities": raw_result,
            "status": "success",
            "graph_data": graph_data,
        }
    })


class IpTraceInput(BaseModel):
    """IP 溯源工具输入参数模型"""
    ip: str = Field(description="要溯源的攻击 IP 地址（必填）")
    start_time: str = Field(default=None, description="溯源起始时间，格式：YYYY-MM-DD HH:MM:SS")
    end_time: str = Field(default=None, description="溯源结束时间，格式：YYYY-MM-DD HH:MM:SS")
    gid: str = Field(default=None, description="设备组 ID（可选）")
