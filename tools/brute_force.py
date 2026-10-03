# -*- coding: utf-8 -*-
"""
暴力破解检测工具
用于查询 Fortigate 防火墙日志中的登录失败记录，检测暴力破解攻击

【压缩配置】（与其他工具统一）
- 压缩触发阈值：>= 15 条 或 问题包含统计类关键词
- max_tokens: 2000
- 返回数据条数：5 条
- compressed_count = original_count（压缩不改变实际记录数）
- 始终生成统计摘要

【Redis 缓存】
- 缓存 TTL：300 秒（5 分钟）
- 使用统一的 ToolCacheManager

【IP 溯源功能】
- 暴力破解检测完成后，自动提取攻击源 IP
- 按累计占比≥80% 原则选取最多 3 个 IP
- 对每个 IP 查询完整事件范围前后各 30 分钟的活动链路
"""
import json
import logging
from typing import Optional
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
from tools.tool_base import ToolExecutor, CompressionConfig, calculate_ip_stats
from tools.index_config import INDEX_SOURCE_PATTERN
from config import COMPRESSION_MAX_RETURN_DATA, COMPRESSION_MAX_TOKENS, COMPRESSION_THRESHOLD
from tools.ip_trace import (
    ip_trace_request,
    build_trace_window_range,
    normalize_trace_timestamp,
)


def _normalize_attack_time(timestamp_str: str) -> str:
    """将攻击时间规范为东八区时间，避免对已转换的时间重复加 8 小时。"""
    normalized = normalize_trace_timestamp(timestamp_str)
    if normalized:
        return normalized
    return ""

logger = logging.getLogger(__name__)


# PPL 查询模板
# 【字段适配】当前 Pipeline 将状态保存在 fortinet.firewall.status；subtype 仍保留在 fortinet.firewall.subtype。
PPL_TEMPLATE = f"""search source=`{INDEX_SOURCE_PATTERN}`

| where (fortinet.firewall.subtype='system' and event.action='login' and fortinet.firewall.status='failed') OR (fortinet.firewall.subtype='vpn' and message='SSL user failed to logged in')
| where event.reason != 'ip_blocked'
| where source.ip != '218.92.0.39'
| eval attack_src = if(isnotnull(source.ip), cast(source.ip AS STRING), cast(destination.ip AS STRING))
| fields @timestamp, source.user.name, attack_src, source.ip, destination.ip, event.action, event.reason, message, fortinet.firewall.subtype, fortinet.firewall.status, @gid, observer.name, rule.id
| sort - @timestamp"""

# 压缩配置（与其他工具统一）
COMPRESSION_CONFIG = CompressionConfig(
    threshold=COMPRESSION_THRESHOLD,
    max_tokens=COMPRESSION_MAX_TOKENS,
    max_return_data=COMPRESSION_MAX_RETURN_DATA,
)

# 自动溯源的 IP 上限。累计覆盖率规则仍然生效，但最多只对前三个
# 排名 IP 发起 ip_trace_request，保证文字 Top3 与图数据使用同一列表。
MAX_TRACE_IPS = 3
COVERAGE_THRESHOLD = 0.8


def _record_field(record: dict, *names: str):
    """Read a flat or dotted field without changing the query field mapping."""
    if not isinstance(record, dict):
        return None
    for name in names:
        if name in record and record[name] not in (None, ""):
            return record[name]
        value = record
        for part in name.split("."):
            if not isinstance(value, dict) or part not in value:
                value = None
                break
            value = value[part]
        if value not in (None, ""):
            return value
    return None


def _is_brute_force_detection_hit(record: dict) -> bool:
    """Return whether a record satisfies the brute-force PPL condition.

    ToolExecutor normally returns only records matching ``PPL_TEMPLATE``.  The
    field-less fallback keeps synthetic/legacy unit fixtures compatible while
    still classifying mixed trace records accurately when the condition fields
    are present.
    """
    if not isinstance(record, dict):
        return False
    subtype = _record_field(record, "fortinet.firewall.subtype", "subtype")
    action = _record_field(record, "event.action", "action")
    status = _record_field(record, "fortinet.firewall.status", "status")
    message = _record_field(record, "message", "msg")
    reason = _record_field(record, "event.reason", "reason")
    source_ip = _record_field(record, "source.ip", "srcip")
    condition_fields_present = any(
        value not in (None, "")
        for value in (subtype, action, status, message, reason, source_ip)
    )
    if not condition_fields_present:
        return True
    if str(reason or "").strip().lower() == "ip_blocked":
        return False
    if str(source_ip or "").strip() == "218.92.0.39":
        return False
    system_login_failed = (
        str(subtype or "").strip().lower() == "system"
        and str(action or "").strip().lower() == "login"
        and str(status or "").strip().lower() == "failed"
    )
    vpn_login_failed = (
        str(subtype or "").strip().lower() == "vpn"
        and str(message or "").strip() == "SSL user failed to logged in"
    )
    return system_login_failed or vpn_login_failed


def _ip_attack_count(raw_result: dict, target_ip: str) -> int:
    """Return the complete brute-force hit count for one selected IP."""
    stats = raw_result.get("ip_stats") if isinstance(raw_result, dict) else None
    if isinstance(stats, list):
        for item in stats:
            if isinstance(item, dict) and str(item.get("ip")) == str(target_ip):
                try:
                    return int(item.get("count", 0) or 0)
                except (TypeError, ValueError):
                    return 0
    count = 0
    for record in (raw_result.get("data", []) if isinstance(raw_result, dict) else []):
        if not _is_brute_force_detection_hit(record):
            continue
        ip = _record_field(record, "attack_src", "source.ip", "srcip", "destination.ip")
        if str(ip) == str(target_ip):
            count += 1
    return count


def _calculate_ip_priority(raw_result: dict) -> list:
    """
    根据暴力破解命中次数计算 IP 优先级，选取累计占比≥80% 的 IP（最多 3 个）。

    ``ip_stats`` 是查询结果生成的完整统计时优先使用它，避免在未来
    返回样本数据时误用 ``data[:N]`` 推断排名；没有统计字段时才从原始
    命中记录回退计算。
    """
    try:
        data = raw_result.get("data", [])
        logger.info(f"[IP Priority] 开始计算 IP 优先级，原始数据条数: {len(data)}")

        # 统计字段由工具查询结果提供，顺序就是报告 Top3 的稳定顺序。
        ip_counts = {}
        stats = raw_result.get("ip_stats")
        if isinstance(stats, list):
            for item in stats:
                if not isinstance(item, dict):
                    continue
                ip = item.get("ip")
                try:
                    count = int(item.get("count", 0) or 0)
                except (TypeError, ValueError):
                    count = 0
                if ip and count > 0:
                    ip_counts[str(ip)] = count

        if not ip_counts:
            if not data:
                logger.warning("[IP Priority] 未检测到数据，跳过 IP 优先级计算")
                return []
            # ToolExecutor 的 brute-force 结果本应已经是 PPL 命中记录；
            # 这里仍按条件判定，避免混入溯源上下文记录。
            for record in data:
                if not _is_brute_force_detection_hit(record):
                    continue
                ip = _record_field(record, "attack_src", "source.ip", "srcip", "destination.ip")
                if ip:
                    ip = str(ip)
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        logger.info(f"[IP Priority] 统计到的 IP 分布: {ip_counts}")
        
        if not ip_counts:
            logger.warning("[IP Priority] 未找到有效的 IP 字段")
            return []
        
        # 按次数降序排序；Python 的稳定排序保留统计结果中的并列顺序。
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

        # 保留累计覆盖率规则，但最多只选前三个 IP。
        total = sum(ip_counts.values())
        cumulative = 0
        trace_ips = []

        logger.info(f"[IP Priority] 数据统计: 共 {len(sorted_ips)} 个 unique IP，总攻击 {total} 次")
        for ip, count in sorted_ips:
            cumulative += count / total
            trace_ips.append(ip)
            logger.info(f"[IP Priority] 已收录 IP {ip} (累计占比: {cumulative:.2%})")
            # 达到 80% 阈值 OR 达到前三个上限即停止。
            if cumulative >= COVERAGE_THRESHOLD or len(trace_ips) >= MAX_TRACE_IPS:
                logger.info(f"[IP Priority] 达到阈值 (≥80% 或 ≥{MAX_TRACE_IPS}个)，停止选取")
                break

        logger.info(f"[IP Priority] 最终选取的溯源 IP 列表: {trace_ips}")
        return trace_ips
        
    except Exception as e:
        logger.error(f"[IP Priority] 计算 IP 优先级失败: {e}", exc_info=True)
        return []


def _get_first_attack_time(raw_result: dict) -> str | None:
    """从暴力破解结果中提取最早的攻击时间（UTC → CST 转换）"""
    try:
        data = raw_result.get("data", [])
        if not data:
            logger.warning("[Trace] 数据为空，没有有效攻击时间")
            return None

        timestamps = []
        for record in data:
            if not _is_brute_force_detection_hit(record):
                continue
            attack_time = record.get("@timestamp_cst") or record.get("@timestamp")
            normalized_time = _normalize_attack_time(attack_time) if attack_time else ""
            if normalized_time:
                timestamps.append((normalized_time, attack_time))

        if timestamps:
            normalized_time, attack_time = min(timestamps, key=lambda item: item[0])
            logger.info(f"[Trace] 提取到最早攻击时间: {attack_time} → {normalized_time}")
            return normalized_time

        logger.warning("[Trace] 未找到 @timestamp 字段，没有有效攻击时间")
        return None

    except Exception as e:
        logger.error(f"[Trace] 提取攻击时间失败: {e}", exc_info=True)
        return None


def _get_ip_first_attack_time(raw_result: dict, target_ip: str) -> str | None:
    """提取指定 IP 的最早攻击时间，并规范为东八区时间。"""
    try:
        data = raw_result.get("data", [])
        if not data:
            logger.warning(f"[Trace] 数据为空，IP {target_ip} 没有有效攻击时间")
            return None

        ip_first_time = None
        for record in data:
            if not _is_brute_force_detection_hit(record):
                continue
            ip = _record_field(record, "attack_src", "source.ip", "srcip", "destination.ip")
            if ip == target_ip:
                t = record.get("@timestamp_cst") or record.get("@timestamp")
                if t:
                    normalized = _normalize_attack_time(t)
                    if normalized and (not ip_first_time or normalized < ip_first_time):
                        ip_first_time = normalized

        if ip_first_time:
            logger.info(f"[Trace] IP {target_ip} 的最早攻击时间: {ip_first_time}")
            return ip_first_time

        logger.warning(f"[Trace] IP {target_ip} 没有有效 @timestamp，跳过自动溯源")
        return None
    except Exception as e:
        logger.error(f"[Trace] 提取 IP {target_ip} 攻击时间失败: {e}", exc_info=True)
        return None


def _get_ip_attack_time_range(raw_result: dict, target_ip: str) -> tuple[str, str]:
    """Return the earliest and latest observed attack time for one IP."""
    try:
        timestamps = []
        for record in raw_result.get("data", []):
            if not isinstance(record, dict):
                continue
            if not _is_brute_force_detection_hit(record):
                continue
            ip = _record_field(record, "attack_src", "source.ip", "srcip", "destination.ip")
            timestamp = record.get("@timestamp_cst") or record.get("@timestamp")
            if ip == target_ip and timestamp:
                normalized = _normalize_attack_time(timestamp)
                if normalized:
                    timestamps.append(normalized)

        timestamps = [timestamp for timestamp in timestamps if timestamp]
        if timestamps:
            first_time, last_time = min(timestamps), max(timestamps)
            logger.info(f"[Trace] IP: {target_ip}")
            logger.info(f"[Trace] Attack range: {first_time} ~ {last_time}")
            return first_time, last_time

        logger.warning(f"[Trace] IP: {target_ip} 没有有效 @timestamp，跳过自动溯源")
        return None, None
    except Exception as e:
        logger.error(f"[Trace] 提取 IP {target_ip} 攻击时间范围失败: {e}", exc_info=True)
        return None, None

def _auto_trace_brute_force_ips(raw_result: dict, start_time: str, end_time: str, gid: str) -> dict:
    """自动对暴力破解检测到的攻击 IP 执行溯源查询"""
    try:
        logger.info("[Trace] 开始执行自动溯源查询...")
        
        # 计算 IP 优先级
        trace_ips = _calculate_ip_priority(raw_result)
        
        if not trace_ips:
            logger.info("[Trace] 未检测到攻击源 IP，跳过溯源")
            return {
                "status": "success",
                "message": "未检测到攻击源 IP，无需溯源",
                "trace_ips": [],
                "ip_details": []
            }
        
        # 每个 IP 使用完整的攻击时间范围，而非仅最早一条记录。
        logger.info(f"[Trace] 开始对 {len(trace_ips)} 个 IP 执行溯源查询（每个 IP 独立时间窗口）")

        # 对每个 IP 执行溯源查询。ip_details 的顺序与 Top3 排名完全一致。
        ip_details = []
        for rank, ip in enumerate(trace_ips, 1):
            try:
                # 覆盖最早攻击前 30 分钟至最晚攻击后 30 分钟，避免
                # 漏掉同一 IP 在当天后续发生的攻击、锁定或拦截记录。
                ip_first_time, ip_last_time = _get_ip_attack_time_range(raw_result, ip)
                if not ip_first_time or not ip_last_time:
                    ip_details.append({
                        "ip": ip,
                        "rank": rank,
                        "brute_force_count": _ip_attack_count(raw_result, ip),
                        "trace_event_count": 0,
                        "status": "skipped",
                        "message": "缺少有效 @timestamp，未执行自动溯源",
                    })
                    continue
                ip_window = build_trace_window_range(
                    ip_first_time,
                    ip_last_time,
                    pre_minutes=30,
                    post_minutes=30,
                )
                logger.info(f"[Trace] Trace window: {ip_window['start_time']} ~ {ip_window['end_time']}")

                trace_result = ip_trace_request(
                    ip=ip,
                    start_time=ip_window["start_time"],
                    end_time=ip_window["end_time"],
                    gid=gid,
                )
                detail = trace_result.get("trace_info", {})
                if not isinstance(detail, dict):
                    detail = {}
                graph_data = detail.get("graph_data")
                if not isinstance(graph_data, dict):
                    graph_data = {}
                render_lines = graph_data.get("render_lines", [])
                trace_event_count = sum(
                    int(line.get("count", 0) or 0)
                    for line in render_lines
                    if isinstance(line, dict)
                )
                brute_force_count = _ip_attack_count(raw_result, ip)
                # Keep metadata both on the per-IP detail (for SSE graph wrappers)
                # and inside graph_data (for frontend graph consumers).
                graph_data.update({
                    "ip": ip,
                    "rank": rank,
                    "brute_force_count": brute_force_count,
                    "trace_event_count": trace_event_count,
                    "time_window": f"{ip_window['start_time']} ~ {ip_window['end_time']}",
                })
                detail.update({
                    "ip": ip,
                    "rank": rank,
                    "brute_force_count": brute_force_count,
                    "trace_event_count": trace_event_count,
                    "time_window": f"{ip_window['start_time']} ~ {ip_window['end_time']}",
                    "start_time": ip_window["start_time"],
                    "end_time": ip_window["end_time"],
                    "graph_data": graph_data,
                })
                ip_details.append(detail)
                logger.info(f"[Trace] IP {ip} 溯源查询完成，状态: {detail.get('status')}")
            except Exception as e:
                logger.error(f"[Trace] IP {ip} 溯源查询失败: {e}", exc_info=True)
                ip_details.append({
                    "ip": ip,
                    "rank": rank,
                    "brute_force_count": _ip_attack_count(raw_result, ip),
                    "trace_event_count": 0,
                    "status": "error",
                    "message": f"溯源查询失败：{str(e)}"
                })
        
        # 【修复】time_window 从 ip_details 收集（每个 IP 各自有独立窗口）
        # 原代码引用了已删除的 trace_window 变量导致 NameError
        if ip_details:
            time_windows = []
            for d in ip_details:
                if isinstance(d, dict) and d.get("time_window"):
                    time_windows.append(d["time_window"])
            if time_windows:
                # 取最早开始 ~ 最晚结束
                starts = [t.split("~")[0].strip() for t in time_windows if "~" in t]
                ends = [t.split("~")[-1].strip() for t in time_windows if "~" in t]
                overall_window = f"{min(starts)} ~ {max(ends)}" if starts and ends else "未提供"
            else:
                overall_window = "未提供"
        else:
            overall_window = "未提供"

        # Keep the exact selected list (which may contain fewer than three IPs
        # when the 80% coverage threshold is reached early) alongside its
        # complete statistics.  Consumers must use this list for both the
        # textual Top-N section and graph_data.graphs.
        stats_by_ip = {}
        raw_stats = raw_result.get("ip_stats") if isinstance(raw_result, dict) else None
        if isinstance(raw_stats, list):
            for item in raw_stats:
                if isinstance(item, dict) and item.get("ip"):
                    stats_by_ip[str(item["ip"])] = dict(item)
        total_attack_count = sum(
            int(item.get("count", 0) or 0)
            for item in stats_by_ip.values()
            if isinstance(item, dict)
        )
        if not total_attack_count:
            total_attack_count = sum(
                1
                for record in (raw_result.get("data", []) if isinstance(raw_result, dict) else [])
                if _is_brute_force_detection_hit(record)
            )
        trace_ip_stats = []
        for ip in trace_ips:
            stat = dict(stats_by_ip.get(str(ip), {}))
            stat["ip"] = ip
            try:
                stat["count"] = int(stat.get("count", 0) or 0)
            except (TypeError, ValueError):
                stat["count"] = _ip_attack_count(raw_result, ip)
            if "percentage" not in stat:
                stat["percentage"] = round(
                    stat["count"] * 100 / total_attack_count, 1
                ) if total_attack_count else 0.0
            trace_ip_stats.append(stat)

        result = {
            "status": "success",
            "ip_count": len(ip_details),
            "trace_ips": trace_ips,
            "trace_ip_stats": trace_ip_stats,
            "time_window": overall_window,
            "ip_details": ip_details
        }
        logger.info(f"[Trace] 自动溯源完成，共处理 {len(ip_details)} 个 IP")
        return result
        
    except Exception as e:
        logger.error(f"[Trace] 自动溯源执行失败: {e}", exc_info=True)
        return {
            "status": "error",
            "message": f"自动溯源执行失败：{str(e)}",
            "ip_details": []
        }


def brute_force_request(
    user_problem: str = "",
    start_time: str = None,
    end_time: str = None,
    filter_ip: str = None,
    filter_user: str = None,
    gid: str = None,
) -> str:
    """
    暴力破解检测统一入口函数
    
    Args:
        user_problem: 用户问题描述，支持自动提取 IP、用户名
        start_time: 开始时间（可选）
        end_time: 结束时间（可选）
        filter_ip: 过滤的 IP 地址
        filter_user: 过滤的用户名
        gid: 设备组 ID（可选）
    
    Returns:
        str: JSON 格式的暴力破解检测结果（包含溯源信息）
    """
    # 执行暴力破解查询
    executor = ToolExecutor(
        tool_name="brute_force",
        ppl_template=PPL_TEMPLATE,
        user_problem=user_problem,
        start_time=start_time,
        end_time=end_time,
        filter_ip=filter_ip,
        filter_user=filter_user,
        gid=gid,
        compression_config=COMPRESSION_CONFIG,
        ip_field="attack_src",  # attack_src 由 source.ip / destination.ip 计算得出
    )
    
    # 获取原始结果
    raw_result_str = executor.execute()
    try:
        raw_result = json.loads(raw_result_str)
    except json.JSONDecodeError as e:
        logger.error(f"[BruteForce] 解析暴力破解结果失败: {e}")
        return json.dumps({
            "status": "error",
            "error": f"解析查询结果失败: {str(e)}",
            "trace_info": {
                "status": "error",
                "message": "原始查询结果解析失败，无法执行溯源"
            }
        }, ensure_ascii=False)
    
    # 先计算完整查询统计，再用同一份统计选择 Top3 溯源 IP；这样文字
    # 摘要和 graph_data 不会因为 data 样本或调用顺序产生不同排名。
    raw_result["ip_stats"] = calculate_ip_stats(
        raw_result.get("data", []),
        ip_field="attack_src"
    )

    # 自动触发溯源查询
    try:
        trace_info = _auto_trace_brute_force_ips(raw_result, start_time, end_time, gid)
    except Exception as e:
        logger.error(f"[BruteForce] 自动溯源执行异常: {e}", exc_info=True)
        trace_info = {
            "status": "error",
            "message": f"自动溯源执行失败：{str(e)}",
            "ip_details": []
        }
    
    # 将溯源信息追加到结果中
    raw_result["trace_info"] = trace_info
    
    # 返回最终结果
    return json.dumps(raw_result, ensure_ascii=False)


class BruteForceInput(BaseModel):
    """暴力破解检测工具输入参数模型"""
    user_problem: str = Field(default="", description="用户的问题描述，用于提取 IP、用户名等过滤条件")
    start_time: Optional[str] = Field(default=None, description="查询开始时间，格式：YYYY-MM-DD HH:MM:SS（如：2026-05-10 08:00:00）。如果是'今天/近 7 天/最近 24 小时'等相对时间，可直接传原文由后端解析")
    end_time: Optional[str] = Field(default=None, description="查询结束时间，格式：YYYY-MM-DD HH:MM:SS（如：2026-05-10 18:00:00）。如果是'今天/近 7 天/最近 24 小时'等相对时间，可直接传原文由后端解析")
    filter_ip: Optional[str] = Field(default=None, description="过滤的 IP 地址（可选）")
    filter_user: Optional[str] = Field(default=None, description="过滤的用户名（可选）")
    gid: Optional[str] = Field(default=None, description="设备组 ID（可选，用于过滤特定设备组的日志，对应日志字段@gid）")
