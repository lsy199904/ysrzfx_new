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
- 按累计占比≥80% 原则选取最多 5 个 IP
- 对每个 IP 查询前 5 分钟的完整活动链路
"""
import json
import logging
from typing import Optional
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
from tools.tool_base import ToolExecutor, CompressionConfig
from tools.index_config import INDEX_SOURCE_PATTERN
from config import COMPRESSION_MAX_RETURN_DATA, COMPRESSION_MAX_TOKENS, COMPRESSION_THRESHOLD
from tools.ip_trace import ip_trace_request, build_trace_window

logger = logging.getLogger(__name__)


# PPL 查询模板
PPL_TEMPLATE = f"""search source=`{INDEX_SOURCE_PATTERN}`

| where (subtype='system' and action='login' and status='failed') OR (subtype='vpn' and msg='SSL user failed to logged in')
| where reason != 'ip_blocked'
| where srcip != '218.92.0.39'
| eval attack_src = case(isnotnull(srcip), srcip else remip)
| fields @timestamp_cst, user, attack_src, srcip, remip, action, reason, msg, subtype, @gid, devname, policyid
| sort - @timestamp_cst"""


# 压缩配置（与其他工具统一）
COMPRESSION_CONFIG = CompressionConfig(
    threshold=COMPRESSION_THRESHOLD,
    max_tokens=COMPRESSION_MAX_TOKENS,
    max_return_data=COMPRESSION_MAX_RETURN_DATA,
)


def _calculate_ip_priority(raw_result: dict) -> list:
    """
    根据攻击次数计算 IP 优先级，选取累计占比≥80% 的 IP（最多 5 个）
    """
    try:
        data = raw_result.get("data", [])
        logger.info(f"[IP Priority] 开始计算 IP 优先级，原始数据条数: {len(data)}")
        if not data:
            logger.warning("[IP Priority] 未检测到数据，跳过 IP 优先级计算")
            return []
        
        # 统计每个 IP 的出现次数
        ip_counts = {}
        for record in data:
            ip = record.get("attack_src") or record.get("srcip") or record.get("remip")
            if ip:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        logger.info(f"[IP Priority] 统计到的 IP 分布: {ip_counts}")
        
        if not ip_counts:
            logger.warning("[IP Priority] 未找到有效的 IP 字段")
            return []
        
        # 按次数降序排序
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

        # 【保留原阈值】累计 ≥80% 或最多 5 个 IP（兜底）
        # 即便均匀分布永远到不了 80%，也会至少取 5 个 IP 作为兜底
        total = sum(ip_counts.values())
        cumulative = 0
        trace_ips = []
        MAX_TRACE_IPS = 5
        COVERAGE_THRESHOLD = 0.8

        logger.info(f"[IP Priority] 数据统计: 共 {len(sorted_ips)} 个 unique IP，总攻击 {total} 次")
        for ip, count in sorted_ips:
            cumulative += count / total
            trace_ips.append(ip)
            logger.info(f"[IP Priority] 已收录 IP {ip} (累计占比: {cumulative:.2%})")
            # 达到 80% 阈值 OR 达到兜底数量（5 个）即停止
            if cumulative >= COVERAGE_THRESHOLD or len(trace_ips) >= MAX_TRACE_IPS:
                logger.info(f"[IP Priority] 达到阈值 (≥80% 或 ≥{MAX_TRACE_IPS}个)，停止选取")
                break

        logger.info(f"[IP Priority] 最终选取的溯源 IP 列表: {trace_ips}")
        return trace_ips
        
    except Exception as e:
        logger.error(f"[IP Priority] 计算 IP 优先级失败: {e}", exc_info=True)
        return []


def _get_first_attack_time(raw_result: dict) -> str:
    """从暴力破解结果中提取最早的攻击时间"""
    try:
        data = raw_result.get("data", [])
        if not data:
            logger.warning("[Trace] 数据为空，使用当前时间作为攻击时间")
            return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # 数据已经按时间降序排序，取最后一条即为最早
        first_record = data[-1]
        attack_time = first_record.get("@timestamp_cst")

        if attack_time:
            logger.info(f"[Trace] 提取到最早攻击时间: {attack_time}")
            return attack_time

        logger.warning("[Trace] 未找到 @timestamp_cst 字段，使用当前时间")
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    except Exception as e:
        logger.error(f"[Trace] 提取攻击时间失败: {e}", exc_info=True)
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def _get_ip_first_attack_time(raw_result: dict, target_ip: str) -> str:
    """【新增】提取指定 IP 的最早攻击时间（用于该 IP 自己的溯源时间窗口）"""
    try:
        data = raw_result.get("data", [])
        if not data:
            logger.warning(f"[Trace] 数据为空，IP {target_ip} 使用当前时间")
            return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # 数据按时间降序排列，遍历找该 IP 的最早一条（即最后匹配的那条）
        ip_first_time = None
        for record in data:
            ip = record.get("attack_src") or record.get("srcip") or record.get("remip")
            if ip == target_ip:
                t = record.get("@timestamp_cst")
                if t:
                    ip_first_time = t  # 不断覆盖，最后保留的是最早的

        if ip_first_time:
            logger.info(f"[Trace] IP {target_ip} 的最早攻击时间: {ip_first_time}")
            return ip_first_time

        # 没找到该 IP 的记录，回退到全局最早时间
        logger.warning(f"[Trace] IP {target_ip} 在数据中未找到记录，回退到全局最早时间")
        return _get_first_attack_time(raw_result)

    except Exception as e:
        logger.error(f"[Trace] 提取 IP {target_ip} 攻击时间失败: {e}", exc_info=True)
        return _get_first_attack_time(raw_result)


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
                "ip_details": []
            }
        
        # 【修复】每个 IP 各自计算自己的首次攻击时间，得到独立的 time_window
        # 原代码：所有 IP 共享全局首次时间，导致后攻击的 IP 窗口可能错过它自己的攻击
        logger.info(f"[Trace] 开始对 {len(trace_ips)} 个 IP 执行溯源查询（每个 IP 独立时间窗口）")

        # 对每个 IP 执行溯源查询
        ip_details = []
        for ip in trace_ips:
            try:
                # 【修复】取该 IP 自己的首次攻击时间
                # 【可调】溯源时间窗口：5 分钟太短容易漏上下文，30 分钟是经验值
                # 暴力破解攻击通常在 5-15 分钟内完成，但关联事件（账号创建、配置变更）可能更早
                ip_first_time = _get_ip_first_attack_time(raw_result, ip)
                ip_window = build_trace_window(ip_first_time, pre_minutes=30)
                logger.info(f"[Trace] 正在溯源 IP: {ip}，时间窗口：{ip_window['start_time']} ~ {ip_window['end_time']}")

                trace_result = ip_trace_request(
                    ip=ip,
                    start_time=ip_window["start_time"],
                    end_time=ip_window["end_time"],
                    gid=gid,
                )
                ip_details.append(trace_result.get("trace_info", {}))
                logger.info(f"[Trace] IP {ip} 溯源查询完成，状态: {trace_result.get('trace_info', {}).get('status')}")
            except Exception as e:
                logger.error(f"[Trace] IP {ip} 溯源查询失败: {e}", exc_info=True)
                ip_details.append({
                    "ip": ip,
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

        result = {
            "status": "success",
            "ip_count": len(ip_details),
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
        ip_field="attack_src",  # 暴力破解使用 attack_src 字段（由模板中 srcip 和 remip 计算得出）
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
