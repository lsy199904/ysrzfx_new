# -*- coding: utf-8 -*-
"""
系统安全监控工具
用于监控系统安全相关事件，包括设备重启、系统关机等

【压缩配置】（与 brute_force.py 对齐）
- 压缩触发阈值：>= 15 条 或 问题包含统计类关键词
- max_tokens: 2000
- 返回数据条数：5 条
- compressed_count = original_count（压缩不改变实际记录数）

【Redis 缓存】
- 缓存 TTL：300 秒（5 分钟）

【IP 溯源功能】
- 系统安全事件完成后，自动提取操作者 IP（uiscrip）
- 按累计占比≥80% 原则选取最多 5 个 IP
- 对每个 IP 查询前 30 分钟的完整活动链路
"""
import json
import logging
from typing import Optional
from datetime import datetime
from pydantic import BaseModel, Field
from tools.tool_base import ToolExecutor, CompressionConfig
from tools.index_config import INDEX_SOURCE_PATTERN
from config import COMPRESSION_MAX_RETURN_DATA, COMPRESSION_MAX_TOKENS, COMPRESSION_THRESHOLD
from tools.ip_trace import ip_trace_request, build_trace_window

logger = logging.getLogger(__name__)


# PPL 查询模板
PPL_TEMPLATE = rf"""search source=`{INDEX_SOURCE_PATTERN}`
| where fortinet.firewall.subtype='system'
| where rule.description="Device rebooted" OR rule.description="Device shutdown"
| eval msg1=like(message,'%scheduled daily restart%'), msg2=like(message,'%upgrade firmware%')
| where msg1=false and msg2=false
| parse fortinet.firewall.ui '.*\((?<uiscrip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\).*'
| where isnotnull(uiscrip) AND uiscrip != ''
| where source.user.name NOT in ("c_admin", "cpc-ops")
| where isnotnull(uiscrip) AND uiscrip != '' AND NOT (cidrmatch(uiscrip, "202.76.24.0/27") OR cidrmatch(uiscrip, "202.88.96.0/27"))
| eval out5=if(like(source.user.name, "s%") OR like(source.user.name, "op%"), 'discard', "keep")
| where out5="keep"
| fields fortinet.firewall.type,event.action, @timestamp, @gid, observer.name, source.user.name, message, rule.description, fortinet.firewall.subtype, rule.id, uiscrip"""

# 自定义压缩配置（可选，不传则使用默认配置）
COMPRESSION_CONFIG = CompressionConfig(
    threshold=COMPRESSION_THRESHOLD,
    max_tokens=COMPRESSION_MAX_TOKENS,
    max_return_data=COMPRESSION_MAX_RETURN_DATA,
)


def _calculate_ip_priority(raw_result: dict) -> list:
    """根据系统安全事件的操作者 IP（uiscrip）计算优先级"""
    try:
        data = raw_result.get("data", [])
        logger.info(f"[SystemTrace] 开始计算 IP 优先级，原始数据条数: {len(data)}")
        if not data:
            logger.warning("[SystemTrace] 未检测到数据，跳过 IP 优先级计算")
            return []
        
        ip_counts = {}
        for record in data:
            ip = record.get("uiscrip") or record.get("source.ip") or record.get("srcip")
            if ip:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        logger.info(f"[SystemTrace] 统计到的 IP 分布: {ip_counts}")
        if not ip_counts:
            logger.warning("[SystemTrace] 未找到有效的 IP 字段")
            return []
        
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        total = sum(ip_counts.values())
        cumulative = 0
        trace_ips = []
        
        for ip, count in sorted_ips:
            cumulative += count / total
            trace_ips.append(ip)
            logger.info(f"[SystemTrace] 已收录 IP {ip} (累计占比: {cumulative:.2%})")
            if cumulative >= 0.8 or len(trace_ips) >= 5:
                logger.info(f"[SystemTrace] 达到阈值，停止选取")
                break
        
        logger.info(f"[SystemTrace] 最终选取的溯源 IP 列表: {trace_ips}")
        return trace_ips
        
    except Exception as e:
        logger.error(f"[SystemTrace] 计算 IP 优先级失败: {e}", exc_info=True)
        return []


def _get_ip_first_event_time(raw_result: dict, target_ip: str) -> str:
    """提取指定 IP 的最早系统安全事件时间"""
    try:
        data = raw_result.get("data", [])
        if not data:
            return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        ip_first_time = None
        for record in data:
            ip = record.get("uiscrip") or record.get("source.ip") or record.get("srcip")
            if ip == target_ip:
                t = record.get("@timestamp")
                if t:
                    ip_first_time = t
        
        if ip_first_time:
            logger.info(f"[SystemTrace] IP {target_ip} 的最早事件时间: {ip_first_time}")
            return ip_first_time
        
        logger.warning(f"[SystemTrace] IP {target_ip} 未找到记录，回退到全局时间")
        first_record = data[-1] if data else {}
        return first_record.get("@timestamp", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    except Exception as e:
        logger.error(f"[SystemTrace] 提取时间失败: {e}", exc_info=True)
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def _auto_trace_system_security_ips(raw_result: dict, start_time: str, end_time: str, gid: str) -> dict:
    """自动对系统安全事件的操作者 IP 执行溯源查询"""
    try:
        logger.info("[SystemTrace] 开始执行自动溯源查询...")
        trace_ips = _calculate_ip_priority(raw_result)
        
        if not trace_ips:
            logger.info("[SystemTrace] 未检测到操作者 IP，跳过溯源")
            return {"status": "success", "message": "未检测到操作者 IP，无需溯源", "ip_details": []}
        
        logger.info(f"[SystemTrace] 开始对 {len(trace_ips)} 个 IP 执行溯源查询")
        ip_details = []
        
        for ip in trace_ips:
            try:
                ip_first_time = _get_ip_first_event_time(raw_result, ip)
                ip_window = build_trace_window(ip_first_time, pre_minutes=30)
                logger.info(f"[SystemTrace] 正在溯源 IP: {ip}，时间窗口：{ip_window['start_time']} ~ {ip_window['end_time']}")
                
                trace_result = ip_trace_request(
                    ip=ip,
                    start_time=ip_window["start_time"],
                    end_time=ip_window["end_time"],
                    gid=gid,
                )
                ip_details.append(trace_result.get("trace_info", {}))
                logger.info(f"[SystemTrace] IP {ip} 溯源查询完成，状态: {trace_result.get('trace_info', {}).get('status')}")
            except Exception as e:
                logger.error(f"[SystemTrace] IP {ip} 溯源查询失败: {e}", exc_info=True)
                ip_details.append({"ip": ip, "status": "error", "message": f"溯源查询失败：{str(e)}"})
        
        # 收集 time_window
        if ip_details:
            time_windows = [d["time_window"] for d in ip_details if isinstance(d, dict) and d.get("time_window")]
            if time_windows:
                starts = [t.split("~")[0].strip() for t in time_windows if "~" in t]
                ends = [t.split("~")[-1].strip() for t in time_windows if "~" in t]
                overall_window = f"{min(starts)} ~ {max(ends)}" if starts and ends else "未提供"
            else:
                overall_window = "未提供"
        else:
            overall_window = "未提供"
        
        result = {"status": "success", "ip_count": len(ip_details), "time_window": overall_window, "ip_details": ip_details}
        logger.info(f"[SystemTrace] 自动溯源完成，共处理 {len(ip_details)} 个 IP")
        return result
        
    except Exception as e:
        logger.error(f"[SystemTrace] 自动溯源执行失败: {e}", exc_info=True)
        return {"status": "error", "message": f"自动溯源执行失败：{str(e)}", "ip_details": []}



def system_security_request(
    user_problem: str = "",
    start_time: str = None,
    end_time: str = None,
    filter_ip: str = None,
    filter_user: str = None,
    gid: str = None,
) -> str:
    """
    系统安全监控统一入口函数（包含自动溯源）
    
    Args:
        user_problem: 用户问题描述，支持：今天、近 7 天、IP 过滤等
        start_time: 开始时间（可选）
        end_time: 结束时间（可选）
        filter_ip: 过滤的 IP 地址
        filter_user: 过滤的用户名
        gid: 设备组 ID（可选）
    
    Returns:
        str: JSON 格式的系统安全监控结果（包含溯源信息）
    """
    executor = ToolExecutor(
        tool_name="system_security_monitor",
        ppl_template=PPL_TEMPLATE,
        user_problem=user_problem,
        start_time=start_time,
        end_time=end_time,
        filter_ip=filter_ip,
        filter_user=filter_user,
        gid=gid,
        compression_config=COMPRESSION_CONFIG,
        ip_field="uiscrip",  # 系统安全使用 uiscrip 字段（从 UI 字段解析出的操作者 IP）
    )
    
    raw_result_str = executor.execute()
    try:
        raw_result = json.loads(raw_result_str)
    except json.JSONDecodeError as e:
        logger.error(f"[SystemSecurity] 解析结果失败: {e}")
        return json.dumps({
            "status": "error",
            "error": f"解析查询结果失败: {str(e)}",
            "trace_info": {"status": "error", "message": "原始查询结果解析失败，无法执行溯源"}
        }, ensure_ascii=False)
    
    # 自动触发溯源查询
    try:
        trace_info = _auto_trace_system_security_ips(raw_result, start_time, end_time, gid)
    except Exception as e:
        logger.error(f"[SystemSecurity] 自动溯源执行异常: {e}", exc_info=True)
        trace_info = {"status": "error", "message": f"自动溯源执行失败：{str(e)}", "ip_details": []}
    
    raw_result["trace_info"] = trace_info
    return json.dumps(raw_result, ensure_ascii=False)


class SystemSecurityInput(BaseModel):
    """系统安全监控工具输入参数模型"""
    user_problem: str = Field(default="", description="用户问题描述")
    start_time: Optional[str] = Field(default=None, description="查询开始时间")
    end_time: Optional[str] = Field(default=None, description="查询结束时间")
    filter_ip: Optional[str] = Field(default=None, description="过滤的 IP 地址")
    filter_user: Optional[str] = Field(default=None, description="过滤的用户名")
    gid: Optional[str] = Field(default=None, description="设备组 ID（可选，用于过滤特定设备组的日志，对应日志字段@gid）")
