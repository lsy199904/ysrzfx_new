# -*- coding: utf-8 -*-
"""
网络攻击检测工具
用于检测网络攻击相关事件，包括 IPS 告警、恶意流量等

【压缩配置】（与 brute_force.py 对齐）
- 压缩触发阈值：>= 15 条 或 问题包含统计类关键词
- max_tokens: 2000
- 返回数据条数：5 条
- compressed_count = original_count（压缩不改变实际记录数）

【Redis 缓存】
- 缓存 TTL：300 秒（5 分钟）

【IP 溯源功能】
- 网络攻击检测完成后，自动提取攻击源 IP（srcip）
- 按累计占比≥80% 原则选取最多 5 个 IP
- 对每个 IP 查询前 30 分钟的完整活动链路
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


def _utc_to_cst(timestamp_str: str) -> str:
    """将 ES 返回的 UTC 时间字符串转换为东八区（CST）时间字符串。"""
    try:
        ts_str = str(timestamp_str).strip()
        ts_clean = ts_str.replace('Z', '').replace('+00:00', '').strip()
        for fmt in ('%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S'):
            try:
                dt_utc = datetime.strptime(ts_clean, fmt)
                dt_cst = dt_utc + timedelta(hours=8)
                return dt_cst.strftime('%Y-%m-%d %H:%M:%S')
            except ValueError:
                continue
        return timestamp_str
    except Exception as e:
        logger.warning(f"[NetworkTrace] UTC 转 CST 失败: {e}，返回原值: {timestamp_str}")
        return timestamp_str


# PPL 查询模板
PPL_TEMPLATE = f"""search source=`{INDEX_SOURCE_PATTERN}`
| where fortinet.firewall.type='utm' and fortinet.firewall.subtype='ips'
| where NOT (cidrmatch(source.ip, "10.0.0.0/8") AND cidrmatch(destination.ip, "10.0.0.0/8"))
| where log.level='alert'
| where fortinet.firewall.severity!='info' and fortinet.firewall.severity!='low'
| where event.action!='blocked' and event.action!='dropped'
| where NOT like(fortinet.firewall.attack,'%SQL.Injection%') AND NOT like(fortinet.firewall.attack,'%TCP.Split.Handshake%')
| where source.ip!="202.76.24.1"
| where source.ip!="8.8.8.8"
| fields @gid, fortinet.firewall.type, fortinet.firewall.subtype, source.ip, destination.ip, destination.port, fortinet.firewall.attack, url.original, event.action, rule.id, message, observer.name, @timestamp, source.user.name"""


# 自定义压缩配置（可选，不传则使用默认配置）
COMPRESSION_CONFIG = CompressionConfig(
    threshold=COMPRESSION_THRESHOLD,
    max_tokens=COMPRESSION_MAX_TOKENS,
    max_return_data=COMPRESSION_MAX_RETURN_DATA,
)


def _calculate_ip_priority(raw_result: dict) -> list:
    """根据网络攻击事件的攻击源 IP（srcip）计算优先级"""
    try:
        data = raw_result.get("data", [])
        logger.info(f"[NetworkTrace] 开始计算 IP 优先级，原始数据条数: {len(data)}")
        if not data:
            logger.warning("[NetworkTrace] 未检测到数据，跳过 IP 优先级计算")
            return []
        
        ip_counts = {}
        for record in data:
            ip = record.get("source.ip") or record.get("srcip")
            if ip:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        logger.info(f"[NetworkTrace] 统计到的 IP 分布: {ip_counts}")
        if not ip_counts:
            logger.warning("[NetworkTrace] 未找到有效的 IP 字段")
            return []
        
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        total = sum(ip_counts.values())
        cumulative = 0
        trace_ips = []
        
        for ip, count in sorted_ips:
            cumulative += count / total
            trace_ips.append(ip)
            logger.info(f"[NetworkTrace] 已收录 IP {ip} (累计占比: {cumulative:.2%})")
            if cumulative >= 0.8 or len(trace_ips) >= 5:
                logger.info(f"[NetworkTrace] 达到阈值，停止选取")
                break
        
        logger.info(f"[NetworkTrace] 最终选取的溯源 IP 列表: {trace_ips}")
        return trace_ips
        
    except Exception as e:
        logger.error(f"[NetworkTrace] 计算 IP 优先级失败: {e}", exc_info=True)
        return []


def _get_ip_first_attack_time(raw_result: dict, target_ip: str) -> str:
    """提取指定 IP 的最早网络攻击时间（UTC → CST 转换）"""
    try:
        data = raw_result.get("data", [])
        if not data:
            return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        ip_first_time = None
        for record in data:
            ip = record.get("source.ip") or record.get("srcip")
            if ip == target_ip:
                t = record.get("@timestamp")
                if t:
                    ip_first_time = t

        if ip_first_time:
            # 【修复】ES 返回的是 UTC 时间，需转换为 CST 供后续链路使用
            cst_time = _utc_to_cst(ip_first_time)
            logger.info(f"[NetworkTrace] IP {target_ip} 的最早攻击时间（UTC→CST）: {ip_first_time} → {cst_time}")
            return cst_time

        logger.warning(f"[NetworkTrace] IP {target_ip} 未找到记录，回退到全局时间")
        first_record = data[-1] if data else {}
        raw_ts = first_record.get("@timestamp", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        if raw_ts and raw_ts != datetime.now().strftime('%Y-%m-%d %H:%M:%S'):
            return _utc_to_cst(raw_ts)
        return raw_ts
    except Exception as e:
        logger.error(f"[NetworkTrace] 提取时间失败: {e}", exc_info=True)
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def _auto_trace_network_attack_ips(raw_result: dict, start_time: str, end_time: str, gid: str) -> dict:
    """自动对网络攻击检测到的攻击源 IP 执行溯源查询"""
    try:
        logger.info("[NetworkTrace] 开始执行自动溯源查询...")
        trace_ips = _calculate_ip_priority(raw_result)
        
        if not trace_ips:
            logger.info("[NetworkTrace] 未检测到攻击源 IP，跳过溯源")
            return {"status": "success", "message": "未检测到攻击源 IP，无需溯源", "ip_details": []}
        
        logger.info(f"[NetworkTrace] 开始对 {len(trace_ips)} 个 IP 执行溯源查询")
        ip_details = []
        
        for ip in trace_ips:
            try:
                ip_first_time = _get_ip_first_attack_time(raw_result, ip)
                ip_window = build_trace_window(ip_first_time, pre_minutes=30)
                logger.info(f"[NetworkTrace] 正在溯源 IP: {ip}，时间窗口：{ip_window['start_time']} ~ {ip_window['end_time']}")
                
                trace_result = ip_trace_request(
                    ip=ip,
                    start_time=ip_window["start_time"],
                    end_time=ip_window["end_time"],
                    gid=gid,
                )
                ip_details.append(trace_result.get("trace_info", {}))
                logger.info(f"[NetworkTrace] IP {ip} 溯源查询完成，状态: {trace_result.get('trace_info', {}).get('status')}")
            except Exception as e:
                logger.error(f"[NetworkTrace] IP {ip} 溯源查询失败: {e}", exc_info=True)
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
        logger.info(f"[NetworkTrace] 自动溯源完成，共处理 {len(ip_details)} 个 IP")
        return result
        
    except Exception as e:
        logger.error(f"[NetworkTrace] 自动溯源执行失败: {e}", exc_info=True)
        return {"status": "error", "message": f"自动溯源执行失败：{str(e)}", "ip_details": []}



def network_attack_request(
    user_problem: str = "",
    start_time: str = None,
    end_time: str = None,
    filter_ip: str = None,
    filter_user: str = None,
    gid: str = None,
) -> str:
    """
    网络攻击检测统一入口函数（包含自动溯源）
    
    Args:
        user_problem: 用户问题描述
        start_time: 开始时间（可选）
        end_time: 结束时间（可选）
        filter_ip: 过滤的 IP 地址
        filter_user: 过滤的用户名
        gid: 设备组 ID（可选）
    
    Returns:
        str: JSON 格式的网络攻击检测结果（包含溯源信息）
    """
    executor = ToolExecutor(
        tool_name="network_attack_detection",
        ppl_template=PPL_TEMPLATE,
        user_problem=user_problem,
        start_time=start_time,
        end_time=end_time,
        filter_ip=filter_ip,
        filter_user=filter_user,
        gid=gid,
        compression_config=COMPRESSION_CONFIG,
        ip_field="source.ip",  # 网络攻击检测使用 source.ip 字段（攻击源 IP）
    )
    
    raw_result_str = executor.execute()
    try:
        raw_result = json.loads(raw_result_str)
    except json.JSONDecodeError as e:
        logger.error(f"[NetworkAttack] 解析结果失败: {e}")
        return json.dumps({
            "status": "error",
            "error": f"解析查询结果失败: {str(e)}",
            "trace_info": {"status": "error", "message": "原始查询结果解析失败，无法执行溯源"}
        }, ensure_ascii=False)
    
    # 自动触发溯源查询
    try:
        trace_info = _auto_trace_network_attack_ips(raw_result, start_time, end_time, gid)
    except Exception as e:
        logger.error(f"[NetworkAttack] 自动溯源执行异常: {e}", exc_info=True)
        trace_info = {"status": "error", "message": f"自动溯源执行失败：{str(e)}", "ip_details": []}
    
    raw_result["trace_info"] = trace_info
    return json.dumps(raw_result, ensure_ascii=False)


class NetworkAttackInput(BaseModel):
    """网络攻击检测工具输入参数模型"""
    user_problem: str = Field(default="", description="用户问题描述")
    start_time: Optional[str] = Field(default=None, description="查询开始时间")
    end_time: Optional[str] = Field(default=None, description="查询结束时间")
    filter_ip: Optional[str] = Field(default=None, description="过滤的 IP 地址")
    filter_user: Optional[str] = Field(default=None, description="过滤的用户名")
    gid: Optional[str] = Field(default=None, description="设备组 ID（可选，用于过滤特定设备组的日志，对应日志字段@gid）")
