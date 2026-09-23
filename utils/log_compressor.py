"""
日志数据压缩模块

提供多级压缩策略，用于减少日志数据量，避免 LLM Token 超限。

压缩流程：
1. 字段压缩（保险策略）- 当字段数 > 20 时触发
2. 智能聚合 - 根据问题类型识别聚合维度
3. 语义筛选 - 使用 BERT + 余弦相似度保留 Top K

使用示例：
    compressor = LogCompressor()
    result = compressor.compress(logs, question="今天有哪些暴力破解记录？")
"""
import json
import re
import os
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict
from datetime import datetime

# 延迟导入，避免不必要的依赖加载
_tiktoken = None
_torch = None
_transformers = None

# 压缩输出结构/字段策略版本。加入缓存 key 后，旧压缩结果不会继续复用。
COMPRESSION_VERSION = "ecs-v2"

# 只使用当前索引中的 ECS 字段。值既支持 OpenSearch 返回的扁平键
# （例如 ``source.ip``），也支持测试/调用方传入的嵌套对象。
ECS_FIELD_ALIASES = {
    "timestamp": ["@timestamp", "@timestamp_cst"],
    "source.ip": ["source.ip"],
    "destination.ip": ["destination.ip"],
    "source.user.name": ["source.user.name"],
    "event.action": ["event.action"],
    "event.reason": ["event.reason"],
    "fortinet.firewall.subtype": ["fortinet.firewall.subtype"],
    "fortinet.firewall.status": ["fortinet.firewall.status"],
    "observer.name": ["observer.name"],
    "rule.id": ["rule.id"],
    "rule.name": ["rule.name"],
    "message": ["message"],
    "fortinet.firewall.attack": ["fortinet.firewall.attack"],
    "@gid": ["@gid"],
    "fail_count": ["fail_count"],
}


def _get_ecs_value(log: Dict, field: str, default: Any = None) -> Any:
    """读取 ECS 字段，兼容扁平点号键和嵌套字典，不回退旧字段。"""
    if not isinstance(log, dict):
        return default
    for candidate in ECS_FIELD_ALIASES.get(field, [field]):
        if candidate in log and log[candidate] not in (None, ""):
            return log[candidate]
        current = log
        for part in candidate.split("."):
            if not isinstance(current, dict) or part not in current:
                current = None
                break
            current = current[part]
        if current not in (None, ""):
            return current
    return default


def _get_tiktoken():
    """延迟加载 tiktoken"""
    global _tiktoken
    if _tiktoken is None:
        import tiktoken
        _tiktoken = tiktoken
    return _tiktoken


def _get_torch():
    """延迟加载 torch"""
    global _torch
    if _torch is None:
        import torch
        _torch = torch
    return _torch


def _get_transformers():
    """延迟加载 transformers"""
    global _transformers
    if _transformers is None:
        try:
            from transformers import AutoTokenizer, AutoModel
            _transformers = (AutoTokenizer, AutoModel)
        except (ModuleNotFoundError, ImportError, AttributeError) as e:
            print(f"警告：无法加载 transformers 库：{e}，将使用简化压缩模式")
            _transformers = None
    return _transformers


# ========================================
# 配置参数
# ========================================
class LogCompressorConfig:
    """压缩配置"""
    # 字段压缩阈值
    field_threshold: int = 20  # 字段数超过此值触发字段压缩
    
    # 聚合触发阈值
    aggregate_threshold: int = 3  # 记录数超过此值触发聚合
    
    # Token 阈值
    token_threshold: int = 3000  # Token 数超过此值触发语义筛选
    max_output_tokens: int = 2000  # 最大输出 Token 数（压缩后日志文本目标上限，配合 max_tokens=50000 确保输入 < 10000）
    
    # LLM 文本中的代表性日志上限；与前端图谱 Top 3 展示无关。
    max_output_records: int = 10
    
    # 语义筛选保留比例
    keep_ratio: float = 0.5  # 默认保留 50%
    
    # 模型配置
    model_path: str = None  # BERT 模型路径，None 则使用默认
    device: str = "cpu"  # 计算设备
    
    # 关键字段（字段压缩时保留）
    key_fields: List[str] = [
        "@timestamp", "@timestamp_cst", "timestamp",
        "source.ip", "destination.ip", "source.user.name",
        "event.action", "event.reason",
        "fortinet.firewall.subtype", "fortinet.firewall.status",
        "fortinet.firewall.attack", "observer.name",
        "rule.id", "rule.name", "message", "@gid", "fail_count",
    ]


# 默认配置实例
DEFAULT_CONFIG = LogCompressorConfig()


# ========================================
# 聚合维度识别规则
# ========================================
def generate_summary_statistics(logs: List[Dict]) -> Dict[str, Any]:
    """
    生成日志摘要统计信息（在压缩前调用，用于保留整体统计信息）
    
    Args:
        logs: 原始日志列表
        
    Returns:
        Dict[str, Any]: 统计摘要信息
    """
    if not logs:
        return {"total_count": 0}
    
    from collections import defaultdict
    
    total_count = len(logs)
    
    # 统计 ECS 源 IP 分布
    src_ip_stats = defaultdict(int)
    for log in logs:
        ip = _get_ecs_value(log, "source.ip", "unknown")
        src_ip_stats[ip] += 1
    
    # 统计目标用户分布
    user_stats = defaultdict(int)
    for log in logs:
        user = _get_ecs_value(log, "source.user.name", "unknown")
        user_stats[user] += 1
    
    # 统计失败原因分布
    reason_stats = defaultdict(int)
    for log in logs:
        reason = _get_ecs_value(log, "event.reason", "unknown")
        reason_stats[reason] += 1
    
    # 统计设备分布
    device_stats = defaultdict(int)
    for log in logs:
        device = _get_ecs_value(log, "observer.name", "unknown")
        device_stats[device] += 1
    
    # 统计客户/组分布
    gid_stats = defaultdict(int)
    for log in logs:
        gid = _get_ecs_value(log, "@gid", "unknown")
        gid_stats[gid] += 1
    
    # 找出最活跃的 IP（攻击次数最多）
    most_active_ip = max(src_ip_stats.items(), key=lambda x: x[1]) if src_ip_stats else ("unknown", 0)
    
    # 找出最常被攻击的用户
    most_targeted_user = max(user_stats.items(), key=lambda x: x[1]) if user_stats else ("unknown", 0)
    
    return {
        "total_count": total_count,
        "unique_src_ip_count": len(src_ip_stats),
        "unique_user_count": len(user_stats),
        "src_ip_stats": dict(src_ip_stats),
        "user_stats": dict(user_stats),
        "reason_stats": dict(reason_stats),
        "device_stats": dict(device_stats),
        "gid_stats": dict(gid_stats),
        "most_active_ip": {"ip": most_active_ip[0], "count": most_active_ip[1]},
        "most_targeted_user": {"user": most_targeted_user[0], "count": most_targeted_user[1]},
    }


def format_summary_text(summary: Dict[str, Any]) -> str:
    """
    将统计摘要格式化为文本
    
    Args:
        summary: 统计摘要字典
        
    Returns:
        str: 格式化的摘要文本
    """
    if summary.get("total_count", 0) == 0:
        return "无日志记录"
    
    lines = [
        "=== 原始日志统计摘要 ===",
        f"原始日志总数：{summary.get('total_count', 0)} 条",
        f"去重后源 IP 数量：{summary.get('unique_src_ip_count', 0)} 个",
        f"涉及用户数量：{summary.get('unique_user_count', 0)} 个",
        "",
        "源 IP 分布（按攻击次数）:",
    ]
    
    # 按次数排序显示 Top 10 IP
    src_ip_stats = sorted(summary.get("src_ip_stats", {}).items(), key=lambda x: x[1], reverse=True)[:10]
    for ip, count in src_ip_stats:
        lines.append(f"  - {ip}: {count} 次")
    
    lines.append("")
    lines.append("目标用户分布（按被攻击次数）:")
    user_stats = sorted(summary.get("user_stats", {}).items(), key=lambda x: x[1], reverse=True)[:10]
    for user, count in user_stats:
        lines.append(f"  - {user}: {count} 次")
    
    if summary.get("reason_stats"):
        lines.append("")
        lines.append("失败原因分布:")
        for reason, count in summary.get("reason_stats", {}).items():
            lines.append(f"  - {reason}: {count} 次")
    
    if summary.get("most_active_ip"):
        lines.append("")
        lines.append(f"最活跃攻击源：{summary['most_active_ip']['ip']} ({summary['most_active_ip']['count']} 次)")
    
    if summary.get("most_targeted_user"):
        lines.append(f"最常被攻击用户：{summary['most_targeted_user']['user']} ({summary['most_targeted_user']['count']} 次)")
    
    return "\n".join(lines)


def identify_aggregate_dimension(logs: List[Dict], question: str) -> Tuple[str, List[str]]:
    """
    识别聚合维度
    
    Args:
        logs: 日志列表
        question: 用户问题
        
    Returns:
        Tuple[str, List[str]]: (聚合类型，聚合字段列表)
    """
    # 检查日志类型
    log_types = set()
    for log in logs[:10]:  # 采样前 10 条
        if isinstance(log, dict):
            if _get_ecs_value(log, "fortinet.firewall.subtype") == "ips":
                log_types.add("ips")
            if _get_ecs_value(log, "event.action") in ["Add", "Delete", "password reset"]:
                log_types.add("account")
            message = str(_get_ecs_value(log, "message", "")).lower()
            if any(kw in message for kw in ["reboot", "shutdown", "startup"]):
                log_types.add("system")
            if _get_ecs_value(log, "event.action") in ["login", "logout"]:
                log_types.add("login")
    
    # 根据问题关键词和日志类型确定聚合维度
    # 1. 统计类问题：按源 IP 聚合
    if any(kw in question for kw in ["哪些", "多少", "排名", "统计", "top", "主要"]):
        if "ips" in log_types:
            return "attack_type", ["fortinet.firewall.attack", "source.ip"]
        elif "account" in log_types:
            return "account_action", ["event.action", "source.user.name"]
        elif "system" in log_types:
            return "system_event", ["message", "observer.name"]
        else:
            return "source_ip", ["source.ip"]
    
    # 2. 时间类问题：按日期聚合
    if any(kw in question for kw in ["时间", "趋势", "变化", "每天", "每小时"]):
        return "time_series", ["@timestamp", "source.ip"]
    
    # 3. 已指定过滤条件：不聚合或按剩余维度聚合
    if any(kw in question for kw in ["IP", "ip=", "用户", "user=", "admin", "root"]):
        return "minimal", ["source.ip"]  # 最小聚合
    
    # 默认按源 IP 聚合
    return "source_ip", ["source.ip"]


# ========================================
# 问题类型识别
# ========================================
def identify_question_type(question: str) -> str:
    """
    识别问题类型，决定压缩策略
    
    Args:
        question: 用户问题
        
    Returns:
        str: "aggregate" (先聚合) 或 "direct" (直接压缩)
    """
    # 统计/枚举类问题 → 先聚合
    aggregate_keywords = ["哪些", "多少", "排名", "统计", "top", "主要", "汇总", "合计", "count"]
    if any(kw in question for kw in aggregate_keywords):
        return "aggregate"
    
    # 详情查询类问题 → 直接压缩
    detail_keywords = ["显示", "查询", "详情", "详细", "具体", "记录", "尝试"]
    if any(kw in question for kw in detail_keywords):
        # 检查是否有明确过滤条件
        if re.search(r'IP\s*[\d\.]+|ip\s*=\s*[\d\.]+|用户\s*\w+|user\s*=\s*\w+', question, re.IGNORECASE):
            return "direct"
    
    # 默认直接压缩
    return "direct"


# ========================================
# LogCompressor 主类
# ========================================
class LogCompressor:
    """
    日志压缩器
    
    提供多级压缩策略：
    1. 字段压缩（保险策略）
    2. 智能聚合
    3. 语义筛选
    """
    
    def __init__(self, config: LogCompressorConfig = None):
        """
        初始化压缩器
        
        Args:
            config: 压缩配置，使用默认配置
        """
        self.config = config or DEFAULT_CONFIG
        self._tokenizer = None
        self._model = None
        self._tiktoken_encoder = None
        self._embedding_cache = {}
    
    def _load_bert_model(self):
        """加载 BERT 模型用于语义相似度计算"""
        if self._model is not None:
            return self._model, self._tokenizer
        
        transformers_lib = _get_transformers()
        if transformers_lib is None:
            # transformers 库不可用，直接返回 None
            self._model = None
            return None, None
        
        AutoTokenizer, AutoModel = transformers_lib
        
        # 确定模型路径
        model_path = self.config.model_path
        if model_path is None:
            # 尝试从缓存目录加载（容器内路径）
            cache_base = "/app/hf_cache/models--microsoft--llmlingua-2-bert-base-multilingual-cased-meetingbank"
            if os.path.exists(cache_base):
                import subprocess
                result = subprocess.run(
                    ["find", cache_base, "-name", "config.json"],
                    capture_output=True, text=True
                )
                config_files = result.stdout.strip().split("\n")
                if config_files and config_files[0]:
                    model_path = os.path.dirname(config_files[0])
        
        if model_path and os.path.exists(model_path):
            try:
                print(f"加载 BERT 模型：{model_path}")
                self._tokenizer = AutoTokenizer.from_pretrained(model_path)
                self._model = AutoModel.from_pretrained(model_path)
                self._model.eval()
            except (AttributeError, ImportError, RuntimeError) as e:
                print(f"警告：加载 BERT 模型失败：{e}，将使用简化压缩模式")
                self._model = None
        else:
            print("警告：BERT 模型路径不存在，将使用简化压缩模式")
            self._model = None
        
        return self._model, self._tokenizer
    
    def _get_tiktoken_encoder(self):
        """获取 tiktoken 编码器"""
        if self._tiktoken_encoder is None:
            try:
                tiktoken = _get_tiktoken()
                self._tiktoken_encoder = tiktoken.get_encoding("cl100k_base")
            except (ModuleNotFoundError, ImportError):
                # 开发/精简运行环境可能没有 tiktoken，使用 estimate_tokens 的字符兜底。
                self._tiktoken_encoder = False
        return self._tiktoken_encoder
    
    def estimate_tokens(self, text: str) -> int:
        """
        估算文本的 Token 数量
        
        Args:
            text: 输入文本
            
        Returns:
            int: Token 数量
        """
        encoder = self._get_tiktoken_encoder()
        if encoder is False:
            return max(1, (len(text) + 3) // 4)
        return len(encoder.encode(text))

    def estimate_log_payload_tokens(self, logs: List[Dict], summary_text: str = "") -> int:
        """估算完整日志和摘要进入 LLM 前的大致 Token 数。"""
        payload = json.dumps(logs or [], ensure_ascii=False, separators=(",", ":"))
        if summary_text:
            payload = f"{summary_text}\n{payload}"
        return self.estimate_tokens(payload)
    
    def _get_sentence_embedding(self, text: str):
        """
        获取句子的 BERT embedding
        
        Args:
            text: 输入文本
            
        Returns:
            numpy array: 句子 embedding
        """
        # 检查缓存
        if text in self._embedding_cache:
            return self._embedding_cache[text]
        
        model, tokenizer = self._load_bert_model()
        if model is None:
            return None
        
        torch = _get_torch()
        inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        with torch.no_grad():
            outputs = model(**inputs)
        embedding = outputs.last_hidden_state[0, 0].numpy()
        
        # 缓存 embedding
        self._embedding_cache[text] = embedding
        return embedding
    
    def _calculate_importance_scores(self, logs: List[Dict], question: str) -> List[float]:
        """
        计算每条日志与问题的语义相似度分数
        
        Args:
            logs: 日志列表
            question: 用户问题
            
        Returns:
            List[float]: 重要性分数列表
        """
        model, _ = self._load_bert_model()
        if model is None:
            return self._heuristic_importance_scores(logs, question)
        
        torch = _get_torch()
        question_emb = self._get_sentence_embedding(question)
        if question_emb is None:
            return self._heuristic_importance_scores(logs, question)
        
        scores = []
        for log in logs:
            log_text = json.dumps(log, ensure_ascii=False) if isinstance(log, dict) else str(log)
            log_emb = self._get_sentence_embedding(log_text)
            if log_emb is not None:
                similarity = torch.cosine_similarity(
                    torch.tensor(question_emb).unsqueeze(0),
                    torch.tensor(log_emb).unsqueeze(0)
                )
                scores.append(float(similarity))
            else:
                scores.append(0.5)  # 默认分数
        
        return scores

    def _heuristic_importance_scores(self, logs: List[Dict], question: str) -> List[float]:
        """BERT 不可用时按问题词、ECS 关键字段和时间生成确定性分数。"""
        terms = set(re.findall(r"[\w.]+|[\u4e00-\u9fff]", (question or "").lower()))
        scores = []
        for index, log in enumerate(logs):
            text = json.dumps(log, ensure_ascii=False).lower()
            overlap = sum(1 for term in terms if term and term in text)
            key_bonus = sum(
                0.1 for field in ("source.ip", "destination.ip", "source.user.name",
                                   "event.action", "event.reason", "observer.name")
                if _get_ecs_value(log, field)
            )
            # 保持稳定顺序，但不再让所有记录分数相同、退化为原始截取。
            scores.append(float(overlap) + key_bonus + index * 1e-9)
        return scores
    
    def _compress_fields(self, log: Dict) -> Dict:
        """
        字段压缩：只保留关键字段
        
        Args:
            log: 原始日志
            
        Returns:
            Dict: 压缩后的日志
        """
        if len(log) <= self.config.field_threshold:
            return log
        
        compressed = {}
        # 优先保留关键字段
        for field in self.config.key_fields:
            value = _get_ecs_value(log, field)
            if value is not None:
                compressed[field] = value
        
        # 如果关键字段不足，保留其他字段
        if len(compressed) < self.config.field_threshold:
            remaining = self.config.field_threshold - len(compressed)
            for key in list(log.keys()):
                if key not in compressed and remaining > 0:
                    compressed[key] = log[key]
                    remaining -= 1
        
        return compressed
    
    def _aggregate_logs(self, logs: List[Dict], dimension: str, group_fields: List[str]) -> List[Dict]:
        """
        聚合日志
        
        Args:
            logs: 日志列表
            dimension: 聚合维度名称
            group_fields: 分组字段列表
            
        Returns:
            List[Dict]: 聚合后的日志
        """
        # 按分组字段分组
        groups = defaultdict(list)
        for log in logs:
            key_parts = []
            for field in group_fields:
                value = _get_ecs_value(log, field, "unknown")
                key_parts.append(str(value))
            key = "|".join(key_parts)
            groups[key].append(log)
        
        # 生成聚合结果
        aggregated = []
        for key, group_logs in groups.items():
            if not group_logs:
                continue
            
            # 取第一条日志作为模板
            template = group_logs[0].copy()
            
            # 添加统计信息
            agg_result = {
                "_aggregated": True,
                "_count": len(group_logs),
                "_group_key": key,
                "_group_fields": group_fields,
            }
            
            # 保留聚合维度和图谱/分析所需的 ECS 字段。
            for field in self.config.key_fields:
                value = _get_ecs_value(template, field)
                if value is not None:
                    # 使用原始扁平字段名，避免 LLM 输入混用嵌套/旧字段。
                    agg_result[field] = value
            
            # 添加时间范围
            timestamps = []
            for log in group_logs:
                ts = _get_ecs_value(log, "timestamp")
                if ts:
                    timestamps.append(ts)
            if timestamps:
                agg_result["_time_range"] = f"{min(timestamps)} ~ {max(timestamps)}"
            
            # 添加失败次数统计（如果有）
            fail_counts = [_get_ecs_value(log, "fail_count") for log in group_logs
                           if _get_ecs_value(log, "fail_count")]
            if fail_counts:
                agg_result["_total_fail_count"] = sum(fail_counts)
                agg_result["_avg_fail_count"] = round(sum(fail_counts) / len(fail_counts), 1)
            
            # 保留 1-2 条代表性日志
            agg_result["_sample_logs"] = group_logs[:2]
            
            aggregated.append(agg_result)
        
        # 按数量排序
        aggregated.sort(key=lambda x: x.get("_count", 0), reverse=True)
        
        return aggregated
    
    def _semantic_filter(self, logs: List[Dict], question: str, keep_ratio: float = None) -> List[Dict]:
        """
        语义筛选：保留与问题最相关的日志
        
        Args:
            logs: 日志列表
            question: 用户问题
            keep_ratio: 保留比例
            
        Returns:
            List[Dict]: 筛选后的日志
        """
        if keep_ratio is None:
            keep_ratio = self.config.keep_ratio
        
        if len(logs) <= 10:
            return logs
        
        # 计算重要性分数
        scores = self._calculate_importance_scores(logs, question)
        
        # 按分数排序
        indexed = list(zip(scores, range(len(logs))))
        indexed.sort(reverse=True, key=lambda x: x[0])
        
        # 保留 Top K
        keep_count = max(10, int(len(logs) * keep_ratio))
        keep_count = min(keep_count, self.config.max_output_records)
        
        keep_indices = [idx for _, idx in indexed[:keep_count]]
        keep_indices.sort()  # 恢复原始顺序
        
        return [logs[i] for i in keep_indices]
    
    def _logs_to_text(self, logs: List[Dict], include_stats: bool = True, 
                      original_count: int = None, compression_info: str = None,
                      summary_text: str = None) -> str:
        """
        将日志列表转换为文本
        
        Args:
            logs: 日志列表
            include_stats: 是否包含统计信息
            original_count: 原始日志数量（用于标注压缩情况）
            compression_info: 压缩方式说明
            summary_text: 压缩前的统计摘要文本（重要：让 LLM 知道原始数据全貌）
            
        Returns:
            str: 日志文本
        """
        if not logs:
            return "未查询到相关日志记录"
        
        lines = []
        
        # 【新增】首先添加压缩前的统计摘要（如果提供了）
        if summary_text:
            lines.append(summary_text)
            lines.append("")
            lines.append("=== 压缩后的日志详情 ===")
            lines.append(f"【重要提示】以下是从原始 {original_count or len(logs)} 条日志中压缩/筛选/聚合后的结果，")
            lines.append("请结合上方的「原始日志统计摘要」进行综合分析，不要仅基于以下压缩后的数据进行统计！")
            lines.append("")
        
        # 添加压缩说明（如果有压缩）
        if original_count is not None and original_count != len(logs):
            lines.append(f"=== 日志压缩说明 ===")
            lines.append(f"原始日志数量：{original_count} 条")
            if compression_info and "聚合" in compression_info:
                # 聚合模式：强调是分组/分类
                lines.append(f"聚合后分组数：{len(logs)} 类（按攻击源 IP 分组统计）")
                lines.append(f"压缩方式：{compression_info}")
                lines.append(f"注意：以下为聚合后的分组统计，每条记录代表一类攻击事件，原始日志共{original_count}条")
            else:
                # 语义筛选模式：强调是筛选
                lines.append(f"筛选后保留：{len(logs)} 条")
                lines.append(f"压缩方式：{compression_info}")
                lines.append(f"注意：以下为筛选后的日志数据，原始日志共{original_count}条")
            lines.append("")
        
        # 添加统计摘要
        if include_stats and len(logs) > 5:
            lines.append(f"=== 日志摘要（共 {len(logs)} 条）===")
            
            # 统计源 IP 分布
            src_ips = defaultdict(int)
            for log in logs:
                ip = _get_ecs_value(log, "source.ip", "unknown")
                src_ips[ip] += 1
            
            lines.append(f"攻击源 IP 数量：{len(src_ips)}")
            lines.append(f"最活跃攻击源：{sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[0][0]} ({sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[0][1]} 次)")
            lines.append("")
        
        # 输出日志详情
        # 不在这里按条数截断；是否截断由 Token 预算驱动的前置筛选决定。
        for i, log in enumerate(logs, 1):
            if isinstance(log, dict):
                if log.get("_aggregated"):
                    # 聚合日志
                    lines.append(f"[{i}] 聚合记录 (共{log.get('_count', 0)}条)")
                    lines.append(f"    源 IP: {_get_ecs_value(log, 'source.ip', 'N/A')}")
                    lines.append(f"    事件类型：{_get_ecs_value(log, 'event.action', 'N/A')}")
                    lines.append(f"    时间范围：{log.get('_time_range', 'N/A')}")
                    if log.get('_total_fail_count'):
                        lines.append(f"    总失败次数：{log.get('_total_fail_count')}")
                else:
                    # 普通日志
                    lines.append(f"[{i}] {json.dumps(log, ensure_ascii=False)}")
            else:
                lines.append(f"[{i}] {str(log)}")
        
        return "\n".join(lines)
    
    def compress(self, logs: List[Dict], question: str = "", 
                 mode: str = "auto", return_format: str = "text", 
                 include_summary: bool = True, preset_summary_text: str = None) -> Any:
        """
        压缩日志
        
        Args:
            logs: 日志列表
            question: 用户问题（用于语义筛选）
            mode: 压缩模式 ("auto" | "aggregate" | "direct")
            return_format: 返回格式 ("text" | "json" | "list")
            include_summary: 是否包含压缩前的统计摘要（重要：让 LLM 知道原始数据全貌）
            preset_summary_text: 预先生成的统计摘要文本（如果提供，则直接使用此摘要，不再生成新的）
            
        Returns:
            压缩后的日志（格式由 return_format 指定）
        """
        if not logs:
            return "未查询到相关日志记录" if return_format == "text" else []
        
        # 保存原始日志数量
        original_count = len(logs)
        compression_applied = None
        
        # 【新增】在压缩前生成统计摘要，保留原始数据的全貌信息
        # 如果提供了 preset_summary_text，则直接使用，不再生成新的摘要
        summary_stats = None
        summary_text = preset_summary_text
        if include_summary and preset_summary_text is None:
            summary_stats = generate_summary_statistics(logs)
            summary_text = format_summary_text(summary_stats)
            print(f"[LogCompressor] 已生成压缩前统计摘要：原始记录{original_count}条，{summary_stats.get('unique_src_ip_count', 0)}个源 IP")
        elif preset_summary_text:
            print(f"[LogCompressor] 使用预先生成的统计摘要")
        
        # 自动判断模式
        if mode == "auto":
            mode = identify_question_type(question)
        
        print(f"[LogCompressor] 压缩模式：{mode}, 原始记录数：{original_count}")
        
        # 步骤 1: 字段压缩（保险策略）
        if len(logs) > 0 and isinstance(logs[0], dict):
            sample_fields = len(logs[0])
            if sample_fields > self.config.field_threshold:
                print(f"[LogCompressor] 触发字段压缩（字段数：{sample_fields}）")
                logs = [self._compress_fields(log) for log in logs]
        
        # 步骤 2: 根据模式选择压缩策略
        if mode == "aggregate" and len(logs) >= self.config.aggregate_threshold:
            # 先聚合再压缩
            dim_type, group_fields = identify_aggregate_dimension(logs, question)
            print(f"[LogCompressor] 聚合维度：{dim_type}, 分组字段：{group_fields}")
            logs = self._aggregate_logs(logs, dim_type, group_fields)
            compression_applied = "智能聚合（按攻击源 IP 分组统计）"
            print(f"[LogCompressor] 聚合后记录数：{len(logs)}")
        
        # 步骤 3: 先估算当前输出，只有超出 Token 预算才做语义筛选。
        text_output = self._logs_to_text(logs, original_count=original_count if original_count != len(logs) else None, 
                                         compression_info=compression_applied,
                                         summary_text=summary_text)
        token_count = self.estimate_tokens(text_output)
        print(f"[LogCompressor] 预估 Token 数：{token_count}")

        if token_count > self.config.max_output_tokens and question and len(logs) > self.config.max_output_records:
            print(f"[LogCompressor] 超出 Token 预算，触发语义筛选（记录数：{len(logs)}）")
            logs = self._semantic_filter(logs, question)
            compression_applied = "语义筛选（Token 预算内保留相关日志）"
            print(f"[LogCompressor] 语义筛选后记录数：{len(logs)}")
            text_output = self._logs_to_text(
                logs,
                original_count=original_count,
                compression_info=compression_applied,
                summary_text=summary_text,
            )
            token_count = self.estimate_tokens(text_output)
            print(f"[LogCompressor] 语义筛选后预估 Token 数：{token_count}")

        # 如果 Token 数仍然超限，进一步降低保留比例
        if token_count > self.config.max_output_tokens and len(logs) > 5:
            print(f"[LogCompressor] Token 数超限（{token_count} > {self.config.max_output_tokens}），进一步压缩")
            logs = logs[:self.config.max_output_records]
            text_output = self._logs_to_text(
                logs,
                original_count=original_count,
                compression_info=f"{compression_applied or ''} + Token 限制截断".strip(),
                summary_text=summary_text,
            )
            token_count = self.estimate_tokens(text_output)
            print(f"[LogCompressor] 截断后预估 Token 数：{token_count}")
        
        # 返回结果
        if return_format == "text":
            return text_output
        elif return_format == "json":
            return json.dumps(logs, ensure_ascii=False, indent=2)
        else:  # list
            return logs
    
    def compress_for_llm(self, logs: List[Dict], question: str, 
                         max_tokens: int = None, summary_text: str = None) -> str:
        """
        专门为 LLM 输入压缩日志
        
        Args:
            logs: 日志列表
            question: 用户问题
            max_tokens: 最大 Token 数
            summary_text: 预先生成的统计摘要文本（可选，如果提供则直接使用，不再生成）
            
        Returns:
            str: 压缩后的日志文本
        """
        if max_tokens:
            self.config.max_output_tokens = max_tokens
        
        # 如果提供了预先生成的摘要，则不再生成新的摘要
        include_summary = summary_text is None
        
        return self.compress(logs, question, mode="auto", return_format="text", 
                            include_summary=include_summary, 
                            preset_summary_text=summary_text)


# ========================================
# 便捷函数
# ========================================
def compress_logs(logs: List[Dict], question: str = "", 
                  mode: str = "auto") -> str:
    """
    便捷函数：压缩日志
    
    Args:
        logs: 日志列表
        question: 用户问题
        mode: 压缩模式
        
    Returns:
        str: 压缩后的日志文本
    """
    compressor = LogCompressor()
    return compressor.compress(logs, question, mode)


def estimate_log_tokens(logs: List[Dict], summary_text: str = None) -> int:
    """
    估算日志的 Token 数量
    
    Args:
        logs: 日志列表
        
    Returns:
        int: Token 数量
    """
    compressor = LogCompressor()
    if summary_text is None and logs:
        summary_text = format_summary_text(generate_summary_statistics(logs))
    return compressor.estimate_log_payload_tokens(logs, summary_text or "")
