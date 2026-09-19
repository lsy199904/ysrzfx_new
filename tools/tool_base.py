# -*- coding: utf-8 -*-
"""
工具基类模块
提供通用的工具执行框架，包括：
- Redis 缓存管理
- 日志压缩逻辑
- 结果构建逻辑

各安全监控工具只需继承此基类，提供 PPL 模板和工具名称即可。
"""
import json
import hashlib
import asyncio
import contextvars
from typing import Optional, Dict, Any, Callable
from datetime import datetime
from config import (
    CACHE_TOOL_TTL,
    COMPRESSION_MAX_RETURN_DATA,
    COMPRESSION_MAX_TOKENS,
    COMPRESSION_THRESHOLD,
)
# 兼容 langchain 0.0.354 和 0.1.x 版本
try:
    from langchain.agents import Tool
    from langchain.schema import AgentFinish
except ImportError:
    # 针对 langchain 0.1+
    from langchain_core.tools import Tool
    from langchain_core.agents import AgentFinish
import asyncio
import logging
# Import AgentExecutor for legacy support
from langchain.agents import AgentExecutor
# ============================================
# 自定义 AgentExecutor：支持工具提前终止
# ============================================
class EarlyStopAgentExecutor(AgentExecutor):
    """
    自定义 AgentExecutor，在工具返回特殊标记时提前终止循环，不调用 LLM。
    用于索引探测失败等兜底场景。
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    # EarlyStopAgentExecutor 的核心功能由 sever.py 中的
    # on_tool_end 检测 __agent_stop__ 并调用 task_ref.cancel() 实现。
    # 此处留空，等待 on_tool_end 主动终止。


# ============================================
# 请求级认证上下文（contextvars）
# ============================================
# 用于跨 async 链路传递用户认证信息，LLM 不可见、不可伪造
import contextvars
request_ctx = contextvars.ContextVar('request_context', default=None)


# ============================================
# Redis 缓存管理器（全局单例）
# ============================================
class ToolCacheManager:
    """工具缓存管理器"""
    
    _redis_manager = None
    _initialized = False
    
    @classmethod
    async def _get_redis_manager(cls):
        """获取 Redis 管理器（延迟导入）"""
        if not cls._initialized:
            try:
                from utils.redis_manager import get_redis_manager
                cls._redis_manager = get_redis_manager()
                success = await cls._redis_manager.initialize()
                if not success:
                    print(f"Redis 初始化失败")
                    cls._redis_manager = None
            except Exception as e:
                print(f"Redis 初始化失败：{e}")
                cls._redis_manager = None
            cls._initialized = True
        return cls._redis_manager
    
    @classmethod
    def _get_cache_key(cls, tool_name: str, params: dict) -> str:
        """生成缓存 Key"""
        param_str = json.dumps(params, sort_keys=True, ensure_ascii=False)
        param_hash = hashlib.md5(param_str.encode()).hexdigest()
        return f"cache:tool:{tool_name}:{param_hash}"
    
    @classmethod
    async def get_cached_result(cls, tool_name: str, params: dict) -> Optional[dict]:
        """从 Redis 获取缓存结果"""
        cache_key = cls._get_cache_key(tool_name, params)
        mgr = await cls._get_redis_manager()
        if mgr:
            loop = asyncio.get_event_loop()
            data = await loop.run_in_executor(None, mgr.client.get, cache_key)
            if data:
                print(f"\n=== 缓存命中 ===")
                print(f"缓存 Key: {cache_key}")
                return json.loads(data)
        return None
    
    @classmethod
    async def save_cached_result(cls, tool_name: str, params: dict, data: dict, ttl: int = 300):
        """保存结果到 Redis 缓存"""
        cache_key = cls._get_cache_key(tool_name, params)
        mgr = await cls._get_redis_manager()
        if mgr:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: mgr.client.setex(cache_key, ttl, json.dumps(data, ensure_ascii=False))
            )
            print(f"\n=== 缓存已保存 ===")


# ============================================
# 通用压缩配置
# ============================================
from dataclasses import dataclass, field

@dataclass
class CompressionConfig:
    """压缩配置"""
    # 压缩触发阈值：数据量 >= 此值时触发压缩
    threshold: int = COMPRESSION_THRESHOLD
    
    # 统计类关键词（触发压缩）
    aggregate_keywords: list = field(default_factory=lambda: ["哪些", "多少", "排名", "统计", "top", "主要"])
    
    # Token 限制
    max_tokens: int = COMPRESSION_MAX_TOKENS
    
    # 返回原始数据条数限制
    max_return_data: int = COMPRESSION_MAX_RETURN_DATA


# ============================================
# 通用工具执行器
# ============================================
class ToolExecutor:
    """
    通用工具执行器
    
    使用示例：
    ```python
    def account_security_monitor_request(user_problem: str = "", ...):
        executor = ToolExecutor(
            tool_name="account_security_monitor",
            ppl_template=PPL_TEMPLATE,
            user_problem=user_problem,
            start_time=start_time,
            end_time=end_time,
            filter_ip=filter_ip,
            filter_user=filter_user,
            gid=gid,
        )
        return executor.execute()
    ```
    """
    
    def __init__(
        self,
        tool_name: str,
        ppl_template: str,
        user_problem: str = "",
        start_time: str = None,
        end_time: str = None,
        filter_ip: str = None,
        filter_user: str = None,
        gid: str = None,
        ip_field: str = "srcip",
        # 数据权限：gid_scope 从 request_ctx 自动注入，也可显式传入
        gid_scope: dict = None,
        # 可选的自定义配置
        compression_config: CompressionConfig = None,
        # 可选的额外处理函数
        preprocess_hook: Callable = None,  # 在查询前处理参数
        postprocess_hook: Callable = None,  # 在返回前处理结果
        cache_version: str = None,
    ):
        self.tool_name = tool_name
        self.ppl_template = ppl_template
        self.user_problem = user_problem
        self.start_time = start_time
        self.end_time = end_time
        self.filter_ip = filter_ip
        self.filter_user = filter_user
        self.gid = gid
        self.ip_field = ip_field
        self.cache_version = cache_version
        # 数据权限上下文：优先使用显式传入，否则从 contextvars 自动获取
        self.gid_scope = gid_scope or (request_ctx.get() if request_ctx.get() else None)
        self.compression_config = compression_config or CompressionConfig()
        self.preprocess_hook = preprocess_hook
        self.postprocess_hook = postprocess_hook
        
        # 导入依赖
        from tools.common_config import (
            extract_ip_from_text, extract_username_from_text, extract_gid_from_text,
            normalize_time_param,
            build_ppl_query, query_es, ES_AUTH_USER, ES_AUTH_PASSWORD, ES_HOST, ES_PORT
        )
        from utils.log_compressor import LogCompressor, generate_summary_statistics, format_summary_text
        
        self.extract_ip_from_text = extract_ip_from_text
        self.extract_username_from_text = extract_username_from_text
        self.extract_gid_from_text = extract_gid_from_text
        self.normalize_time_param = normalize_time_param
        self.build_ppl_query = build_ppl_query
        self.query_es = query_es
        self.ES_AUTH_USER = ES_AUTH_USER
        self.ES_AUTH_PASSWORD = ES_AUTH_PASSWORD
        self.ES_HOST = ES_HOST
        self.ES_PORT = ES_PORT
        self.LogCompressor = LogCompressor
        self.generate_summary_statistics = generate_summary_statistics
        self.format_summary_text = format_summary_text
    
    def _print_debug_info(self):
        """打印调试信息"""
        print(f"\n{'='*60}")
        print(f"[{self.tool_name.upper()}] 开始执行查询")
        print(f"[{self.tool_name.upper()}] 用户问题：{self.user_problem[:200] if self.user_problem else 'N/A'}")
        print(f"[{self.tool_name.upper()}] 传入参数:")
        print(f"[{self.tool_name.upper()}]   - start_time: {self.start_time}")
        print(f"[{self.tool_name.upper()}]   - end_time: {self.end_time}")
        print(f"[{self.tool_name.upper()}]   - filter_ip: {self.filter_ip}")
        print(f"[{self.tool_name.upper()}]   - filter_user: {self.filter_user}")
        print(f"[{self.tool_name.upper()}]   - gid: {self.gid}")
    
    def _extract_filters(self):
        """从用户问题中提取过滤条件"""
        if not self.filter_ip:
            self.filter_ip = self.extract_ip_from_text(self.user_problem)
        if not self.filter_user:
            self.filter_user = self.extract_username_from_text(self.user_problem)
        if not self.gid:
            self.gid = self.extract_gid_from_text(self.user_problem)
    
    def _normalize_time(self):
        """标准化时间参数"""
        self.start_time = self.normalize_time_param(self.start_time, self.user_problem, is_start_time=True)
        self.end_time = self.normalize_time_param(self.end_time, self.user_problem, is_start_time=False)
    
    def _build_ppl_query(self) -> str:
        """构建 PPL 查询"""
        return self.build_ppl_query(
            self.ppl_template,
            self.start_time,
            self.end_time,
            self.filter_ip,
            self.filter_user,
            self.gid,
            self.ip_field,
            self.gid_scope  # 传入数据权限上下文
        )
    
    def _check_cache(self) -> Optional[dict]:
        """检查缓存"""
        # 从 gid_scope 提取 login_account 加入缓存 key，防止不同用户互相命中缓存
        login_account = ""
        allowed_gids_hash = ""
        if self.gid_scope:
            login_account = self.gid_scope.get("login_account", "")
            allowed_gids = self.gid_scope.get("allowed_gids")
            if allowed_gids:
                import hashlib
                allowed_gids_hash = hashlib.md5(json.dumps(sorted(allowed_gids), sort_keys=True).encode()).hexdigest()[:8]
        
        from tools.index_config import INDEX_SOURCE_PATTERN
        cache_params = {
            "user_problem": self.user_problem,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "filter_ip": self.filter_ip,
            "filter_user": self.filter_user,
            "gid": self.gid,
            "is_admin": bool(self.gid_scope and self.gid_scope.get("is_admin", False)),
            "index_source_pattern": INDEX_SOURCE_PATTERN,
            "login_account": login_account,  # 按账号隔离缓存
            "allowed_gids_hash": allowed_gids_hash,  # 按权限范围隔离缓存
        }
        if self.cache_version:
            cache_params["cache_version"] = self.cache_version
        
        try:
            # 【修复】使用安全异步运行器，确保 contextvars 正确传播
            cached_data = self._run_async(ToolCacheManager.get_cached_result(self.tool_name, cache_params))
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
                return result
        except Exception as e:
            print(f"缓存检查失败：{e}")
        return None
    
    def _save_cache(self, cache_data: dict):
        """保存缓存"""
        # 从 gid_scope 提取 login_account 加入缓存 key
        login_account = ""
        allowed_gids_hash = ""
        if self.gid_scope:
            login_account = self.gid_scope.get("login_account", "")
            allowed_gids = self.gid_scope.get("allowed_gids")
            if allowed_gids:
                import hashlib
                allowed_gids_hash = hashlib.md5(json.dumps(sorted(allowed_gids), sort_keys=True).encode()).hexdigest()[:8]
        
        from tools.index_config import INDEX_SOURCE_PATTERN
        cache_params = {
            "user_problem": self.user_problem,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "filter_ip": self.filter_ip,
            "filter_user": self.filter_user,
            "gid": self.gid,
            "is_admin": bool(self.gid_scope and self.gid_scope.get("is_admin", False)),
            "index_source_pattern": INDEX_SOURCE_PATTERN,
            "login_account": login_account,  # 按账号隔离缓存
            "allowed_gids_hash": allowed_gids_hash,  # 按权限范围隔离缓存
        }
        if self.cache_version:
            cache_params["cache_version"] = self.cache_version
        try:
            # 【修复】使用安全异步运行器
            self._run_async(ToolCacheManager.save_cached_result(self.tool_name, cache_params, cache_data, ttl=CACHE_TOOL_TTL))
        except Exception as e:
            print(f"缓存保存失败：{e}")

    def _run_async(self, coro):
        """
        安全地运行异步协程，处理 contextvars 传播问题
        在同步代码中调用异步方法时，确保当前上下文的 contextvars 被传递
        """
        import asyncio
        try:
            loop = asyncio.get_running_loop()
            # 如果在异步上下文中，直接运行，不要创建新循环
            # 注意：这要求 caller 是 async 的，并且我们不在已经运行的循环中嵌套 run
            return loop.run_until_complete(coro)
        except RuntimeError:
            pass
        
        # 如果没有运行中的循环，创建新的
        loop = asyncio.new_event_loop()
        try:
            # 捕获当前上下文
            ctx = contextvars.copy_context()
            # 在新循环中运行
            return loop.run_until_complete(coro, context=ctx) if hasattr(loop, 'run_until_complete') and 'context' in loop.run_until_complete.__code__.co_varnames else loop.run_until_complete(coro)
        except Exception as e:
            raise e
        finally:
            loop.close()
    
    def _needs_compression(self, count: int) -> bool:
        """判断是否需要压缩"""
        # 条件 1：数据量 >= 阈值
        if count >= self.compression_config.threshold:
            return True
        # 条件 2：问题包含统计类关键词
        if any(kw in self.user_problem for kw in self.compression_config.aggregate_keywords):
            return True
        return False
    
    def _build_compression_info(
        self,
        data: list,
        count: int,
        user_problem: str,
        needs_compression: bool
    ) -> tuple:
        """
        构建压缩信息
        
        Returns:
            tuple: (compression_info, summary_text)
        """
        compression_info = {"compressed": False, "original_count": count}
        summary_text = ""
        
        # 始终生成统计摘要
        if data:
            summary_stats = self.generate_summary_statistics(data)
            summary_text = self.format_summary_text(summary_stats)
            print(f"[LogCompressor] 已生成统计摘要：原始记录{count}条，{summary_stats.get('unique_src_ip_count', 0)}个源 IP")
        
        if needs_compression and data:
            print(f"\n=== 触发日志压缩 ===")
            print(f"原始数据量：{count} 条")
            print(f"[LogCompressor] 使用已生成的统计摘要进行压缩")
            
            compressor = self.LogCompressor()
            compressed_text = compressor.compress_for_llm(
                logs=data,
                question=user_problem,
                max_tokens=self.compression_config.max_tokens,
                summary_text=summary_text
            )
            
            # 获取压缩后的实际记录数（从 compressed_text 中解析聚合后的记录数）
            import re
            compressed_count = count  # 默认使用原始数量
            
            # 匹配"聚合后分组数：X 类"格式（log_compressor.py 输出的格式）
            match = re.search(r'聚合后分组数：(\d+)', compressed_text)
            if match:
                compressed_count = int(match.group(1))
            
            # 匹配"筛选后保留：X 条"格式
            if compressed_count == count:
                match = re.search(r'筛选后保留：(\d+)', compressed_text)
                if match:
                    compressed_count = int(match.group(1))
            
            print(f"压缩后 Token 数：{compressor.estimate_tokens(compressed_text)}")
            print(f"压缩后记录数：{compressed_count} 条")
            
            compression_info = {
                "compressed": True,
                "original_count": count,
                "compressed_count": compressed_count,
                "compressed_text": compressed_text,
                "summary_text": summary_text
            }
        else:
            # 未压缩时也保存 summary_text
            compression_info["summary_text"] = summary_text
        
        return compression_info, summary_text
    
    def _is_chinese(self, text: str) -> bool:
        """判断文本是否包含中文字符"""
        for char in text:
            if '\u4e00' <= char <= '\u9fff':
                return True
        return False
    
    def _build_steps(
        self,
        ppl_query: str,
        http_status: int,
        error_msg: str,
        count: int,
        compression_info: dict
    ) -> list:
        """构建步骤信息"""
        # 根据用户问题判断语言
        is_chinese = self._is_chinese(self.user_problem)

        if is_chinese:
            if compression_info.get("compressed"):
                result_detail = f"原始记录 {count} 条，压缩后 {compression_info.get('compressed_count', 0)} 条"
            else:
                result_detail = f"共查询到 {count} 条记录"

            # 构建基础步骤
            steps = [
                {
                    "step": 1,
                    "title": "解析用户问题",
                    "detail": f"查询时间：{self.start_time or '未指定'} ~ {self.end_time or '未指定'}, IP 过滤：{self.filter_ip or '无'}, 用户过滤：{self.filter_user or '无'}"
                },
                {
                    "step": 2,
                    "title": "构建 PPL 查询",
                    "detail": ppl_query,
                    "is_code": True
                },
                {
                    "step": 3,
                    "title": "执行 API 查询",
                    "detail": f"HTTP 状态码：{http_status}" + (f", 错误：{error_msg}" if error_msg else "")
                },
                {
                    "step": 4,
                    "title": "返回结果",
                    "detail": result_detail
                }
            ]

            # 如果有索引探测步骤，插入"索引存在性探测"步骤，后续步骤顺延为连续整数
            if getattr(self, 'index_check_steps', None):
                steps.insert(1, self.index_check_steps[0])
                for i in range(2, len(steps)):
                    steps[i]["step"] = i + 1

            return steps
        else:
            if compression_info.get("compressed"):
                result_detail = f"Original: {count} records, Compressed: {compression_info.get('compressed_count', 0)} records"
            else:
                result_detail = f"Total {count} records found"

            steps = [
                {
                    "step": 1,
                    "title": "Parse User Question",
                    "detail": f"Query Time: {self.start_time or 'Not specified'} ~ {self.end_time or 'Not specified'}, IP Filter: {self.filter_ip or 'None'}, User Filter: {self.filter_user or 'None'}"
                },
                {
                    "step": 2,
                    "title": "Build PPL Query",
                    "detail": ppl_query,
                    "is_code": True
                },
                {
                    "step": 3,
                    "title": "Execute API Query",
                    "detail": f"HTTP Status: {http_status}" + (f", Error: {error_msg}" if error_msg else "")
                },
                {
                    "step": 4,
                    "title": "Return Results",
                    "detail": result_detail
                }
            ]

            # 如果探测过索引，插入“索引存在性探测”作为步骤 2，后续步骤顺延
            if getattr(self, 'index_check_steps', None):
                detection_step = self.index_check_steps[0].copy()
                detection_step["step"] = 2
                steps.insert(1, detection_step)
                for i in range(2, len(steps)):
                    steps[i]["step"] = i + 1

            return steps

    def execute(self) -> str:
        """
        执行工具查询

        Returns:
            str: JSON 格式的查询结果
        """
        # 确保 user_problem 是字符串
        if self.user_problem is None:
            self.user_problem = ""
        elif isinstance(self.user_problem, dict):
            self.user_problem = str(self.user_problem)

        # 先从用户原文提取 gid，再做权限判断，避免 gid 未作为工具参数传入时漏检。
        self._extract_filters()

        # 【数据权限】入口越权拦截：gid 参数不在白名单内时直接返回固定模板，
        # 不再执行查询（带 suggestion 字段，agent_chat 会直推 final_answer）
        from tools.ppl_guard import is_gid_empty, check_gid_allowed, build_denied_result, normalize_allowed_gids
        if self.gid_scope is not None:
            allowed_gids = self.gid_scope.get("allowed_gids")
            is_admin = self.gid_scope.get("is_admin", False)
            if allowed_gids is not None and not is_admin:
                if not is_gid_empty(self.gid) and not check_gid_allowed(self.gid, allowed_gids):
                    print(f"[{self.tool_name.upper()}] [GID_GUARD] 越权拦截：gid={self.gid}，白名单：{normalize_allowed_gids(allowed_gids)}")
                    return build_denied_result(
                        self.gid,
                        allowed_gids,
                        is_chinese=self._is_chinese(self.user_problem),
                    )

        # 打印调试信息
        self._print_debug_info()
        
        # 标准化时间
        self._normalize_time()
        
        # 执行预处理钩子
        if self.preprocess_hook:
            self.preprocess_hook(self)
        
        # 【新增】索引存在性探测（在缓存检查之前，不依赖通配符）
        # 索引存在性探测独立于查询构造，确保缓存命中时也能拦截无效索引。
        # 必须在缓存检查之前运行，确保所有查询（包括缓存命中）都能被拦截无效索引
        print(f"[GID_GUARD_DEBUG] execute() entering index check section. gid_scope={self.gid_scope}, gid={self.gid}")
        self.index_check_info = None
        self.index_check_error = None
        self.index_check_steps = None
        from tools.ppl_guard import check_index_existence, build_index_invalid_result, is_gid_empty, normalize_allowed_gids
        if self.gid_scope is not None:
            allowed_gids = self.gid_scope.get("allowed_gids")
            if allowed_gids is not None:
                index_info, exists, err_msg = check_index_existence(
                    self.gid, allowed_gids,
                    host=self.ES_HOST, port=self.ES_PORT,
                    user=self.ES_AUTH_USER, password=self.ES_AUTH_PASSWORD,
                    start_time=self.start_time, end_time=self.end_time,
                )
                self.index_check_info = index_info
                print(f"[{self.tool_name.upper()}] [GID_GUARD] 索引探测：gids={self.gid or '全部白名单'}, exists={exists}")
                if err_msg:
                    # 索引不存在 -> early-stop，直接返回兜底消息
                    print(f"[{self.tool_name.upper()}] [GID_GUARD] 索引探测拦截：{err_msg}")
                    self.index_check_error = err_msg
                # 无论索引是否存在，都记录探测步骤，供前端步骤列表展示
                from tools.index_config import INDEX_SOURCE_PATTERN
                actual_pattern = index_info.get("pattern", INDEX_SOURCE_PATTERN)
                self.index_check_steps = [{
                    "step": 1,
                    "title": "索引存在性探测",
                    "detail": f"探测索引模式：{actual_pattern}\n探测用户组：{self.gid or '全部白名单'}\n探测结果：{'存在' if exists else '不存在'}",
                }]
                
                if err_msg:
                    specific = self.gid if not is_gid_empty(self.gid) else None
                    result = build_index_invalid_result(
                        specific,
                        normalize_allowed_gids(allowed_gids),
                        pattern=actual_pattern,
                        is_chinese=self._is_chinese(self.user_problem),
                    )
                    # 附加步骤信息以便前端展示
                    try:
                        res_obj = json.loads(result)
                        res_obj["steps"] = self.index_check_steps
                        result = json.dumps(res_obj, ensure_ascii=False)
                    except (json.JSONDecodeError, TypeError):
                        pass
                    return result

        # 检查缓存
        cached_result = self._check_cache()
        if cached_result:
            # 如果探测过索引，统一附加步骤信息到缓存结果
            if self.index_check_steps:
                existing_steps = cached_result.get("steps", [])
                cached_result["steps"] = self.index_check_steps + existing_steps
            return json.dumps(cached_result, ensure_ascii=False)

        # 构建 PPL 查询
        ppl_query = self._build_ppl_query()
        print(f"\n[{self.tool_name.upper()}] === PPL 查询（原始）===")
        print(ppl_query)

        # enforce_gid_permission（二次确认：gid 注入 + 通配符展开）
        from tools.ppl_guard import enforce_gid_permission
        if self.gid_scope is not None:
            allowed_gids = self.gid_scope.get("allowed_gids")
            is_admin = self.gid_scope.get("is_admin", False)
            if allowed_gids is not None:
                ppl_query, _ = enforce_gid_permission(
                    ppl_query, allowed_gids,
                    host=self.ES_HOST, port=self.ES_PORT,
                    user=self.ES_AUTH_USER, password=self.ES_AUTH_PASSWORD,
                    start_time=self.start_time, end_time=self.end_time,
                    skip_gid_injection=is_admin,  # 管理员跳过 gid 条件注入，仅做索引展开
                    requested_gid=self.gid,
                )
        
        print(f"\n[{self.tool_name.upper()}] === PPL 查询（权限处理后）===")
        print(ppl_query)
        
        # 执行 ES 查询
        result = self.query_es(ppl_query, self.ES_AUTH_USER, self.ES_AUTH_PASSWORD)
        
        ppl_query_str = result.get("ppl_query", "")
        error_msg = result.get("error", "")
        http_status = result.get("http_status", 0)
        data = result.get("data", [])
        count = result.get("count", 0)
        
        # 判断是否需要压缩
        needs_comp = self._needs_compression(count)
        
        # 构建压缩信息
        compression_info, summary_text = self._build_compression_info(
            data, count, self.user_problem, needs_comp
        )
        
        # 构建返回数据（只保留前 N 条）
        final_data = data[:self.compression_config.max_return_data]
        final_count = count
        
        # 构建步骤
        steps = self._build_steps(ppl_query_str, http_status, error_msg, final_count, compression_info)
        
        # 构建最终结果
        final_result = {
            "steps": steps,
            "ppl_query": ppl_query_str,
            "http_status": http_status,
            "error": error_msg,
            "count": final_count,
            "data": final_data,
            "compression": compression_info
        }
        
        # 执行后处理钩子
        if self.postprocess_hook:
            final_result = self.postprocess_hook(final_result)
        
        # 保存缓存
        cache_data = {
            "ppl_query": ppl_query_str,
            "http_status": http_status,
            "error": error_msg,
            "count": final_count,
            "data": final_data,
            "compression": compression_info
        }
        if http_status == 200 and not error_msg:
            self._save_cache(cache_data)
        else:
            print(f"[{self.tool_name.upper()}] 查询失败，不缓存结果：http_status={http_status}")
        
        return json.dumps(final_result, ensure_ascii=False)


# ============================================
# 便捷函数
# ============================================
def create_tool_request(
    tool_name: str,
    ppl_template: str,
    compression_config: CompressionConfig = None
):
    """
    创建工具请求函数的工厂函数
    
    使用示例：
    ```python
    account_security_monitor_request = create_tool_request(
        tool_name="account_security_monitor",
        ppl_template=PPL_TEMPLATE,
    )
    ```
    """
    def request_func(
        user_problem: str = "",
        start_time: str = None,
        end_time: str = None,
        filter_ip: str = None,
        filter_user: str = None,
        gid: str = None,
        ip_field: str = "srcip",
    ) -> str:
        executor = ToolExecutor(
            tool_name=tool_name,
            ppl_template=ppl_template,
            user_problem=user_problem,
            start_time=start_time,
            end_time=end_time,
            filter_ip=filter_ip,
            filter_user=filter_user,
            gid=gid,
            compression_config=compression_config,
        )
        return executor.execute()
    
    return request_func
