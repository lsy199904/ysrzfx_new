# -*- coding: utf-8 -*-
"""
Redis Manager - 统一的 Redis 管理器

提供以下功能：
1. 会话管理：会话历史、场景状态、用户会话列表
2. 工具缓存：工具调用结果缓存
3. 查询缓存：PPL 查询结果缓存
4. 分布式锁：并发控制
5. 限流控制：API 限流
6. 消息队列：异步任务处理

使用示例：
    redis_mgr = RedisManager()
    await redis_mgr.initialize()
    
    # 会话管理
    await redis_mgr.save_session(session_id, history)
    history = await redis_mgr.get_session(session_id)
    
    # 工具缓存
    await redis_mgr.cache_tool_result("brute_force", params_hash, result, ttl=300)
    cached = await redis_mgr.get_cached_tool_result("brute_force", params_hash)
    
    # 分布式锁
    async with redis_mgr.lock(f"lock:session:{session_id}"):
        # 临界区代码
        pass
    
    # 限流控制
    allowed = await redis_mgr.check_rate_limit(session_id, limit=10, window=60)
"""

import asyncio
import hashlib
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

import redis  # 使用同步客户端，避免事件循环问题

logger = logging.getLogger(__name__)


class RedisManager:
    """统一的 Redis 管理器"""
    
    # Redis Key 前缀
    KEY_PREFIX = {
        "session": "session",
        "cache_tool": "cache:tool",
        "cache_query": "cache:query",
        "lock": "lock",
        "ratelimit": "ratelimit",
        "queue": "queue",
        "user": "user",
    }
    
    # 默认过期时间（秒）
    DEFAULT_TTL = {
        "session": 3600,        # 会话 1 小时
        "cache_tool": 300,      # 工具缓存 5 分钟
        "cache_query": 600,     # 查询缓存 10 分钟
        "ratelimit": 60,        # 限流 1 分钟
        "lock": 30,             # 锁超时 30 秒
    }
    
    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: Optional[str] = None,
        decode_responses: bool = True,
        socket_timeout: float = 5.0,
        socket_connect_timeout: float = 5.0,
        retry_on_timeout: bool = True,
        max_connections: int = 50,
    ):
        """
        初始化 Redis 管理器
        
        Args:
            host: Redis 主机地址
            port: Redis 端口
            db: Redis 数据库编号
            password: Redis 密码（可选）
            decode_responses: 是否自动解码响应
            socket_timeout: Socket 超时时间
            socket_connect_timeout: 连接超时时间
            retry_on_timeout: 超时是否重试
            max_connections: 最大连接数
        """
        self.config = {
            "host": host,
            "port": port,
            "db": db,
            "password": password,
            "decode_responses": decode_responses,
            "socket_timeout": socket_timeout,
            "socket_connect_timeout": socket_connect_timeout,
            "retry_on_timeout": retry_on_timeout,
            "max_connections": max_connections,
        }
        self._pool: Optional[redis.ConnectionPool] = None
        self._client: Optional[redis.Redis] = None
        self._initialized = False
    
    async def initialize(self) -> bool:
        """初始化连接池和客户端（异步方式）
        
        Returns:
            bool: 初始化成功返回 True，失败返回 False
        """
        if self._initialized:
            return True
        
        try:
            # 使用同步 Redis 客户端，在 executor 中运行以避免阻塞事件循环
            self._client = redis.Redis(
                host=self.config['host'],
                port=self.config['port'],
                db=self.config['db'],
                password=self.config.get('password'),
                decode_responses=self.config.get('decode_responses', True),
                socket_timeout=self.config.get('socket_timeout', 5.0),
                socket_connect_timeout=self.config.get('socket_connect_timeout', 5.0),
                retry_on_timeout=self.config.get('retry_on_timeout', True),
            )
            # 测试连接
            self._client.ping()
            self._initialized = True
            logger.info(f"Redis 连接成功：{self.config['host']}:{self.config['port']}")
            return True
        except Exception as e:
            logger.error(f"Redis 连接失败：{e}")
            self._initialized = False
            return False
    
    async def close(self):
        """关闭连接池"""
        if self._client:
            self._client.close()
            self._client = None
        if self._pool:
            self._pool.disconnect()
            self._pool = None
        self._initialized = False
        logger.info("Redis 连接已关闭")
    
    @property
    def client(self) -> redis.Redis:
        """获取 Redis 客户端（带健康检查）"""
        if not self._initialized or self._client is None:
            raise RuntimeError("Redis 未初始化，请先调用 initialize()")
        return self._client
    
    async def _ensure_connection(self):
        """确保连接有效，必要时重新连接"""
        try:
            # 在 executor 中运行同步 ping 方法
            loop = asyncio.get_event_loop()
            await asyncio.wait_for(
                loop.run_in_executor(None, self.client.ping),
                timeout=2.0
            )
        except Exception:
            logger.warning("Redis 连接失效，尝试重新初始化...")
            self._initialized = False
            await self.initialize()
    
    # ==================== 会话管理 ====================
    
    def _session_key(self, session_id: str, suffix: str = "history") -> str:
        """生成会话 Key"""
        return f"{self.KEY_PREFIX['session']}:{session_id}:{suffix}"
    
    async def save_session(
        self,
        session_id: str,
        history: List[Dict],
        ttl: Optional[int] = None,
    ):
        """
        保存会话历史
        
        Args:
            session_id: 会话 ID
            history: 对话历史列表 [{"type": "human"/"ai", "data": {"content": "..."}}]
            ttl: 过期时间（秒），默认 3600
        """
        try:
            await self._ensure_connection()
            key = self._session_key(session_id)
            ttl = ttl or self.DEFAULT_TTL["session"]
            # 在 executor 中运行同步 Redis 命令
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.client.setex(
                    key,
                    ttl,
                    json.dumps(history, ensure_ascii=False),
                )
            )
            # 更新最后活跃时间
            await loop.run_in_executor(
                None,
                lambda: self.client.setex(
                    self._session_key(session_id, "last_active"),
                    ttl,
                    str(int(time.time())),
                )
            )
            logger.debug(f"会话已保存：{session_id}")
        except Exception as e:
            logger.error(f"保存会话失败：{session_id}, error: {e}")
            raise
    
    async def get_session(self, session_id: str) -> List[Dict]:
        """
        获取会话历史
        
        Args:
            session_id: 会话 ID
            
        Returns:
            对话历史列表，不存在返回空列表
        """
        try:
            await self._ensure_connection()
            key = self._session_key(session_id)
            # 在 executor 中运行同步 Redis 命令
            loop = asyncio.get_event_loop()
            data = await loop.run_in_executor(None, self.client.get, key)
            if data:
                return json.loads(data)
        except Exception as e:
            logger.warning(f"获取会话失败：{session_id}, error: {e}")
        return []
    
    async def delete_session(self, session_id: str):
        """删除会话"""
        try:
            await self._ensure_connection()
            keys = [
                self._session_key(session_id, "history"),
                self._session_key(session_id, "scene"),
                self._session_key(session_id, "last_active"),
            ]
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: self.client.delete(*keys))
            logger.debug(f"会话已删除：{session_id}")
        except Exception as e:
            logger.error(f"删除会话失败：{session_id}, error: {e}")
    
    async def set_session_scene(self, session_id: str, scene: str):
        """设置当前会话场景"""
        try:
            await self._ensure_connection()
            key = self._session_key(session_id, "scene")
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.client.setex(key, self.DEFAULT_TTL["session"], scene)
            )
        except Exception as e:
            logger.warning(f"设置会话场景失败：{e}")
    
    async def get_session_scene(self, session_id: str) -> str:
        """获取当前会话场景"""
        try:
            await self._ensure_connection()
            key = self._session_key(session_id, "scene")
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, self.client.get, key)
            return result or "default"
        except Exception as e:
            logger.warning(f"获取会话场景失败：{e}")
            return "default"
    
    async def get_session_info(self, session_id: str) -> Dict:
        """获取会话完整信息"""
        try:
            history = await self.get_session(session_id)
            scene = await self.get_session_scene(session_id)
            await self._ensure_connection()
            loop = asyncio.get_event_loop()
            last_active = await loop.run_in_executor(
                None, 
                self.client.get, 
                self._session_key(session_id, "last_active")
            )
            
            return {
                "session_id": session_id,
                "history": history,
                "scene": scene,
                "last_active": int(last_active) if last_active else None,
                "history_count": len(history),
            }
        except Exception as e:
            logger.warning(f"获取会话信息失败：{e}")
            return {}
    
    # ==================== 用户会话管理 ====================
    
    def _user_key(self, user_id: str) -> str:
        """生成用户 Key"""
        return f"{self.KEY_PREFIX['user']}:{user_id}:sessions"
    
    async def add_user_session(self, user_id: str, session_id: str):
        """添加用户会话到列表"""
        try:
            await self._ensure_connection()
            key = self._user_key(user_id)
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: self.client.lpush(key, session_id))
            await loop.run_in_executor(None, lambda: self.client.ltrim(key, 0, 99))
            await loop.run_in_executor(
                None, 
                lambda: self.client.expire(key, self.DEFAULT_TTL["session"] * 24)
            )
        except Exception as e:
            logger.warning(f"添加用户会话失败：{e}")
    
    async def get_user_sessions(self, user_id: str, limit: int = 20) -> List[str]:
        """获取用户的会话列表"""
        try:
            await self._ensure_connection()
            key = self._user_key(user_id)
            loop = asyncio.get_event_loop()
            sessions = await loop.run_in_executor(
                None, 
                lambda: self.client.lrange(key, 0, limit - 1)
            )
            return sessions or []
        except Exception as e:
            logger.warning(f"获取用户会话失败：{e}")
            return []
    
    # ==================== 工具调用缓存 ====================
    
    def _tool_cache_key(self, tool_name: str, params_hash: str) -> str:
        """生成工具缓存 Key"""
        return f"{self.KEY_PREFIX['cache_tool']}:{tool_name}:{params_hash}"
    
    @staticmethod
    def hash_params(params: Dict) -> str:
        """计算参数的哈希值"""
        param_str = json.dumps(params, sort_keys=True, ensure_ascii=False)
        return hashlib.md5(param_str.encode()).hexdigest()
    
    async def cache_tool_result(
        self,
        tool_name: str,
        params: Dict,
        result: Any,
        ttl: Optional[int] = None,
    ):
        """
        缓存工具调用结果
        
        Args:
            tool_name: 工具名称
            params: 工具参数（用于生成缓存 key）
            result: 工具返回结果
            ttl: 过期时间（秒）
        """
        try:
            await self._ensure_connection()
            params_hash = self.hash_params(params)
            key = self._tool_cache_key(tool_name, params_hash)
            ttl = ttl or self.DEFAULT_TTL["cache_tool"]
            
            cache_data = {
                "result": result,
                "timestamp": int(time.time()),
            }
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.client.setex(key, ttl, json.dumps(cache_data, ensure_ascii=False))
            )
            logger.debug(f"工具缓存已保存：{tool_name}, hash: {params_hash[:8]}")
        except Exception as e:
            logger.warning(f"缓存工具结果失败：{e}")
    
    async def get_cached_tool_result(self, tool_name: str, params: Dict) -> Optional[Any]:
        """
        获取缓存的工具结果
        
        Args:
            tool_name: 工具名称
            params: 工具参数
            
        Returns:
            缓存的结果，不存在返回 None
        """
        try:
            await self._ensure_connection()
            params_hash = self.hash_params(params)
            key = self._tool_cache_key(tool_name, params_hash)
            loop = asyncio.get_event_loop()
            data = await loop.run_in_executor(None, self.client.get, key)
            if data:
                cache_data = json.loads(data)
                logger.debug(f"工具缓存命中：{tool_name}, hash: {params_hash[:8]}")
                return cache_data.get("result")
        except Exception as e:
            logger.warning(f"获取工具缓存失败：{e}")
        return None
    
    async def invalidate_tool_cache(self, tool_name: str, params: Optional[Dict] = None):
        """
        使工具缓存失效
        
        Args:
            tool_name: 工具名称
            params: 如果提供则只删除特定参数的缓存，否则删除该工具所有缓存
        """
        try:
            await self._ensure_connection()
            loop = asyncio.get_event_loop()
            if params:
                params_hash = self.hash_params(params)
                key = self._tool_cache_key(tool_name, params_hash)
                await loop.run_in_executor(None, self.client.delete, key)
            else:
                # 删除所有该工具的缓存
                pattern = f"{self.KEY_PREFIX['cache_tool']}:{tool_name}:*"
                cursor = 0
                while True:
                    # 同步 scan 需要在 executor 中运行
                    cursor, keys = await loop.run_in_executor(
                        None,
                        lambda p=pattern, c=cursor: self.client.scan(c, match=p, count=100)
                    )
                    if keys:
                        await loop.run_in_executor(None, lambda k=keys: self.client.delete(*k))
                    if cursor == 0:
                        break
            logger.debug(f"工具缓存已失效：{tool_name}")
        except Exception as e:
            logger.warning(f"使工具缓存失效失败：{e}")
    
    # ==================== 查询结果缓存 ====================
    
    def _query_cache_key(self, query: str) -> str:
        """生成查询缓存 Key"""
        query_hash = hashlib.md5(query.encode()).hexdigest()
        return f"{self.KEY_PREFIX['cache_query']}:{query_hash}"
    
    async def cache_query_result(
        self,
        query: str,
        result: Any,
        metadata: Optional[Dict] = None,
        ttl: Optional[int] = None,
    ):
        """缓存查询结果"""
        try:
            await self._ensure_connection()
            key = self._query_cache_key(query)
            ttl = ttl or self.DEFAULT_TTL["cache_query"]
            
            cache_data = {
                "result": result,
                "metadata": metadata or {},
                "timestamp": int(time.time()),
            }
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.client.setex(key, ttl, json.dumps(cache_data, ensure_ascii=False))
            )
        except Exception as e:
            logger.warning(f"缓存查询结果失败：{e}")
    
    async def get_cached_query_result(self, query: str) -> Optional[Dict]:
        """获取缓存的查询结果"""
        try:
            await self._ensure_connection()
            key = self._query_cache_key(query)
            loop = asyncio.get_event_loop()
            data = await loop.run_in_executor(None, self.client.get, key)
            if data:
                return json.loads(data)
        except Exception as e:
            logger.warning(f"获取查询缓存失败：{e}")
        return None
    
    # ==================== 分布式锁 ====================
    
    @asynccontextmanager
    async def lock(
        self,
        key: str,
        timeout: int = 30,
        retry_delay: float = 0.1,
        max_retries: int = 30,
    ):
        """
        分布式锁上下文管理器
        
        使用示例：
            async with redis_mgr.lock("lock:session:123"):
                # 临界区代码
                pass
        
        Args:
            key: 锁的 key
            timeout: 锁超时时间（秒）
            retry_delay: 重试间隔（秒）
            max_retries: 最大重试次数
        """
        await self._ensure_connection()
        lock_key = f"{self.KEY_PREFIX['lock']}:{key}"
        lock_value = str(uuid.uuid4())
        acquired = False
        loop = asyncio.get_event_loop()
        
        try:
            for _ in range(max_retries):
                # 尝试获取锁 - 使用 executor 运行同步命令
                result = await loop.run_in_executor(
                    None,
                    lambda: self.client.set(lock_key, lock_value, nx=True, ex=timeout)
                )
                if result:
                    acquired = True
                    break
                await asyncio.sleep(retry_delay)
            
            if not acquired:
                raise TimeoutError(f"获取锁超时：{lock_key}")
            
            yield
        finally:
            if acquired:
                # 只有持有锁的客户端才能释放
                current_value = await loop.run_in_executor(None, self.client.get, lock_key)
                if current_value == lock_value:
                    await loop.run_in_executor(None, self.client.delete, lock_key)
    
    async def try_lock(
        self,
        key: str,
        timeout: int = 30,
    ) -> bool:
        """
        尝试获取锁（非阻塞）
        
        Returns:
            是否成功获取锁
        """
        await self._ensure_connection()
        lock_key = f"{self.KEY_PREFIX['lock']}:{key}"
        lock_value = str(uuid.uuid4())
        loop = asyncio.get_event_loop()
        
        result = await loop.run_in_executor(
            None,
            lambda: self.client.set(lock_key, lock_value, nx=True, ex=timeout)
        )
        if result:
            # 存储锁标识用于后续释放
            await loop.run_in_executor(
                None,
                lambda: self.client.set(f"{lock_key}:holder", lock_value, ex=timeout)
            )
            return True
        return False
    
    async def release_lock(self, key: str) -> bool:
        """释放锁"""
        await self._ensure_connection()
        lock_key = f"{self.KEY_PREFIX['lock']}:{key}"
        holder_key = f"{lock_key}:holder"
        loop = asyncio.get_event_loop()
        
        try:
            lock_value = await loop.run_in_executor(None, self.client.get, holder_key)
            if lock_value:
                current_value = await loop.run_in_executor(None, self.client.get, lock_key)
                if current_value == lock_value:
                    await loop.run_in_executor(None, lambda: self.client.delete(lock_key, holder_key))
                    return True
        except Exception as e:
            logger.warning(f"释放锁失败：{e}")
        return False
    
    # ==================== 限流控制 ====================
    
    async def check_rate_limit(
        self,
        identifier: str,
        limit: int = 10,
        window: int = 60,
    ) -> bool:
        """
        检查是否超过限流
        
        使用滑动窗口计数
        
        Args:
            identifier: 限流标识（如 session_id、user_id、IP）
            limit: 窗口期内允许的最大请求数
            window: 时间窗口（秒）
            
        Returns:
            True 表示未超限，可以进行请求
            False 表示已超限，需要等待
        """
        await self._ensure_connection()
        key = f"{self.KEY_PREFIX['ratelimit']}:{identifier}"
        current_time = int(time.time())
        window_start = current_time - window
        
        try:
            pipe = self.client.pipeline()
            # 移除窗口期外的记录
            pipe.zremrangebyscore(key, 0, window_start)
            # 添加当前请求
            pipe.zadd(key, {str(current_time): current_time})
            # 获取窗口期内请求数
            pipe.zcard(key)
            # 设置过期时间
            pipe.expire(key, window)
            # 在 executor 中执行 pipeline
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(None, pipe.execute)
            
            request_count = results[2]
            
            if request_count > limit:
                logger.warning(f"限流触发：{identifier}, count: {request_count}, limit: {limit}")
                return False
            
            return True
        except Exception as e:
            logger.warning(f"检查限流失败：{e}")
            return True  # 失败时允许通过，避免影响正常业务
    
    async def get_rate_limit_info(self, identifier: str, window: int = 60) -> Dict:
        """
        获取限流信息
        
        Returns:
            {"current": 当前请求数，"limit": 限制数，"remaining": 剩余次数，"reset": 重置时间}
        """
        await self._ensure_connection()
        key = f"{self.KEY_PREFIX['ratelimit']}:{identifier}"
        current_time = int(time.time())
        window_start = current_time - window
        
        try:
            pipe = self.client.pipeline()
            pipe.zremrangebyscore(key, 0, window_start)
            pipe.zcard(key)
            pipe.ttl(key)
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(None, pipe.execute)
            
            current = results[1]
            ttl = results[2]
            
            return {
                "current": current,
                "limit": 10,  # 默认值
                "remaining": max(0, 10 - current),
                "reset": ttl if ttl > 0 else window,
            }
        except Exception as e:
            logger.warning(f"获取限流信息失败：{e}")
            return {"current": 0, "limit": 10, "remaining": 10, "reset": window}
    
    # ==================== 消息队列 ====================
    
    async def push_queue(self, queue_name: str, message: Dict, block: bool = False):
        """
        推送消息到队列
        
        Args:
            queue_name: 队列名称
            message: 消息内容
            block: 是否阻塞（用于等待处理完成）
        """
        await self._ensure_connection()
        key = f"{self.KEY_PREFIX['queue']}:{queue_name}:pending"
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.client.lpush(key, json.dumps(message, ensure_ascii=False))
            )
            logger.debug(f"消息已推送到队列：{queue_name}")
        except Exception as e:
            logger.warning(f"推送队列失败：{e}")
    
    async def pop_queue(
        self,
        queue_name: str,
        timeout: float = 0,
    ) -> Optional[Dict]:
        """
        从队列弹出消息
        
        Args:
            queue_name: 队列名称
            timeout: 阻塞超时时间（0 为非阻塞）
            
        Returns:
            消息内容，队列为空返回 None
        """
        await self._ensure_connection()
        key = f"{self.KEY_PREFIX['queue']}:{queue_name}:pending"
        try:
            loop = asyncio.get_event_loop()
            if timeout > 0:
                # 阻塞 pop 需要在 executor 中运行
                result = await loop.run_in_executor(
                    None,
                    lambda: self.client.brpop(key, timeout=timeout)
                )
                if result:
                    return json.loads(result[1])
            else:
                result = await loop.run_in_executor(None, self.client.rpop, key)
                if result:
                    return json.loads(result)
        except Exception as e:
            logger.warning(f"弹出队列失败：{e}")
        return None
    
    async def get_queue_size(self, queue_name: str) -> int:
        """获取队列大小"""
        await self._ensure_connection()
        key = f"{self.KEY_PREFIX['queue']}:{queue_name}:pending"
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self.client.llen, key)
        except Exception as e:
            logger.warning(f"获取队列大小失败：{e}")
            return 0
    
    # ==================== 工具方法 ====================
    
    async def ping(self) -> bool:
        """检查 Redis 连接状态"""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, self.client.ping)
            return bool(result)
        except Exception:
            return False
    
    async def get_stats(self) -> Dict:
        """获取 Redis 统计信息"""
        try:
            await self._ensure_connection()
            loop = asyncio.get_event_loop()
            info = await loop.run_in_executor(None, lambda: self.client.info("stats"))
            return {
                "connected": await self.ping(),
                "total_connections_received": info.get("total_connections_received", 0),
                "total_commands_processed": info.get("total_commands_processed", 0),
            }
        except Exception as e:
            logger.warning(f"获取统计信息失败：{e}")
            return {"connected": False}


# ==================== 全局单例 ====================

# 全局 Redis 管理器实例
_redis_manager: Optional[RedisManager] = None


def get_redis_manager() -> RedisManager:
    """获取全局 Redis 管理器单例"""
    global _redis_manager
    if _redis_manager is None:
        _redis_manager = RedisManager()
    return _redis_manager


async def init_redis_manager(
    host: str = "localhost",
    port: int = 6379,
    db: int = 0,
    password: Optional[str] = None,
) -> RedisManager:
    """初始化全局 Redis 管理器"""
    global _redis_manager
    _redis_manager = RedisManager(
        host=host,
        port=port,
        db=db,
        password=password,
    )
    await _redis_manager.initialize()
    return _redis_manager