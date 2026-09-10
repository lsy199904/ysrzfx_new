# -*- coding: utf-8 -*-
"""
电路断路器模块 (Circuit Breaker)

用于防止系统在依赖服务（如 ES、LLM）连续失败时继续尝试，
从而避免资源浪费和雪崩效应。

状态说明：
- CLOSED（闭合）：正常状态，允许请求通过
- OPEN（断开）：失败次数超过阈值，拒绝请求，直接返回兜底响应
- HALF_OPEN（半开）：等待一段时间后，允许一个请求通过测试服务是否恢复

使用示例：
    breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=60)
    
    async with breaker.request():
        # 执行可能失败的操作
        result = await some_operation()
        
    # 或者手动标记成功/失败
    breaker.record_success()
    breaker.record_failure()
"""
import asyncio
import logging
import time
from enum import Enum
from typing import Optional, Dict, Any
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """电路状态"""
    CLOSED = "closed"      # 闭合 - 正常
    OPEN = "open"          # 断开 - 拒绝请求
    HALF_OPEN = "half_open"  # 半开 - 测试恢复


class CircuitBreakerError(Exception):
    """电路断路器异常"""
    pass


class CircuitBreaker:
    """
    电路断路器实现
    
    当连续失败次数达到阈值时，电路断开，拒绝后续请求。
    经过恢复超时时间后，电路进入半开状态，允许一个请求通过测试。
    如果测试成功，电路闭合恢复正常；如果失败，继续断开。
    """
    
    def __init__(
        self,
        name: str = "default",
        failure_threshold: int = 5,      # 失败阈值
        success_threshold: int = 2,      # 成功阈值（半开状态下需要连续成功次数）
        recovery_timeout: float = 60.0,  # 恢复超时时间（秒）
        expected_exceptions: tuple = (Exception,),  # 需要捕获的异常类型
    ):
        """
        初始化电路断路器
        
        Args:
            name: 断路器名称，用于日志和监控
            failure_threshold: 连续失败多少次后断开电路
            success_threshold: 半开状态下连续成功多少次后闭合电路
            recovery_timeout: 电路断开后多少秒进入半开状态
            expected_exceptions: 需要捕获的异常类型
        """
        self.name = name
        self.failure_threshold = failure_threshold
        self.success_threshold = success_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exceptions = expected_exceptions
        
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._lock = asyncio.Lock()
        
        # 统计信息
        self._total_requests = 0
        self._total_failures = 0
        self._total_successes = 0
        self._total_rejected = 0
        self._last_state_change_time = time.time()
    
    @property
    def state(self) -> CircuitState:
        """获取当前状态（自动检查是否需要进入半开状态）"""
        if self._state == CircuitState.OPEN:
            if self._last_failure_time is None:
                return CircuitState.HALF_OPEN
            if time.time() - self._last_failure_time >= self.recovery_timeout:
                return CircuitState.HALF_OPEN
        return self._state
    
    @property
    def is_closed(self) -> bool:
        """电路是否闭合（正常状态）"""
        return self.state == CircuitState.CLOSED
    
    @property
    def is_open(self) -> bool:
        """电路是否断开（拒绝请求）"""
        return self.state == CircuitState.OPEN
    
    @property
    def is_half_open(self) -> bool:
        """电路是否半开（测试状态）"""
        return self.state == CircuitState.HALF_OPEN
    
    def _change_state(self, new_state: CircuitState):
        """改变状态并记录时间"""
        old_state = self._state
        self._state = new_state
        self._last_state_change_time = time.time()
        logger.info(f"[CircuitBreaker:{self.name}] 状态变更：{old_state.value} → {new_state.value}")
    
    async def _check_state(self):
        """检查并更新状态"""
        async with self._lock:
            if self._state == CircuitState.OPEN:
                if self._last_failure_time is not None:
                    if time.time() - self._last_failure_time >= self.recovery_timeout:
                        self._change_state(CircuitState.HALF_OPEN)
                        self._success_count = 0
    
    def record_success(self):
        """记录成功"""
        self._total_successes += 1
        self._total_requests += 1
        
        if self._state == CircuitState.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self.success_threshold:
                self._change_state(CircuitState.CLOSED)
                self._failure_count = 0
                self._success_count = 0
        elif self._state == CircuitState.CLOSED:
            # 闭合状态下成功，重置失败计数
            self._failure_count = 0
    
    def record_failure(self):
        """记录失败"""
        self._total_failures += 1
        self._total_requests += 1
        self._last_failure_time = time.time()
        
        if self._state == CircuitState.HALF_OPEN:
            # 半开状态下失败，立即断开
            self._change_state(CircuitState.OPEN)
            self._success_count = 0
        elif self._state == CircuitState.CLOSED:
            self._failure_count += 1
            if self._failure_count >= self.failure_threshold:
                self._change_state(CircuitState.OPEN)
    
    def record_rejected(self):
        """记录被拒绝的请求"""
        self._total_rejected += 1
        self._total_requests += 1
    
    @asynccontextmanager
    async def request(self):
        """
        上下文管理器：用于包装可能失败的操作
        
        使用示例：
            async with breaker.request():
                result = await some_operation()
        """
        await self._check_state()
        
        if self._state == CircuitState.OPEN:
            self.record_rejected()
            raise CircuitBreakerError(
                f"[CircuitBreaker:{self.name}] 电路已断开，服务暂时不可用"
            )
        
        try:
            yield
        except self.expected_exceptions as e:
            self.record_failure()
            raise
        else:
            self.record_success()
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self._failure_count,
            "success_count": self._success_count,
            "total_requests": self._total_requests,
            "total_successes": self._total_successes,
            "total_failures": self._total_failures,
            "total_rejected": self._total_rejected,
            "failure_threshold": self.failure_threshold,
            "recovery_timeout": self.recovery_timeout,
            "last_state_change_time": self._last_state_change_time,
            "last_failure_time": self._last_failure_time,
        }
    
    def reset(self):
        """重置断路器"""
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time = None
        logger.info(f"[CircuitBreaker:{self.name}] 已重置")


# ========================================
# 全局断路器实例
# ========================================

# ES 查询断路器
es_circuit_breaker = CircuitBreaker(
    name="es_query",
    failure_threshold=5,       # 连续 5 次失败后断开
    recovery_timeout=60.0,     # 60 秒后尝试恢复
)

# LLM 调用断路器
llm_circuit_breaker = CircuitBreaker(
    name="llm_call",
    failure_threshold=3,       # 连续 3 次失败后断开
    recovery_timeout=30.0,     # 30 秒后尝试恢复
)

# Redis 操作断路器
redis_circuit_breaker = CircuitBreaker(
    name="redis_operation",
    failure_threshold=10,      # 连续 10 次失败后断开
    recovery_timeout=30.0,     # 30 秒后尝试恢复
)


def get_circuit_breaker(name: str) -> Optional[CircuitBreaker]:
    """根据名称获取断路器"""
    breakers = {
        "es_query": es_circuit_breaker,
        "llm_call": llm_circuit_breaker,
        "redis_operation": redis_circuit_breaker,
    }
    return breakers.get(name)


def get_all_circuit_breakers() -> Dict[str, CircuitBreaker]:
    """获取所有断路器"""
    return {
        "es_query": es_circuit_breaker,
        "llm_call": llm_circuit_breaker,
        "redis_operation": redis_circuit_breaker,
    }