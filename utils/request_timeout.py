# -*- coding: utf-8 -*-
"""
请求级超时控制模块

为异步操作提供超时保护，防止单个请求长时间阻塞系统资源。

使用示例：
    # 方式 1：使用装饰器
    @with_timeout(timeout=30.0)
    async def my_async_func():
        ...
    
    # 方式 2：使用上下文管理器
    async with timeout_context(30.0):
        await some_operation()
    
    # 方式 3：直接使用 asyncio.wait_for
    try:
        result = await asyncio.wait_for(some_operation(), timeout=30.0)
    except asyncio.TimeoutError:
        ...
"""
import asyncio
import functools
import logging
import time
from typing import Any, Callable, Optional, TypeVar, Awaitable
from contextlib import asynccontextmanager
from config import (
    ES_QUERY_TIMEOUT,
    HTTP_REQUEST_TIMEOUT,
    LLM_CALL_TIMEOUT,
    REDIS_SOCKET_TIMEOUT,
    TOOL_EXECUTION_TIMEOUT,
    TOTAL_REQUEST_TIMEOUT,
)

logger = logging.getLogger(__name__)

T = TypeVar('T')


class RequestTimeoutError(Exception):
    """请求超时异常"""
    pass


async def timeout_guard(
    coro: Awaitable[T],
    timeout: float,
    default_value: Any = None,
    raise_on_timeout: bool = True,
    operation_name: str = "operation"
) -> Optional[T]:
    """
    为异步操作提供超时保护
    
    Args:
        coro: 要执行的异步操作
        timeout: 超时时间（秒）
        default_value: 超时时的默认返回值
        raise_on_timeout: 超时时是否抛出异常
        operation_name: 操作名称，用于日志
    
    Returns:
        异步操作的结果，或超时时的默认值
    
    Raises:
        RequestTimeoutError: 当 raise_on_timeout=True 且超时时
    """
    try:
        result = await asyncio.wait_for(coro, timeout=timeout)
        return result
    except asyncio.TimeoutError:
        logger.warning(f"[TimeoutGuard] {operation_name} 超时（>{timeout}秒）")
        if raise_on_timeout:
            raise RequestTimeoutError(f"{operation_name} 执行超时（>{timeout}秒）")
        return default_value
    except Exception as e:
        logger.error(f"[TimeoutGuard] {operation_name} 执行失败：{e}")
        raise


@asynccontextmanager
async def timeout_context(timeout: float, operation_name: str = "operation"):
    """
    超时上下文管理器
    
    使用示例：
        async with timeout_context(30.0, "ES 查询"):
            result = await es_query()
    
    Args:
        timeout: 超时时间（秒）
        operation_name: 操作名称，用于日志
    """
    start_time = time.time()
    try:
        # 创建一个带超时的任务
        async def run_with_timeout():
            # 返回一个占位符，实际由外部 await
            pass
        
        yield asyncio.get_event_loop()
        
        elapsed = time.time() - start_time
        if elapsed > timeout:
            logger.warning(f"[TimeoutContext] {operation_name} 执行时间过长：{elapsed:.2f}秒")
    except asyncio.TimeoutError:
        elapsed = time.time() - start_time
        logger.error(f"[TimeoutContext] {operation_name} 超时：{elapsed:.2f}秒 > {timeout}秒")
        raise RequestTimeoutError(f"{operation_name} 执行超时（{elapsed:.2f}秒 > {timeout}秒）")
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"[TimeoutContext] {operation_name} 执行失败（{elapsed:.2f}秒）: {e}")
        raise


def with_timeout(timeout: float, default_value: Any = None, raise_on_timeout: bool = False):
    """
    异步函数超时装饰器
    
    使用示例：
        @with_timeout(timeout=30.0)
        async def my_async_func():
            ...
    
    Args:
        timeout: 超时时间（秒）
        default_value: 超时时的默认返回值
        raise_on_timeout: 超时时是否抛出异常
    """
    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> Optional[T]:
            try:
                return await timeout_guard(
                    func(*args, **kwargs),
                    timeout=timeout,
                    default_value=default_value,
                    raise_on_timeout=raise_on_timeout,
                    operation_name=func.__name__
                )
            except RequestTimeoutError:
                if raise_on_timeout:
                    raise
                return default_value
        return wrapper
    return decorator


# ========================================
# 预定义的超时配置
# ========================================

class TimeoutConfig:
    """超时配置常量"""
    # ES 查询超时（调整为 90 秒，适应大数据量和统计类查询）
    ES_QUERY_TIMEOUT = ES_QUERY_TIMEOUT
    
    # LLM 调用超时（保守调整：60 → 90 秒，适应长文本生成）
    LLM_CALL_TIMEOUT = LLM_CALL_TIMEOUT
    
    # Redis 操作超时
    REDIS_OPERATION_TIMEOUT = REDIS_SOCKET_TIMEOUT
    
    # HTTP 请求超时（保守调整：30 → 45 秒，与 ES 查询保持一致）
    HTTP_REQUEST_TIMEOUT = HTTP_REQUEST_TIMEOUT
    
    # 工具执行超时（保守调整：120 → 150 秒，给重试留出时间）
    TOOL_EXECUTION_TIMEOUT = TOOL_EXECUTION_TIMEOUT
    
    # 整体请求超时（保守调整：180 → 240 秒，适应复杂场景）
    TOTAL_REQUEST_TIMEOUT = TOTAL_REQUEST_TIMEOUT


async def execute_with_retry(
    coro_func: Callable[[], Awaitable[T]],
    max_retries: int = 3,
    timeout: float = 30.0,
    retry_delay: float = 1.0,
    operation_name: str = "operation",
    retry_on_exceptions: tuple = (Exception,)
) -> Optional[T]:
    """
    带重试的超时执行
    
    Args:
        coro_func: 异步操作函数（无参数）
        max_retries: 最大重试次数
        timeout: 每次尝试的超时时间
        retry_delay: 重试间隔（秒）
        operation_name: 操作名称
        retry_on_exceptions: 需要重试的异常类型
    
    Returns:
        操作结果，失败返回 None
    
    使用示例：
        result = await execute_with_retry(
            lambda: es_query(ppl),
            max_retries=3,
            timeout=30.0,
            operation_name="ES 查询"
        )
    """
    last_error = None
    
    for attempt in range(max_retries + 1):
        try:
            return await timeout_guard(
                coro_func(),
                timeout=timeout,
                raise_on_timeout=True,
                operation_name=operation_name
            )
        except RequestTimeoutError as e:
            last_error = e
            logger.warning(f"[Retry] {operation_name} 超时，第{attempt + 1}/{max_retries + 1}次尝试")
        except retry_on_exceptions as e:
            last_error = e
            logger.warning(f"[Retry] {operation_name} 失败：{e}，第{attempt + 1}/{max_retries + 1}次尝试")
        
        if attempt < max_retries:
            await asyncio.sleep(retry_delay * (attempt + 1))  # 递增延迟
    
    logger.error(f"[Retry] {operation_name} 最终失败，共尝试{max_retries + 1}次")
    return None
