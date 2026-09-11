# -*- coding: utf-8 -*-
"""应用配置中心。

加载顺序：进程环境变量 > 项目根目录 .env > 代码默认值。
不依赖第三方 dotenv 包，方便在现有运行环境中直接部署。
"""

import os
from pathlib import Path
from typing import Optional


PROJECT_ROOT = Path(__file__).resolve().parent


def _load_dotenv(path: Path) -> None:
    """加载常见 .env 语法，且不覆盖已有进程环境变量。"""
    if not path.is_file():
        return

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue

        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()

        os.environ.setdefault(key, value)


_load_dotenv(PROJECT_ROOT / ".env")


def _get(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.getenv(name)
    return value.strip() if value is not None else default


INDEX_CONFIG_FILE = os.getenv(
    "INDEX_CONFIG_FILE",
    str(PROJECT_ROOT / "index_config.yaml"),
)


def _get_first(*names: str, default: Optional[str] = None) -> Optional[str]:
    for name in names:
        value = _get(name)
        if value:
            return value
    return default


def _get_int(name: str, default: int) -> int:
    try:
        return int(_get(name, str(default)))
    except (TypeError, ValueError):
        return default


def _get_float(name: str, default: float) -> float:
    try:
        return float(_get(name, str(default)))
    except (TypeError, ValueError):
        return default


def _get_bool(name: str, default: bool) -> bool:
    value = (_get(name) or "").lower()
    if not value:
        return default
    return value in {"1", "true", "yes", "y", "on"}


# Elasticsearch / OpenSearch
ES_SCHEME = _get("ES_SCHEME", "https")
ES_HOST = _get("ES_HOST", "192.168.100.45")
ES_PORT = _get_int("ES_PORT", 9200)
ES_AUTH_USER = _get_first("ES_AUTH_USER", "ES_USER")
ES_AUTH_PASSWORD = _get_first("ES_AUTH_PASSWORD", "ES_PASSWORD")
ES_VERIFY_SSL = _get_bool("ES_VERIFY_SSL", False)
ES_INDEX_TIMEOUT = _get_int("ES_INDEX_TIMEOUT", 5)

# LLM
LLM_BASE_URL = _get_first(
    "LLM_BASE_URL",
    "OPENAI_API_BASE",
    default="http://10.180.158.23:18080",
).rstrip("/")
if LLM_BASE_URL.lower().endswith("/v1"):
    LLM_BASE_URL = LLM_BASE_URL[:-3].rstrip("/")
LLM_MODEL = _get_first("LLM_MODEL", "MODEL_NAME", default="Qwen/Qwen3-32B")
LLM_API_KEY = _get_first("LLM_API_KEY", "OPENAI_API_KEY", default="not empty")
LLM_TEMPERATURE = _get_float("LLM_TEMPERATURE", 0.0)
LLM_MAX_CONTEXT_TOKENS = _get_int("LLM_MAX_CONTEXT_TOKENS", 128000)
LLM_SAFETY_MARGIN = _get_int("LLM_SAFETY_MARGIN", 2000)
LLM_MIN_OUTPUT_TOKENS = _get_int("LLM_MIN_OUTPUT_TOKENS", 1000)
LLM_MAX_OUTPUT_TOKENS = _get_int("LLM_MAX_OUTPUT_TOKENS", 50000)
LLM_MAX_REQUEST_TOKENS = _get_int("LLM_MAX_REQUEST_TOKENS", 2000)
LLM_ENABLE_THINKING = _get_bool("LLM_ENABLE_THINKING", False)

# Redis
REDIS_HOST = _get("REDIS_HOST", "localhost")
REDIS_PORT = _get_int("REDIS_PORT", 6379)
REDIS_DB = _get_int("REDIS_DB", 0)
REDIS_PASSWORD = _get("REDIS_PASSWORD")
REDIS_SOCKET_TIMEOUT = _get_float("REDIS_SOCKET_TIMEOUT", 5.0)
REDIS_CONNECT_TIMEOUT = _get_float("REDIS_CONNECT_TIMEOUT", 5.0)
REDIS_PING_TIMEOUT = _get_float("REDIS_PING_TIMEOUT", 2.0)
REDIS_MAX_CONNECTIONS = _get_int("REDIS_MAX_CONNECTIONS", 50)
SESSION_TTL = _get_int("SESSION_TTL", 3600)
CACHE_TOOL_TTL = _get_int("CACHE_TOOL_TTL", 300)
INDEX_CACHE_TTL = _get_int("INDEX_CACHE_TTL", 300)

# Agent service
APP_HOST = _get("APP_HOST", "0.0.0.0")
APP_PORT = _get_int("APP_PORT", 8000)
APP_LOG_LEVEL = _get("APP_LOG_LEVEL", "info")
APP_TIMEOUT_KEEP_ALIVE = _get_int("APP_TIMEOUT_KEEP_ALIVE", 60)
CORS_ORIGINS = [
    item.strip()
    for item in (_get("CORS_ORIGINS", "*") or "*").split(",")
    if item.strip()
]

# 告警规则服务
ALERT_SSO_APP_ID = _get_first("ALERT_SSO_APP_ID", "SSO_APP_ID")
ALERT_SSO_SECRET_KEY = _get_first("ALERT_SSO_SECRET_KEY", "SSO_SECRET_KEY")
ALERT_API_DOMAIN = (
    _get_first(
        "ALERT_API_DOMAIN",
        "API_DOMAIN",
        default="https://192.168.101.54:8888",
    )
    or ""
).rstrip("/")
ALERT_REQUEST_TIMEOUT = _get_int("ALERT_REQUEST_TIMEOUT", 50)
ALERT_VERIFY_SSL = _get_bool("ALERT_VERIFY_SSL", False)

# Request timeout policies
ES_QUERY_TIMEOUT = _get_float("ES_QUERY_TIMEOUT", 90.0)
LLM_CALL_TIMEOUT = _get_float("LLM_CALL_TIMEOUT", 90.0)
HTTP_REQUEST_TIMEOUT = _get_float("HTTP_REQUEST_TIMEOUT", 45.0)
TOOL_EXECUTION_TIMEOUT = _get_float("TOOL_EXECUTION_TIMEOUT", 150.0)
TOTAL_REQUEST_TIMEOUT = _get_float("TOTAL_REQUEST_TIMEOUT", 240.0)

# Query and alert defaults
COMPRESSION_THRESHOLD = _get_int("COMPRESSION_THRESHOLD", 3)
COMPRESSION_MAX_TOKENS = _get_int("COMPRESSION_MAX_TOKENS", 2000)
COMPRESSION_MAX_RETURN_DATA = _get_int("COMPRESSION_MAX_RETURN_DATA", 3)
IP_TRACE_COMPRESSION_THRESHOLD = _get_int("IP_TRACE_COMPRESSION_THRESHOLD", 15)
IP_TRACE_MAX_RETURN_DATA = _get_int("IP_TRACE_MAX_RETURN_DATA", 5)
QUERY_MAX_RECORDS = _get_int("QUERY_MAX_RECORDS", 100)
FREE_QUERY_MAX_ATTEMPTS = _get_int("FREE_QUERY_MAX_ATTEMPTS", 3)
ALERT_TABLE_NAME = _get("ALERT_TABLE_NAME", "alarm_result")
ALERT_PAGE_SIZE = _get_int("ALERT_PAGE_SIZE", 500)


def require_config(value: Optional[str], name: str) -> str:
    """在真正需要敏感配置时提供明确错误。"""
    if not value:
        raise RuntimeError(f"缺少配置项 {name}，请在 .env 或进程环境变量中设置")
    return value
