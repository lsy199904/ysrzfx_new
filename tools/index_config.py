# -*- coding: utf-8 -*-
"""从 YAML 加载日志索引的厂商/产品组合。"""

import re
from pathlib import Path
from typing import Dict, List

import yaml

from config import INDEX_CONFIG_FILE

_SAFE_PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
_SAFE_GID = re.compile(r"^[A-Za-z0-9]+$")


def _load_combinations() -> List[Dict[str, str]]:
    path = Path(INDEX_CONFIG_FILE)
    if not path.is_absolute():
        path = Path(__file__).resolve().parent.parent / path
    if not path.is_file():
        raise RuntimeError(f"索引组合配置文件不存在：{path}")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise RuntimeError(f"读取索引组合配置失败：{path}: {exc}") from exc

    combinations = raw.get("index_combinations")
    if not isinstance(combinations, list) or not combinations:
        raise RuntimeError("index_config.yaml 必须配置非空 index_combinations 列表")

    result = []
    seen = set()
    for item in combinations:
        if not isinstance(item, dict):
            raise RuntimeError("index_combinations 中的每项必须包含 vendor 和 product")
        vendor = str(item.get("vendor", "")).strip()
        product = str(item.get("product", "")).strip()
        if not _SAFE_PART.fullmatch(vendor) or not _SAFE_PART.fullmatch(product):
            raise RuntimeError(f"非法索引组合：vendor={vendor!r}, product={product!r}")
        key = (vendor, product)
        if key not in seen:
            seen.add(key)
            result.append({"vendor": vendor, "product": product})
    return result


INDEX_COMBINATIONS = _load_combinations()
COMBINATION_NAMES = [
    f"{item['vendor']}_{item['product']}" for item in INDEX_COMBINATIONS
]
INDEX_SOURCE_PATTERNS = [f"log_g*_{name}" for name in COMBINATION_NAMES]
INDEX_SOURCE_PATTERN = ",".join(INDEX_SOURCE_PATTERNS)
# 兼容旧调用方；其值现在由 YAML 中的全部组合动态生成。
BASE_INDEX_PATTERN = INDEX_SOURCE_PATTERN
INDEX_SOURCE_REGEX = re.compile(
    r"log_g\*_(" + "|".join(re.escape(name) for name in COMBINATION_NAMES) + r")"
)


def build_index_name(gid, combination: Dict[str, str] = None) -> str:
    """根据 gid 和厂商/产品组合构造完整索引名。"""
    # 兼容传入列表的情况（如 LLM 误输出 ["19934"]）
    if isinstance(gid, list):
        if len(gid) == 1:
            gid = gid[0]
        else:
            raise ValueError(f"gid 列表包含多个元素：{gid}，请确保只传入单个 gid")
    gid_str = str(gid).strip()
    if not _SAFE_GID.fullmatch(gid_str):
        raise ValueError(f"gid 必须是字母或数字：{gid}")

    item = combination or INDEX_COMBINATIONS[0]
    return f"log_g{gid_str}_{item['vendor']}_{item['product']}"


def build_index_names(gid: str) -> List[str]:
    """构造某个 gid 对应的全部候选索引。"""
    return [build_index_name(gid, item) for item in INDEX_COMBINATIONS]
