# -*- coding: utf-8 -*-
"""Keep model-generated tool arguments consistent with the user request."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional, Tuple


_GID_PATTERN = re.compile(
    r"(?:@?gid|用户组|设备组)\s*(?:为|是|编号为|=|:|：)?\s*([A-Za-z0-9]+)",
    re.IGNORECASE,
)


def extract_explicit_gid(text: str) -> Optional[str]:
    """Extract the first explicitly named gid from the original user text."""
    if not text:
        return None
    match = _GID_PATTERN.search(str(text))
    return match.group(1) if match else None


def canonicalize_action_input(
    action_input: Dict[str, Any],
    original_user_input: str,
) -> Tuple[Dict[str, Any], Dict[str, Tuple[Any, Any]]]:
    """Restore request-owned fields that the model must not rewrite."""
    if not isinstance(action_input, dict) or not isinstance(original_user_input, str):
        return action_input, {}

    normalized = dict(action_input)
    changes: Dict[str, Tuple[Any, Any]] = {}

    if "user_problem" in normalized and normalized.get("user_problem") != original_user_input:
        changes["user_problem"] = (normalized.get("user_problem"), original_user_input)
        normalized["user_problem"] = original_user_input

    expected_gid = extract_explicit_gid(original_user_input)
    if expected_gid is not None or "gid" in normalized:
        if normalized.get("gid") != expected_gid:
            changes["gid"] = (normalized.get("gid"), expected_gid)
            normalized["gid"] = expected_gid

    return normalized, changes
