"""Helpers for separating streamed reasoning from the final answer.

The model may split XML-like tags across arbitrary streaming chunks, so this
module keeps a small amount of state instead of parsing each token in
isolation.  The public protocol is deliberately JSON-friendly: callers emit
``think`` deltas while the completed, cleaned answer is emitted as
``final_answer``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


_OPEN_TAG_RE = re.compile(r"<(?:think|thinking|antThinking)>", re.IGNORECASE)
_CLOSE_TAG_RE = re.compile(r"</(?:think|thinking|antThinking)>", re.IGNORECASE)
_SELF_CLOSING_TAG_RE = re.compile(r"<(?:think|thinking|antThinking)\s*/>", re.IGNORECASE)
_TAG_PREFIXES = ("<think", "<thinking", "<antthinking", "</think", "</thinking", "</antthinking")


def contains_cjk(value: str) -> bool:
    """Return whether *value* contains a CJK ideograph."""
    return any("\u4e00" <= char <= "\u9fff" for char in str(value or ""))


def detect_response_language(user_input: str) -> str:
    """Detect the request language once, using the original user input only."""
    value = str(user_input or "")
    cjk = sum("\u4e00" <= char <= "\u9fff" for char in value)
    # Ignore identifiers, dates, IPs, JSON-like keys, and tool names when
    # deciding the natural-language majority (for example, ``gid19936`` or
    # ``brute_force_request`` must not turn a Chinese question into English).
    natural_text = re.sub(r"[A-Za-z0-9_./:@=-]+", " ", value)
    natural_latin = sum(char.isascii() and char.isalpha() for char in natural_text)
    if cjk and (natural_latin == 0 or cjk >= natural_latin or (cjk >= 2 and natural_latin <= 8)):
        return "zh"
    return "en"


def _safe_suffix_length(value: str) -> int:
    """Return the length of a suffix that may be a split tag prefix."""
    lowered = value.lower()
    for size in range(min(len(lowered), 16), 0, -1):
        if any(prefix.startswith(lowered[-size:]) for prefix in _TAG_PREFIXES):
            return size
    return 0


@dataclass
class ThoughtStreamParser:
    """Incrementally extract explicit ``<think>`` blocks from model tokens."""

    in_think: bool = False
    pending: str = ""
    started: bool = False
    ended: bool = False
    _events: list[dict[str, object]] = field(default_factory=list)

    def feed(self, token: str) -> list[dict[str, object]]:
        if not token:
            return []
        self.pending += token
        self._events = []

        while self.pending:
            if not self.in_think:
                open_match = _OPEN_TAG_RE.search(self.pending)
                self_close = _SELF_CLOSING_TAG_RE.search(self.pending)
                if self_close and (not open_match or self_close.start() <= open_match.start()):
                    self.pending = self.pending[self_close.end():]
                    continue
                if open_match:
                    self.pending = self.pending[open_match.end():]
                    self.in_think = True
                    self.started = True
                    self.ended = False
                    self._events.append({"think": "", "think_start": True})
                    continue
                keep = _safe_suffix_length(self.pending)
                if keep:
                    self.pending = self.pending[-keep:]
                else:
                    self.pending = ""
                break

            close_match = _CLOSE_TAG_RE.search(self.pending)
            if close_match:
                self._append_think(self.pending[:close_match.start()])
                self.pending = self.pending[close_match.end():]
                self.in_think = False
                self.ended = True
                self._events.append({"think": "", "think_end": True})
                continue

            keep = _safe_suffix_length(self.pending)
            if keep:
                self._append_think(self.pending[:-keep])
                self.pending = self.pending[-keep:]
            else:
                self._append_think(self.pending)
                self.pending = ""
            break

        return self._events

    def flush(self) -> list[dict[str, object]]:
        """Flush a truncated block without exposing XML markers to the UI."""
        self._events = []
        if self.in_think and self.pending:
            self._append_think(self.pending)
            self.pending = ""
        if self.started and not self.ended:
            self.ended = True
            self._events.append({"think": "", "think_end": True})
        return self._events

    def _append_think(self, value: str) -> None:
        if value:
            self._events.append({"think": value})


def split_thoughts(text: str) -> tuple[str, str]:
    """Return ``(thought_text, final_text)`` and remove all explicit tags."""
    if not text:
        return "", ""

    thoughts: list[str] = []

    def replace_block(match: re.Match[str]) -> str:
        thoughts.append(match.group(1).strip())
        return ""

    final_text = re.sub(
        r"<(?:think|thinking|antThinking)>\s*(.*?)\s*</(?:think|thinking|antThinking)>\s*",
        replace_block,
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    # A truncated block must never leak its opening marker into final_answer.
    final_text = re.sub(r"<(?:think|thinking|antThinking)>.*$", "", final_text, flags=re.IGNORECASE | re.DOTALL)
    final_text = _SELF_CLOSING_TAG_RE.sub("", final_text)
    final_text = re.sub(r"\n{3,}", "\n\n", final_text).strip()
    return "\n\n".join(item for item in thoughts if item), final_text


def clean_final_answer(text: str) -> str:
    """Strip reasoning blocks while preserving Markdown formatting in the answer."""
    _thought, final_text = split_thoughts(text)
    return final_text


def thought_event_to_answer(event: dict[str, object]) -> str:
    """Map an internal thought event to the legacy ``answer`` stream field."""
    if event.get("think_start"):
        return "<think>"
    if event.get("think_end"):
        return "</think>"
    return str(event.get("think") or "")
