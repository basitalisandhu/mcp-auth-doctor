"""Read JSON with an explicit nesting limit.

``json.loads`` used to stop very deep input (``"[" * 100000``) with ``RecursionError``.
Python 3.14 guards the C decoder by remaining stack space instead of the recursion
limit, so the same input now parses, or fails later as a plain syntax error, and code
that walks the result can still hit the limit. Checking the depth first gives the same
clear error on every supported Python version.
"""

from __future__ import annotations

import json
import re
from typing import Any

MAX_JSON_DEPTH = 200
"""Deepest array/object nesting accepted. Real payloads stay far below this."""

_STRINGS = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"', re.S)
_NOT_BRACKETS = re.compile(r"[^\[\]{}]+")


class JSONTooDeepError(RecursionError):
    """JSON text nests arrays/objects deeper than the limit.

    A ``RecursionError`` subclass, so handlers written for the old behaviour still catch it.
    """


def json_depth(text: str | bytes, limit: int = MAX_JSON_DEPTH) -> int:
    """Return the bracket nesting depth of ``text``, stopping once it passes ``limit``."""
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("utf-8", "replace")
    brackets = _NOT_BRACKETS.sub("", _STRINGS.sub("", text))
    depth = peak = 0
    for ch in brackets:
        if ch in "[{":
            depth += 1
            if depth > peak:
                peak = depth
                if peak > limit:
                    break
        elif depth:
            depth -= 1
    return peak


def check_json_depth(text: str | bytes, limit: int = MAX_JSON_DEPTH) -> None:
    """Raise ``JSONTooDeepError`` when ``text`` nests deeper than ``limit``."""
    if json_depth(text, limit) > limit:
        raise JSONTooDeepError(f"JSON is nested more than {limit} levels deep")


def loads(text: str | bytes, *, limit: int = MAX_JSON_DEPTH, **kwargs: Any) -> Any:
    """``json.loads`` that raises ``JSONTooDeepError`` for input nested deeper than ``limit``."""
    check_json_depth(text, limit)
    try:
        return json.loads(text, **kwargs)
    except RecursionError as exc:  # a smaller C stack than expected: same clear error
        raise JSONTooDeepError(f"JSON is nested too deeply to read: {exc}") from None
