"""Deterministic (canonical) JSON serialization.

Signing and hashing require that the *same* logical object always produces the
*same* bytes, on every machine and every Python version. Standard ``json.dumps``
does not guarantee that (key order and whitespace vary), so all signing/hashing
in Proxim goes through :func:`canonical_bytes`.

Rules:
* keys sorted lexicographically,
* the most compact separators (no insignificant whitespace),
* UTF-8 output,
* ``NaN`` / ``Infinity`` rejected (they are not valid JSON and not portable).
"""

from __future__ import annotations

import json
from typing import Any


def canonical_bytes(obj: Any) -> bytes:
    """Serialize ``obj`` to canonical, deterministic JSON bytes."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_str(obj: Any) -> str:
    """Like :func:`canonical_bytes` but returns a ``str``."""
    return canonical_bytes(obj).decode("utf-8")
