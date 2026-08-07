"""Computing a pin, and explaining one that no longer matches.

The explaining half is not a convenience. A pin that fires produces a
re-approval prompt, and a re-approval prompt that says only "this tool changed"
trains the operator to click through it, which converts the control into a
delay. `describe_change` exists so the prompt can say WHICH field moved and
what it moved to, and `pin/scan.py` exists so the prompt can say when the moved
field is one an approval dialog would not otherwise have shown.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pin.canonical import canonicalize, select
from pin.models import Fingerprint, PinPolicy, ToolRecord


def fingerprint(raw: dict[str, Any], policy: PinPolicy) -> Fingerprint:
    """Reduce a tool definition to one hash under one policy."""
    canonical = canonicalize(select(raw, policy.fields), policy.canonical)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return Fingerprint(digest=digest, policy=policy, canonical_form=canonical)


def fingerprint_record(record: ToolRecord, policy: PinPolicy) -> Fingerprint:
    return fingerprint(record.raw, policy)


def describe_change(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """A field-level diff of two tool definitions, deepest key first.

    Deliberately independent of any policy. The operator being asked to
    re-approve needs to see everything that moved, not only the part the
    configured policy happened to be watching. A diff filtered by the policy
    would hide exactly the fields a narrow policy is bad at, which is the
    failure this repository measures.
    """
    lines: list[str] = []
    _walk(before, after, "", lines)
    return sorted(lines)


def _walk(before: Any, after: Any, path: str, out: list[str]) -> None:
    if isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(set(before) | set(after)):
            child = f"{path}.{key}" if path else key
            if key not in before:
                out.append(f"+ {child} = {_render(after[key])}")
            elif key not in after:
                out.append(f"- {child} (was {_render(before[key])})")
            else:
                _walk(before[key], after[key], child, out)
        return

    if isinstance(before, list) and isinstance(after, list):
        if len(before) != len(after):
            out.append(f"~ {path} list length {len(before)} -> {len(after)}")
        for index, (b, a) in enumerate(zip(before, after)):
            _walk(b, a, f"{path}[{index}]", out)
        return

    if before != after:
        out.append(f"~ {path}: {_render(before)} -> {_render(after)}")


#: How much of a changed value to show. Long enough to read a planted
#: instruction, short enough that one diff line stays one line.
_RENDER_LIMIT = 160


def _render(value: Any) -> str:
    """Render a value for a diff line with invisible characters made visible.

    A diff that prints a zero-width joiner as itself is a diff that shows the
    reviewer two identical strings and asks them to spot the difference. Every
    non-printable and non-ASCII character is escaped here for the same reason
    the source file is ASCII: so a human can see what is actually there.
    """
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    escaped = "".join(
        ch if 0x20 <= ord(ch) < 0x7F else f"\\u{ord(ch):04x}" for ch in text
    )
    if len(escaped) <= _RENDER_LIMIT:
        return escaped
    return escaped[:_RENDER_LIMIT] + f"... ({len(escaped)} chars)"
