"""What an approval dialog does not show.

Pinning answers "has this changed since you approved it". It cannot answer "was
it safe when you approved it", and nothing that hashes bytes ever will. This
module is the separate, weaker, false-negative-prone control that looks at
CONTENT, and it is a separate module on purpose, because merging a check that
is exact with a check that is heuristic produces one number nobody can act on.

The asymmetry it measures. A host asking an operator to approve a tool shows a
name and a description. The definition the model receives also carries
`title`, `annotations`, `outputSchema`, `icons`, and an `inputSchema` whose
per-property `x-mcp-header` annotation causes the argument value to be mirrored
into an HTTP header on the Streamable HTTP transport, where every proxy, load
balancer and WAF on the path can read it. The 2026-07-28 specification says so
directly, and warns server developers not to mark sensitive parameters that
way. Nothing warns the OPERATOR, because the operator is looking at the
description.

`reviewer_surface` and `model_surface` return the two views. The gap between
them is the attack surface a description-only pin leaves uncovered, and
`pin/matrix.py` reports its size.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pin.canonical import fold_text, resolve_schema

#: Property-level annotation that mirrors an argument into an HTTP header.
#: Streamable HTTP only; stdio clients MAY ignore it, which is its own
#: hazard: a tool reviewed on stdio and later reached over HTTP changes
#: meaning without changing a byte.
HEADER_ANNOTATION = "x-mcp-header"


@dataclass(frozen=True, slots=True)
class Finding:
    """One observation about a tool definition. Advisory, never a verdict."""

    kind: str
    path: str
    detail: str


def reviewer_surface(tool: dict[str, Any]) -> str:
    """The text a conventional approval dialog puts in front of a human."""
    name = tool.get("name") or ""
    title = tool.get("title") or ""
    description = tool.get("description") or ""
    return "\n".join(part for part in (title or name, description) if part)


def model_surface(tool: dict[str, Any]) -> str:
    """Everything in the definition that is natural-language text.

    An approximation of what reaches the model's context once a host serializes
    the tool list, and approximate is the honest word: the protocol does not
    specify how a host renders tools into a prompt, so the exact string differs
    per host. What does not differ is that `annotations`, `title` and every
    `description` inside the schemas are part of the definition and the
    reviewer saw one of them.
    """
    chunks: list[str] = []
    _collect_text(tool, chunks)
    return "\n".join(chunks)


def _collect_text(node: Any, out: list[str]) -> None:
    if isinstance(node, str):
        if node.strip():
            out.append(node)
        return
    if isinstance(node, dict):
        for key in sorted(node):
            # Keys are structure, values are content. Schema keywords whose
            # values are enumerations of allowed data (`enum`, `const`) are
            # still text the model reads, so they are not filtered out.
            _collect_text(node[key], out)
        return
    if isinstance(node, list):
        for item in node:
            _collect_text(item, out)


def hidden_text(tool: dict[str, Any]) -> list[str]:
    """Text in the definition that the reviewer surface does not contain.

    Compared after folding, so a difference here is a difference in words
    rather than in whitespace.
    """
    shown = fold_text(reviewer_surface(tool))
    hidden: list[str] = []
    chunks: list[str] = []
    _collect_text(tool, chunks)
    for chunk in chunks:
        folded = fold_text(chunk)
        if folded and folded not in shown:
            hidden.append(chunk)
    return hidden


def header_mirrored_parameters(tool: dict[str, Any]) -> list[Finding]:
    """Every parameter whose value would be mirrored into an HTTP header.

    Schemas are resolved first: an `x-mcp-header` sitting behind a `$ref` is
    the same exposure as one written inline, and a scanner that only reads the
    literal `inputSchema` misses it. That indirection is one line of schema to
    write and the difference between a scan that works and a scan that reports
    zero.
    """
    findings: list[Finding] = []
    for field in ("inputSchema", "outputSchema"):
        schema = tool.get(field)
        if not isinstance(schema, dict):
            continue
        resolved = resolve_schema(schema)
        _find_headers(resolved, f"{field}", findings)
    return findings


def _find_headers(node: Any, path: str, out: list[Finding]) -> None:
    if isinstance(node, dict):
        header = node.get(HEADER_ANNOTATION)
        if isinstance(header, str):
            out.append(
                Finding(
                    kind="header-mirrored-parameter",
                    path=path,
                    detail=(
                        f"argument value is copied into HTTP header "
                        f"Mcp-Param-{header} and is readable by every network "
                        f"intermediary on the path"
                    ),
                )
            )
        for key, sub in node.items():
            _find_headers(sub, f"{path}.{key}", out)
        return
    if isinstance(node, list):
        for index, item in enumerate(node):
            _find_headers(item, f"{path}[{index}]", out)


def unresolvable_refs(tool: dict[str, Any]) -> list[Finding]:
    """Schema references this client cannot follow, and therefore cannot pin.

    See `pin/canonical.py::_resolve_refs`. A definition with one of these has
    part of its contract stored somewhere the pin never covered, so the pin's
    guarantee is narrower than it looks. Reported so a host can decline to pin
    rather than pin something incomplete and believe it is protected.
    """
    findings: list[Finding] = []
    for field in ("inputSchema", "outputSchema"):
        schema = tool.get(field)
        if not isinstance(schema, dict):
            continue
        _find_unresolved(resolve_schema(schema), field, findings)
    return findings


def _find_unresolved(node: Any, path: str, out: list[Finding]) -> None:
    if isinstance(node, dict):
        if node.get("$pin") == "<pin:unresolved-ref>":
            out.append(
                Finding(
                    kind="unresolvable-ref",
                    path=path,
                    detail=(
                        f"{node.get('$ref')!r} was never fetched, so what this "
                        f"tool accepts is not covered by any fingerprint"
                    ),
                )
            )
        for key, sub in node.items():
            _find_unresolved(sub, f"{path}.{key}", out)
        return
    if isinstance(node, list):
        for index, item in enumerate(node):
            _find_unresolved(item, f"{path}[{index}]", out)


def scan(tool: dict[str, Any]) -> list[Finding]:
    """Every advisory finding for one tool definition.

    Order of the returned list is not severity. There is no severity here; a
    scanner that ranks heuristics invites the reader to treat the top one as
    confirmed. These are things worth a human's attention at approval time,
    which is the only moment the pin cannot help.
    """
    findings = header_mirrored_parameters(tool)
    findings += unresolvable_refs(tool)
    for chunk in hidden_text(tool):
        findings.append(
            Finding(
                kind="text-outside-the-reviewed-surface",
                path="(definition)",
                detail=chunk,
            )
        )
    return findings
