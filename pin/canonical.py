"""Turning a tool definition into the exact string that gets hashed.

Two independent stages, and keeping them independent is the point of the
module. `select()` decides WHICH fields are in scope. `canonicalize()` decides
HOW they are normalized. The measurement crosses them, so neither may quietly
do the other's job.

A note on what "raw" can mean here, because it is narrower than the name
suggests. Field selection has to parse the JSON, so by the time any policy sees
a definition the insignificant whitespace between tokens is already gone. RAW
therefore means "preserve key ORDER and every character inside every string,
and normalize nothing"; it separates cleanly from STRUCTURAL, which sorts keys,
and that is the distinction the grid needs it to draw.

True byte-level pinning of the transport frame is not implementable over
`tools/list`. The reason follows rather than being left as a gap. The frame
carries `nextCursor`, `ttlMs` and `cacheScope` alongside the tools. Those are
per-response values that legitimately differ between two identical listings, so
a hash over the frame alarms on every page boundary and every cache decision
while telling you nothing about the tools. Pinning has to descend to the
individual tool object to mean anything, and descending means parsing.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any

from pin.models import Canonicalization, FieldSet

#: Fields the 2026-07-28 `Tool` type declares. Ordering is irrelevant, this is
#: a membership test, but it is kept alphabetical so a spec revision that adds
#: a field is a one-line diff a reviewer can check against the schema.
DECLARED_FIELDS: frozenset[str] = frozenset(
    {
        "annotations",
        "description",
        "icons",
        "inputSchema",
        "name",
        "outputSchema",
        "title",
        "_meta",
    }
)

#: What an approval dialog shows. See models.FieldSet.REVIEWED.
REVIEWED_FIELDS: frozenset[str] = frozenset({"name", "description"})

#: Characters TEXT_FOLDED deletes outright. Every one of them is invisible in a
#: rendered approval dialog and present in the string the model tokenizes,
#: which is precisely the asymmetry that makes deleting them attractive and
#: dangerous in equal measure.
#:
#: Written as escapes rather than literals. The repository is plain ASCII
#: throughout, and this set is the one place where that rule also buys
#: reviewability: a literal zero-width joiner is invisible in an editor and
#: invisible in a diff, so nobody could check the set was right.
_INVISIBLE = frozenset(
    {
        "\u200b",  # zero width space
        "\u200c",  # zero width non-joiner
        "\u200d",  # zero width joiner
        "\u2060",  # word joiner
        "\ufeff",  # zero width no-break space / BOM
        "\u00ad",  # soft hyphen
        "\u202a",  # left-to-right embedding
        "\u202b",  # right-to-left embedding
        "\u202c",  # pop directional formatting
        "\u202d",  # left-to-right override
        "\u202e",  # right-to-left override
        "\u2066",  # left-to-right isolate
        "\u2067",  # right-to-left isolate
        "\u2068",  # first strong isolate
        "\u2069",  # pop directional isolate
    }
)

_CYCLE_MARKER = "<pin:cycle>"


def _depth_marker(node: Any) -> str:
    """A refusal to expand that still carries the identity of what was refused.

    A bare marker here is a hash collision. Two schemas that differ only past
    the cap would render identically, the fingerprint would match, and the
    store would authorize a definition the operator never approved, which is
    the one outcome this module exists to prevent. Truncating to a constant
    also makes a truncation indistinguishable from a cycle, which uses its own
    marker two functions below and records the pointer that closed it for
    exactly the same reason.

    So the cap refuses to EXPAND while still hashing what it refused. The
    digest is over the unexpanded subtree as it arrived: no `$ref` is followed,
    nothing is fetched, and a schema this process never saw is never hashed.
    """
    return "<pin:depth:%s>" % hashlib.sha256(
        _dump(node, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]
_UNRESOLVED_MARKER = "<pin:unresolved-ref>"

#: Depth cap on $ref inlining. A schema legitimately nests, but a chain this
#: deep is either generated or hostile, and either way refusing to expand it is
#: better than expanding forever. Reaching the cap is recorded in the canonical
#: form rather than silently truncated, so two schemas that differ only past
#: the cap do not collide undetected: `_depth_marker` hashes the unexpanded
#: subtree, so the refusal carries the identity of what it refused.
#:
#: note that this counts every nesting level, not `$ref` HOPS. A generated
#: schema reaches it without a single `$ref`, so the marker is on an ordinary
#: path and not an exotic one.
_MAX_REF_DEPTH = 64


def select(raw: dict[str, Any], fields: FieldSet) -> Any:
    """Project a tool definition down to the fields a policy covers.

    Returns a plain JSON-compatible value. Key order of the input is preserved,
    because RAW depends on it and no other level does.
    """
    if fields is FieldSet.NAME:
        return {"name": raw.get("name")}
    if fields is FieldSet.REVIEWED:
        return {k: v for k, v in raw.items() if k in REVIEWED_FIELDS}
    if fields is FieldSet.DECLARED:
        return {k: v for k, v in raw.items() if k in DECLARED_FIELDS}
    if fields is FieldSet.WIRE:
        return dict(raw)
    raise ValueError(f"unhandled field set: {fields!r}")


def canonicalize(value: Any, level: Canonicalization) -> str:
    """Render a selected definition as the string a fingerprint hashes."""
    if level is Canonicalization.RAW:
        return _dump(value, sort_keys=False)
    if level is Canonicalization.STRUCTURAL:
        return _dump(value, sort_keys=True)
    if level is Canonicalization.TEXT_FOLDED:
        return _dump(_fold_strings(value), sort_keys=True)
    if level is Canonicalization.SEMANTIC:
        return _dump(_resolve_refs(value), sort_keys=True)
    if level is Canonicalization.SEMANTIC_FOLDED:
        # Refs first, then folding. The other order would fold the pointer
        # strings before resolving them, and a `$ref` whose whitespace was
        # collapsed no longer resolves.
        return _dump(_fold_strings(_resolve_refs(value)), sort_keys=True)
    raise ValueError(f"unhandled canonicalization: {level!r}")


def _dump(value: Any, *, sort_keys: bool) -> str:
    """One serializer for every level, so the levels differ only by design.

    `ensure_ascii=False` matters: escaping non-ASCII would turn a homoglyph
    into a distinct \\u sequence and make TEXT_FOLDED look like it caught
    something it did not.
    """
    return json.dumps(
        value,
        sort_keys=sort_keys,
        ensure_ascii=False,
        separators=(",", ":"),
    )


# --------------------------------------------------------------------------- #
# TEXT_FOLDED
# --------------------------------------------------------------------------- #


def fold_text(text: str) -> str:
    """NFKC, delete invisibles, collapse whitespace.

    NFKC is not confusable folding, and conflating the two is the mistake this
    function exists to measure. NFKC maps compatibility characters onto their
    canonical forms, fullwidth Latin, ligatures, superscripts, non-breaking
    space, and it leaves Cyrillic, Greek and Cherokee lookalikes completely
    alone, because they are distinct characters and not compatibility variants
    of anything. So reaching for NFKC to defeat homoglyph attacks buys neither
    property it is reached for:

      - it does NOT normalize the Cyrillic 'a' that a homoglyph attack uses,
        so the false alarm it was supposed to prevent still fires, and
      - it DOES normalize fullwidth and compatibility forms, so an attacker who
        writes the payload in those characters moves the model's input without
        moving the hash.

    `tests/test_canonical.py::test_nfkc_folds_compatibility_forms_but_not_
    cyrillic_lookalikes` pins both halves, because a future reader who "fixes"
    this by adding confusable mapping would be changing what the measurement
    measures rather than improving the control.
    """
    folded = unicodedata.normalize("NFKC", text)
    folded = "".join(ch for ch in folded if ch not in _INVISIBLE)
    return " ".join(folded.split())


def _fold_strings(value: Any) -> Any:
    """Apply `fold_text` to string VALUES, never to object keys.

    Keys are structural. Folding them would merge two distinct JSON Schema
    properties into one, which changes what the schema accepts. A
    canonicalizer that alters the meaning of the thing it is canonicalizing is
    not a canonicalizer.
    """
    if isinstance(value, str):
        return fold_text(value)
    if isinstance(value, dict):
        return {k: _fold_strings(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_fold_strings(v) for v in value]
    return value


# --------------------------------------------------------------------------- #
# SEMANTIC
# --------------------------------------------------------------------------- #


def _resolve_refs(value: Any) -> Any:
    """Inline `$ref` targets and drop the now-redundant `$defs` blocks.

    Two cases motivate this level and they pull in opposite directions under
    every other level, so one canonicalization has to handle both:

      a schema rewritten to hoist a repeated subschema into `$defs` validates
      exactly as before and should NOT trigger re-approval, and

      a schema whose reachable content changed MUST trigger it, however the
      change was expressed.

    What this level actually buys, measured rather than assumed: only the
    first. An edit to a LOCAL `$defs` entry is already visible to RAW and
    STRUCTURAL, because the `$defs` block is inside the bytes they hash; they
    catch it, just not for a reason that generalizes. So SEMANTIC is not "the
    level that catches reference attacks"; it is the level that stops
    punishing a rewrite which changed nothing, and it costs no coverage to
    adopt.

    And one case defeats every level on this ladder, which is worth more than
    a level that won: a `$ref` to a schema the client never fetched: an
    absolute URL, or an unresolvable `$anchor`. The effective contract then
    lives somewhere no policy hashed, the referencing bytes stay identical
    while what the tool accepts changes underneath, and there is no field-set
    or canonicalization choice that recovers it. `_dereference` returns None
    for these and `_inline` marks them `<pin:unresolved-ref>` rather than
    quietly treating them as stable. The only real answer is a client that
    REFUSES to pin a schema it cannot fully resolve, which is a policy
    decision this module surfaces and does not make; see
    `pin/scan.py::unresolvable_refs` and README.md section 6.

    Resolution scope is the part that is easy to get wrong, and getting it
    wrong fails silently in both directions. A `$ref` of `#/$defs/P` inside a
    tool's `inputSchema` is a pointer into THAT SCHEMA, not into the tool
    object that contains it. Resolving it against the tool object finds
    nothing, every reference is marked unresolved, and the two cases above
    inverted: the edited target now hashes identically to the original because
    both sides are just an unresolved marker, and the hoisted rewrite still
    differs because one side inlines and the other does not. The level appears
    to work, it produces different digests for different inputs, while doing
    the opposite of its purpose in both of the only two cases it exists for.
    `tests/test_canonical.py` pins each direction separately for that reason; a
    single test that the digests differ would have passed throughout.
    """
    return _resolve_in_schema_scopes(value, 0)


#: Tool fields whose value is a JSON Schema document, and therefore its own
#: `$ref` resolution root. Per the 2026-07-28 Tool type; both default to
#: 2020-12 when no `$schema` is present.
_SCHEMA_FIELDS = ("inputSchema", "outputSchema")


def _resolve_in_schema_scopes(node: Any, depth: int) -> Any:
    """Walk a tool definition, inlining each schema field within its own scope.

    Anything outside a schema field is copied through: a `$ref` in a
    description is a string that happens to look like a pointer, and expanding
    it would be inventing structure the server never declared.
    """
    if depth > _MAX_REF_DEPTH:
        return _depth_marker(node)
    if isinstance(node, list):
        return [_resolve_in_schema_scopes(item, depth + 1) for item in node]
    if not isinstance(node, dict):
        return node

    out: dict[str, Any] = {}
    for key, sub in node.items():
        if key in _SCHEMA_FIELDS and isinstance(sub, dict):
            out[key] = _inline(sub, sub, (), 0)
        else:
            out[key] = _resolve_in_schema_scopes(sub, depth + 1)
    return out


def resolve_schema(schema: dict[str, Any]) -> Any:
    """Inline one JSON Schema against itself. Exposed for tests and for
    `pin/scan.py`, which needs the expanded schema to find `x-mcp-header`
    annotations that a `$ref` would otherwise hide behind one indirection."""
    return _inline(schema, schema, (), 0)


def _inline(node: Any, root: dict[str, Any], seen: tuple[str, ...], depth: int) -> Any:
    if depth > _MAX_REF_DEPTH:
        return _depth_marker(node)

    if isinstance(node, list):
        return [_inline(item, root, seen, depth + 1) for item in node]

    if not isinstance(node, dict):
        return node

    ref = node.get("$ref")
    if isinstance(ref, str):
        if ref in seen:
            # A cycle. Recorded rather than expanded, and recorded with the
            # pointer that closed it so two different cycles do not collide.
            return {"$ref": ref, "$pin": _CYCLE_MARKER}
        target = _dereference(ref, root)
        if target is None:
            # An external or unresolvable pointer. Left in place: pretending to
            # have expanded something that was never fetched would hash a
            # schema this process never saw.
            resolved: Any = {"$ref": ref, "$pin": _UNRESOLVED_MARKER}
        else:
            resolved = _inline(target, root, seen + (ref,), depth + 1)
        # Draft 2020-12 allows $ref to carry siblings, and the siblings apply
        # on top of the target. Merge in that direction.
        siblings = {k: v for k, v in node.items() if k != "$ref"}
        if not siblings:
            return resolved
        if isinstance(resolved, dict):
            merged = dict(resolved)
            merged.update(_inline(siblings, root, seen, depth + 1))
            return merged
        return {"$pin:target": resolved, **_inline(siblings, root, seen, depth + 1)}

    # `$defs` and `definitions` hold subschemas that exist only to be
    # referenced. Once every reference is inlined they are unreachable, and
    # keeping them would make the hoisted rewrite differ from the original:
    # the exact false alarm this level removes. An unreferenced entry is dead
    # weight in the schema too, so dropping it loses nothing that validates.
    return {
        key: _inline(sub, root, seen, depth + 1)
        for key, sub in node.items()
        if key not in ("$defs", "definitions")
    }


def _dereference(ref: str, root: dict[str, Any]) -> Any | None:
    """Resolve a local JSON Pointer. Anything else returns None."""
    if not ref.startswith("#"):
        return None
    pointer = ref[1:]
    if pointer in ("", "/"):
        return root
    if not pointer.startswith("/"):
        # A `$anchor` style reference. Not resolvable without an anchor index,
        # and guessing would be worse than declaring it unresolved.
        return None
    node: Any = root
    for token in pointer.lstrip("/").split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict):
            if token not in node:
                return None
            node = node[token]
        elif isinstance(node, list):
            try:
                node = node[int(token)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return node
