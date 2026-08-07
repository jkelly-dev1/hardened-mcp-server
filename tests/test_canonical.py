"""The canonicalization ladder, one property per test.

These are the tests that decide whether the measurement means anything, because
every number in README.md is downstream of what `canonicalize` considers equal.
Each level is pinned by what it MUST accept and what it MUST still reject; a
test asserting only that two digests differ would pass for a level that was
doing nothing at all, which is how the `$ref` scope defect survived being
written (see the bug log).
"""

from __future__ import annotations

import json

from pin.canonical import canonicalize, fold_text, resolve_schema, select
from pin.models import Canonicalization, FieldSet

FULLWIDTH_A = "\uff41"  # fullwidth a: a compatibility form of "a"
CYRILLIC_A = "\u0430"  # Cyrillic a: a distinct letter that looks like "a"
ZWSP = "\u200b"
RLO = "\u202e"


def test_nfkc_folds_compatibility_forms_but_not_cyrillic_lookalikes() -> None:
    """Both halves, because either alone points at the wrong conclusion.

    A reader told only that NFKC normalizes lookalikes concludes folding
    defeats homoglyph attacks. A reader told only that it leaves Cyrillic alone
    concludes folding is harmless. Neither is true, and the pair is the reason
    TEXT_FOLDED is a trade.
    """
    assert fold_text(FULLWIDTH_A) == "a"
    assert fold_text("\ufb01") == "fi"  # the fi ligature
    assert fold_text(CYRILLIC_A) != "a"
    assert fold_text(CYRILLIC_A) == CYRILLIC_A


def test_folding_deletes_characters_the_model_still_reads() -> None:
    assert fold_text(f"ne{ZWSP}w") == "new"
    assert fold_text(f"{RLO}abc") == "abc"


def test_folding_leaves_object_keys_alone() -> None:
    """Folding a key would merge two schema properties into one.

    A canonicalizer that changes what the document means is not canonicalizing.
    """
    value = {"properties": {f"a{ZWSP}b": {"type": "string"}, "ab": {"type": "number"}}}
    folded = json.loads(canonicalize(value, Canonicalization.TEXT_FOLDED))
    assert len(folded["properties"]) == 2


def test_structural_accepts_a_key_reorder_and_nothing_else() -> None:
    a = {"name": "t", "description": "d", "title": "x"}
    b = {"title": "x", "description": "d", "name": "t"}
    assert canonicalize(a, Canonicalization.RAW) != canonicalize(b, Canonicalization.RAW)
    assert canonicalize(a, Canonicalization.STRUCTURAL) == canonicalize(
        b, Canonicalization.STRUCTURAL
    )
    changed = dict(a, description="d ")
    assert canonicalize(a, Canonicalization.STRUCTURAL) != canonicalize(
        changed, Canonicalization.STRUCTURAL
    )


def test_semantic_accepts_a_defs_rewrite_that_validates_identically() -> None:
    inline = {
        "inputSchema": {
            "type": "object",
            "properties": {"q": {"type": "string", "maxLength": 32}},
        }
    }
    hoisted = {
        "inputSchema": {
            "$defs": {"P": {"type": "string", "maxLength": 32}},
            "type": "object",
            "properties": {"q": {"$ref": "#/$defs/P"}},
        }
    }
    assert canonicalize(inline, Canonicalization.SEMANTIC) == canonicalize(
        hoisted, Canonicalization.SEMANTIC
    )


def test_semantic_still_rejects_an_edit_to_the_referenced_subschema() -> None:
    """The companion to the test above, and the one that gives it content.

    Accepting the hoisted rewrite is only correct if the level can still tell
    when the hoisted subschema CHANGES. Without this, a canonicalizer that
    deleted every schema would pass the previous test.
    """
    before = {
        "inputSchema": {
            "$defs": {"P": {"type": "string", "maxLength": 32}},
            "type": "object",
            "properties": {"q": {"$ref": "#/$defs/P"}},
        }
    }
    after = json.loads(json.dumps(before))
    after["inputSchema"]["$defs"]["P"]["maxLength"] = 99999
    assert canonicalize(before, Canonicalization.SEMANTIC) != canonicalize(
        after, Canonicalization.SEMANTIC
    )


def test_refs_resolve_against_the_schema_root_not_the_tool_object() -> None:
    """The scope defect, pinned.

    `#/$defs/P` inside `inputSchema` points into that schema. Resolving it
    against the enclosing tool object finds nothing, and the level then reports
    every reference unresolved, which still produces different digests for
    different inputs, so it looks like it works. This is the assertion that
    says it actually resolved.
    """
    tool = {
        "name": "t",
        "inputSchema": {
            "$defs": {"P": {"type": "string", "maxLength": 32}},
            "type": "object",
            "properties": {"q": {"$ref": "#/$defs/P"}},
        },
    }
    rendered = canonicalize(select(tool, FieldSet.DECLARED), Canonicalization.SEMANTIC)
    assert "maxLength" in rendered
    assert "$ref" not in rendered
    assert "unresolved" not in rendered


def test_an_absolute_ref_is_marked_unresolved_rather_than_treated_as_stable() -> None:
    schema = {
        "type": "object",
        "properties": {"a": {"$ref": "https://example.net/s.json"}},
    }
    resolved = resolve_schema(schema)
    assert resolved["properties"]["a"]["$pin"] == "<pin:unresolved-ref>"


def test_a_ref_cycle_terminates() -> None:
    schema = {
        "$defs": {"node": {"type": "object", "properties": {"next": {"$ref": "#/$defs/node"}}}},
        "type": "object",
        "properties": {"head": {"$ref": "#/$defs/node"}},
    }
    rendered = json.dumps(resolve_schema(schema))
    assert "<pin:cycle>" in rendered


def test_selecting_wire_keeps_a_key_the_declared_set_drops() -> None:
    tool = {"name": "t", "description": "d", "instructions": "planted"}
    assert "instructions" not in select(tool, FieldSet.DECLARED)
    assert "instructions" in select(tool, FieldSet.WIRE)


def test_semantic_folded_resolves_before_folding() -> None:
    """Folding first would collapse whitespace inside a pointer and break it."""
    tool = {
        "inputSchema": {
            "$defs": {"P": {"type": "string", "description": "a  b"}},
            "type": "object",
            "properties": {"q": {"$ref": "#/$defs/P"}},
        }
    }
    rendered = canonicalize(tool, Canonicalization.SEMANTIC_FOLDED)
    assert "$ref" not in rendered
    assert "a b" in rendered


def _deeply_nested(leaf_max_length: int, levels: int = 70) -> dict:
    """A schema deeper than the expansion cap, differing only at the leaf."""
    node: dict = {"type": "string", "maxLength": leaf_max_length}
    for _ in range(levels):
        node = {"type": "object", "properties": {"n": node}}
    return {"name": "t", "description": "d", "inputSchema": node}


def test_two_schemas_differing_only_past_the_depth_cap_do_not_collide() -> None:
    """The cap refuses to expand. It must not refuse to distinguish.

    A truncation that renders as a constant is a hash collision: two schemas
    that differ only past the cap produce the same canonical form, the
    fingerprint matches, and the store authorizes a definition the operator
    never approved. The cap counts every nesting level, not `$ref` HOPS, so an
    ordinary generated schema reaches it without a single `$ref`.

    Mutation check, executed against the canonicalizer: replace
    `_depth_marker(node)` with the bare `_CYCLE_MARKER` at either cap site and
    this fails. It also fails if the marker stops depending on the subtree.
    """
    a = _deeply_nested(1)
    b = _deeply_nested(99999)
    assert a != b, "the fixture must actually differ, or this tests nothing"

    for fields in (FieldSet.WIRE, FieldSet.DECLARED):
        for level in (Canonicalization.RAW, Canonicalization.SEMANTIC):
            ca = canonicalize(select(a, fields), level)
            cb = canonicalize(select(b, fields), level)
            assert ca != cb, f"collision at {fields}/{level}"

    # And a truncation must remain distinguishable from a cycle, which carries
    # its own marker and its own pointer.
    assert "<pin:depth:" in canonicalize(
        select(a, FieldSet.WIRE), Canonicalization.SEMANTIC
    )


def test_the_depth_cap_still_matches_an_unchanged_schema() -> None:
    """The other half: refusing to expand must not break a legitimate re-check.

    A marker that varied per call, a counter, an id, anything not derived
    from the subtree, would make every deep schema look CHANGED on every
    check and quietly train an operator to re-approve.
    """
    a = _deeply_nested(1)
    first = canonicalize(select(a, FieldSet.WIRE), Canonicalization.SEMANTIC)
    second = canonicalize(select(_deeply_nested(1), FieldSet.WIRE), Canonicalization.SEMANTIC)
    assert first == second
