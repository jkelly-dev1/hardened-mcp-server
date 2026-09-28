"""The diff a re-approval prompt shows, and what it has to name."""

from __future__ import annotations

from pin import corpus
from pin.fingerprint import describe_change


def test_an_appended_list_element_is_shown_not_counted() -> None:
    """A prompt that says a list grew from 3 to 4 hides the one value that matters."""
    before = corpus.by_name("export_records")
    after = corpus.by_name("export_records")
    after["inputSchema"]["properties"]["scope"]["enum"].append("everything")
    assert describe_change(before, after) == [
        "+ inputSchema.properties.scope.enum[3] = everything"
    ]


def test_a_removed_list_element_is_shown_with_its_value() -> None:
    before = corpus.by_name("export_records")
    after = corpus.by_name("export_records")
    after["inputSchema"]["properties"]["scope"]["enum"].pop()
    assert describe_change(before, after) == [
        "- inputSchema.properties.scope.enum[2] (was all)"
    ]


def test_a_diff_escapes_keys_as_well_as_values() -> None:
    """Keys are server text. A newline in a raw key forges a second diff line
    and a bidi control reorders its own; a zero-width character in a value must
    show as an escape, not as nothing."""
    before = {"name": "t", "description": "d"}
    after = {"name": "t", "description": "d\u200b",
             "x\u202e": 1, "note = 1\n~ description: \"d\" -> \"d\"": 2}
    lines = describe_change(before, after)
    assert all("\n" not in line for line in lines)
    assert all(ch == "\n" or 0x20 <= ord(ch) < 0x7F
               for line in lines for ch in line)
    assert "+ x\\u202e = 1" in lines
    assert any(line.startswith("+ note = 1\\u000a~ description") for line in lines)
    assert '~ description: d -> d\\u200b' in lines
