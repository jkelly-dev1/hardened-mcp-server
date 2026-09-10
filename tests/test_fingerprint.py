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
