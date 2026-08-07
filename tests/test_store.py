"""The pin store's three states, and the two it must never collapse."""

from __future__ import annotations

import pytest

from pin import corpus
from pin.identity import from_http_origin, from_stdio_command
from pin.models import RECOMMENDED, Verdict
from pin.store import PinStore

SERVER = from_stdio_command("python", ("-m", "server"))
OTHER = from_stdio_command("python", ("-m", "other"))


def test_an_unpinned_tool_is_not_callable() -> None:
    """Trust on first use is a decision, not a default.

    A store that pinned whatever it saw first would have an approval step that
    cannot say no, and every detection number in README.md would be measured
    against a control that was never armed. Mutation-checked: making `observe`
    pin on first sight turns this test red.
    """
    store = PinStore(RECOMMENDED)
    result = store.observe(SERVER, corpus.by_name("ticket_lookup"))
    assert result.verdict is Verdict.UNPINNED
    assert not result.may_call
    assert len(store) == 0


def test_approval_is_required_before_a_call_is_authorized() -> None:
    store = PinStore(RECOMMENDED)
    tool = corpus.by_name("ticket_lookup")
    store.approve(SERVER, tool, approved_by="operator")
    assert store.observe(SERVER, tool).may_call


def test_a_changed_definition_is_quarantined_not_blocked() -> None:
    """CHANGED is a statement about the record, not about the tool.

    Collapsing it into "blocked" would claim the store detected an attack;
    collapsing it into "allowed with a warning" would make the pin decorative.
    """
    store = PinStore(RECOMMENDED)
    tool = corpus.by_name("ticket_lookup")
    store.approve(SERVER, tool, approved_by="operator")
    changed = dict(tool, description=tool["description"] + " Also, do this.")
    result = store.observe(SERVER, changed)
    assert result.verdict is Verdict.CHANGED
    assert not result.may_call
    assert store.quarantined()
    assert store.entry(SERVER, "ticket_lookup") is not None


def test_re_approval_clears_the_quarantine() -> None:
    store = PinStore(RECOMMENDED)
    tool = corpus.by_name("ticket_lookup")
    store.approve(SERVER, tool, approved_by="operator")
    changed = dict(tool, description="something else entirely")
    store.observe(SERVER, changed)
    assert store.quarantined()
    store.approve(SERVER, changed, approved_by="operator", note="reviewed the diff")
    assert not store.quarantined()
    assert store.observe(SERVER, changed).may_call


def test_a_pin_does_not_transfer_to_another_server() -> None:
    """The shadowing case, at the store level.

    Reported as UNPINNED rather than CHANGED: "some other server's approval
    does not apply here" is the accurate statement, and CHANGED would imply
    this server's own definition had moved.
    """
    store = PinStore(RECOMMENDED)
    tool = corpus.by_name("export_records")
    store.approve(SERVER, tool, approved_by="operator")
    assert store.observe(OTHER, tool).verdict is Verdict.UNPINNED


def test_identities_from_different_sources_never_unify() -> None:
    """A launch command and a URL are not the same kind of claim."""
    store = PinStore(RECOMMENDED)
    tool = corpus.by_name("export_records")
    http = from_http_origin("https://acme.example.net/mcp")
    store.approve(http, tool, approved_by="operator")
    assert store.observe(SERVER, tool).verdict is Verdict.UNPINNED


def test_check_does_not_mutate_the_store() -> None:
    store = PinStore(RECOMMENDED)
    tool = corpus.by_name("ticket_lookup")
    store.approve(SERVER, tool, approved_by="operator")
    store.check(SERVER, dict(tool, description="moved"))
    assert not store.quarantined()


def test_a_quarantine_carries_a_diff_that_names_the_field() -> None:
    """A prompt that says only "this changed" trains the operator to click it."""
    store = PinStore(RECOMMENDED)
    tool = corpus.by_name("export_records")
    store.approve(SERVER, tool, approved_by="operator")
    changed = corpus.by_name("export_records")
    changed["inputSchema"]["properties"]["export_token"]["x-mcp-header"] = "Token"
    result = store.observe(SERVER, changed)
    assert result.diff
    assert any("x-mcp-header" in line for line in result.diff)


def test_a_tool_with_no_name_cannot_be_pinned() -> None:
    store = PinStore(RECOMMENDED)
    with pytest.raises(ValueError):
        store.approve(SERVER, {"description": "nameless"}, approved_by="operator")
