"""The client's gate over a listing, exercised without a network.

`PinningClient.verify()` and `call()` reach the SDK only through
`raw_tool_list()`, so a stub session and a replaced listing are enough to ask
what the client does with a listing a hostile server could send. The tests run
their coroutines with `asyncio.run` rather than the anyio marker, so the
pytest-only CI job runs them too.
"""

from __future__ import annotations

import asyncio

import pytest

from pin import corpus
from pin.identity import from_stdio_command
from pin.models import RECOMMENDED, Canonicalization, FieldSet, PinPolicy, Verdict
from pin.mutations import MUTATIONS
from pin.store import PinStore
from pin.wire_client import PinningClient, _explain

SERVER = from_stdio_command("python", ("-m", "server"))


class _Session:
    """Records tool calls; speaks no protocol."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    async def call_tool(self, name: str, arguments: dict) -> str:
        self.calls.append((name, arguments))
        return "executed"


def _client(listing: list[dict]) -> tuple[PinningClient, _Session]:
    """A client with every corpus tool approved, served the given listing."""
    store = PinStore(RECOMMENDED)
    for tool in corpus.baseline():
        store.approve(SERVER, tool, approved_by="operator")
    session = _Session()
    client = PinningClient(session=session, identity=SERVER, store=store)

    async def raw_tool_list() -> list[dict]:
        return listing

    client.raw_tool_list = raw_tool_list  # type: ignore[method-assign]
    return client, session


def _mutated_export_records() -> dict:
    mutation = next(m for m in MUTATIONS if m.key == "header_exfil")
    return mutation(corpus.by_name("export_records"))


def test_a_listing_that_offers_one_name_twice_is_refused_whole() -> None:
    """Two definitions under one name, the approved one listed last.

    A gate is keyed by name and holds one entry per name, so a listing that
    repeats a name would let the server choose, by ordering, which definition
    the gate describes and which one a call proceeds on. The listing is
    refused before any entry is gated, so the order decides nothing.
    """
    client, session = _client(
        [_mutated_export_records(), corpus.by_name("export_records")]
    )
    with pytest.raises(PermissionError, match="export_records"):
        asyncio.run(client.verify())
    with pytest.raises(PermissionError):
        asyncio.run(client.call("export_records", {"scope": "all"}))
    assert session.calls == []


def test_a_nameless_entry_in_the_listing_is_refused_whole() -> None:
    """An entry with no name has nothing to gate and nothing to pin."""
    client, session = _client([corpus.by_name("export_records"), {}])
    with pytest.raises(PermissionError, match="no name"):
        asyncio.run(client.verify())
    with pytest.raises(PermissionError):
        asyncio.run(client.call("export_records", {"scope": "all"}))
    assert session.calls == []


def test_a_clean_listing_still_gates_every_tool() -> None:
    """The control: a client that refused every listing would pass both above."""
    client, _ = _client(corpus.baseline())
    gates = asyncio.run(client.verify())
    assert set(gates) == set(corpus.NAMES)
    assert all(gate.may_call for gate in gates.values())


def test_a_change_with_no_field_diff_is_explained_rather_than_cut_off() -> None:
    """Under wire/raw a key reorder is CHANGED and no field value differs.

    The explanation has to say so. A message that stops at a colon reads as a
    truncated report, and a re-approval prompt nobody can read is a prompt
    that gets clicked through.
    """
    store = PinStore(PinPolicy(FieldSet.WIRE, Canonicalization.RAW))
    tool = corpus.by_name("ticket_lookup")
    store.approve(SERVER, tool, approved_by="operator")
    reorder = next(m for m in MUTATIONS if m.key == "key_reorder")
    check = store.observe(SERVER, reorder(tool))
    assert check.verdict is Verdict.CHANGED
    assert check.diff == []
    text = _explain(check)
    assert not text.rstrip().endswith(":")
    assert "encoding" in text
