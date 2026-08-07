"""Tests that require the `mcp` SDK and launch real servers over stdio.

These skip rather than fail when the SDK is absent, and every skip names what
was missing. A repository whose test suite is red on a clean checkout teaches
the reader to ignore red.

They are also the only tests that can establish certain claims at all. That the
SDK's `Tool` model discards an unknown key, and that its cache ceiling is 24
hours, are facts about a dependency; asserting them against a local
reimplementation would assert nothing. If a future SDK release changes either,
these fail and the README stops being true.
"""

from __future__ import annotations

import sys

import pytest

from pin import corpus
from pin.identity import from_stdio_command
from pin.models import RECOMMENDED, Verdict
from pin.store import PinStore

mcp = pytest.importorskip("mcp", reason="the mcp SDK is not installed")
pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def rogue_args(*extra: str) -> tuple[str, ...]:
    return ("-m", "pin.wire_server", "--rogue", *extra)


async def _listing(args: tuple[str, ...]) -> list[dict]:
    from pin.wire_client import connect_stdio

    async with connect_stdio(sys.executable, args, RECOMMENDED) as client:
        return await client.raw_tool_list()


async def test_the_client_reads_a_real_tool_list_over_stdio() -> None:
    tools = await _listing(rogue_args())
    assert [t["name"] for t in tools] == list(corpus.NAMES)


async def test_the_raw_path_preserves_a_key_the_typed_api_would_drop() -> None:
    """The reason `raw_tool_list` does not call `Client.list_tools()`.

    `mcp_types.Tool` is declared `extra="ignore"`. A client that fingerprints
    parsed models fingerprints a view with this key already removed, computes a
    matching digest, and is correct about the wrong bytes.
    """
    from mcp_types import Tool

    tools = await _listing(rogue_args("--mutation", "unknown_field_plant"))
    planted = next(t for t in tools if t["name"] == "ticket_lookup")
    assert "instructions" in planted

    parsed = Tool.model_validate(planted)
    assert not hasattr(parsed, "instructions")
    assert "instructions" not in parsed.model_dump(by_alias=True)


async def test_a_conformant_sdk_server_cannot_emit_the_planted_key() -> None:
    """The reason the rogue server writes its own frames.

    Not a client failure and not a gap in the measurement: the SDK is refusing
    to send a definition its type system does not describe, and that is correct
    of it. The attack simply does not come from a server built this way.
    """
    honest = ("-m", "pin.wire_server", "--honest", "--mutation", "unknown_field_plant")
    tools = await _listing(honest)
    served = next(t for t in tools if t["name"] == "ticket_lookup")
    assert "instructions" not in served


async def test_a_rug_pull_mid_session_is_refused() -> None:
    """The end-to-end shape: trust established, then abused, then caught."""
    from pin.wire_client import connect_stdio

    args = rogue_args("--mutation", "header_exfil", "--flip-after", "1")
    identity = from_stdio_command(sys.executable, args)
    store = PinStore(RECOMMENDED)
    for tool in corpus.baseline():
        store.approve(identity, tool, approved_by="operator")

    async with connect_stdio(sys.executable, args, RECOMMENDED, store=store) as client:
        client.identity = identity
        first = await client.verify()
        assert first["export_records"].check.verdict is Verdict.MATCH

        second = await client.verify()
        assert second["export_records"].check.verdict is Verdict.CHANGED
        with pytest.raises(PermissionError, match="definition changed"):
            await client.call("export_records", {"scope": "all"})


async def test_an_approved_tool_still_calls_through() -> None:
    """The control that stops the test above from passing on a broken client."""
    from pin.wire_client import connect_stdio

    args = rogue_args()
    identity = from_stdio_command(sys.executable, args)
    store = PinStore(RECOMMENDED)
    for tool in corpus.baseline():
        store.approve(identity, tool, approved_by="operator")

    async with connect_stdio(sys.executable, args, RECOMMENDED, store=store) as client:
        client.identity = identity
        result = await client.call(
            "ticket_lookup", {"ticket_id": "ACME-1", "region": "us-east"}
        )
        assert "ticket_lookup" in result.content[0].text


async def test_the_sdk_ttl_ceiling_is_what_this_module_assumes() -> None:
    """`pin/exposure.py` restates the ceiling; this checks the restatement."""
    from mcp.client.caching import MAX_TTL_MS

    from pin.exposure import SDK_MAX_TTL_MS

    assert MAX_TTL_MS == SDK_MAX_TTL_MS == 24 * 60 * 60 * 1000


async def test_the_server_advertises_a_cache_ttl_the_client_can_read() -> None:
    """Leg 2 rests on the server naming the interval; this is that field."""
    import json
    import subprocess

    proc = subprocess.run(
        [sys.executable, *rogue_args("--ttl-ms", "300000")],
        input='{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}\n',
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(__import__("pathlib").Path(__file__).resolve().parent.parent),
    )
    payload = json.loads(proc.stdout.strip().splitlines()[0])["result"]
    assert payload["ttlMs"] == 300_000
    assert payload["cacheScope"] == "public"
