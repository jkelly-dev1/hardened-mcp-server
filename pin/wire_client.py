"""An MCP client that will not call a tool whose definition moved.

The pinning logic lives in `pin/store.py` and knows nothing about the network.
This module is the part that has to touch the protocol, and it exists so the
measurement is made against real frames from a real server rather than against
a description of what a server would send.

Why it does not use `Client.list_tools()`, which is the obvious call. That
method returns `ListToolsResult`, whose `tools` are `mcp_types.Tool` instances,
and `Tool` leaves pydantic's `extra` setting at its default, `ignore`. Any
top-level key the schema does not name is gone before the caller sees it. Fingerprinting those
objects therefore fingerprints a view with an entire class of content already
filtered out. The client would compute a digest, compare it, find it equal, and
be correct about the wrong bytes.

So `raw_tool_list()` sends the same request through `session.send_request` with
a permissive `TypeAdapter`, which the SDK honors by returning the validated
payload unchanged. This is a supported path and not a hack, but it IS a
deliberate step outside the typed API, and a client that wants wire-level
integrity has to take it. That is a finding about the ecosystem, not a
complaint about the SDK: the type system is doing its job by discarding fields
it cannot vouch for, and integrity checking needs the bytes that were actually
on the wire.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from pin.identity import ServerIdentity, from_stdio_command
from pin.models import CheckResult, PinPolicy, Verdict
from pin.scan import Finding, scan
from pin.store import PinStore


@dataclass(slots=True)
class ToolGate:
    """The client's answer for one tool: may it be called, and why not.

    Carries the advisory scan findings alongside the pin verdict without
    merging them. A MATCH with three scan findings is a tool that is unchanged
    since approval AND was worth a closer look when it was approved; collapsing
    those into one status would lose the distinction that pinning proves
    "unchanged" and never proves "safe".
    """

    check: CheckResult
    findings: list[Finding] = field(default_factory=list)

    @property
    def may_call(self) -> bool:
        return self.check.may_call


class PinningClient:
    """Wraps an SDK client with an approval gate over tool definitions."""

    def __init__(self, session: Any, identity: ServerIdentity, store: PinStore,
                 reported_name: str | None = None) -> None:
        self._session = session
        self.identity = identity
        self.store = store
        #: The `serverInfo.name` this connection's server reported, as it came
        #: over the wire. Recorded for the measurement that shows why it must
        #: not key a pin; nothing on the pinning path reads it.
        self.reported_name = reported_name

    # ------------------------------------------------------------------ #

    async def raw_tool_list(self) -> list[Any]:
        """`tools/list` as JSON, with nothing filtered out.

        See the module docstring for why this is not `client.list_tools()`.
        """
        # Both arrive with `mcp` (requirements.txt): mcp_types is its wire
        # model package and pydantic its validation layer.
        import mcp_types as types
        from pydantic import TypeAdapter

        # `ClientRequest` is a union alias in the 2.x types, not a wrapper
        # class, so the request model is passed directly.
        payload: dict[str, Any] = await self._session.send_request(
            types.ListToolsRequest(), TypeAdapter(dict[str, Any])
        )
        if payload.get("nextCursor"):
            # Only a whole listing can be checked for a name offered twice; a
            # duplicate split across pages would never be seen. Refused, not
            # followed, so the check stays one listing wide.
            raise PermissionError(
                "listing refused: tools/list is paginated, and only a "
                "complete listing can be verified")
        tools = payload.get("tools")
        # Returned as sent. Dropping an entry that is not an object here would
        # hide it from the refusal below, which rejects the whole listing.
        return list(tools) if isinstance(tools, list) else []

    async def checked_tool_list(self) -> list[dict[str, Any]]:
        """`raw_tool_list()`, refused whole unless every entry is an object
        with a name and no name appears twice.

        The one way into a listing for any caller that reads entries by name.
        `verify()` uses it, and so do the measurement harnesses, so a
        malformed listing is refused with the same message everywhere instead
        of surfacing as a TypeError in whichever caller indexes it first.
        """
        listing = await self.raw_tool_list()
        _refuse_ambiguous(listing)
        return listing

    async def verify(self) -> dict[str, ToolGate]:
        """Check every offered tool against the pins on file.

        Returns a gate per tool NAME as the server offered it. Names are not
        deduplicated against other servers here; this client talks to one
        server and the store is keyed by identity, so shadowing is resolved by
        the key rather than by anything this method does. See `pin/shadow.py`.

        The listing is checked as a whole before any entry in it is gated.
        Every entry must carry a name, and no name may appear twice: a gate is
        keyed by name and holds one entry per name, so a listing that repeats
        one would let the server choose, by ordering, which definition the
        gate describes and which one a call proceeds on. A nameless entry has
        nothing to gate and nothing to pin. Either refuses the WHOLE listing
        rather than the offending entry, because a server that produces one
        is not a server whose remaining entries are trusted by default.
        """
        listing = await self.checked_tool_list()
        gates: dict[str, ToolGate] = {}
        for definition in listing:
            result = self.store.observe(self.identity, definition)
            gates[result.tool] = ToolGate(check=result, findings=scan(definition))
        return gates

    async def call(self, name: str, arguments: dict[str, Any]) -> Any:
        """Call a tool, or refuse and say which verdict refused it.

        The check re-reads the listing instead of trusting the last one. A pin
        verified once at connect time and never again is a pin that covers the
        connect, and the 2026-07-28 core is stateless; there is no session
        guaranteeing the next request even reaches the same process. What that
        costs, and what a client-side cache does to it, is the subject of
        `pin/exposure.py`.
        """
        gates = await self.verify()
        gate = gates.get(name)
        if gate is None:
            raise PermissionError(f"{name}: not offered by this server")
        if not gate.may_call:
            raise PermissionError(
                f"{name}: refused, verdict={gate.check.verdict.value}. "
                f"{_explain(gate.check)}"
            )
        return await self._session.call_tool(name, arguments)


def _refuse_ambiguous(listing: list[Any]) -> None:
    """Raise unless every entry has a name and every name appears once."""
    seen: set[str] = set()
    for definition in listing:
        if not isinstance(definition, dict):
            raise PermissionError("listing refused: an offered tool is not an object")
        name = definition.get("name")
        if not isinstance(name, str) or not name:
            raise PermissionError("listing refused: an offered tool has no name")
        if name in seen:
            raise PermissionError(f"listing refused: {name} is offered more than once")
        seen.add(name)


def _explain(check: CheckResult) -> str:
    if check.verdict is Verdict.UNPINNED:
        return "no approval on file for this server and tool"
    if check.verdict is Verdict.CHANGED:
        if not check.diff:
            # A digest that moved while no field value did: the change is in
            # the encoding, which a RAW policy hashes. Said outright, since a
            # sentence ending at a colon reads as a truncated report.
            return (
                "definition changed since approval; no field value differs, so "
                "the change is in the encoding (key order or serialization), "
                f"which {check.policy.label} hashes"
            )
        head = "; ".join(check.diff[:3])
        more = f" (+{len(check.diff) - 3} more)" if len(check.diff) > 3 else ""
        return f"definition changed since approval: {head}{more}"
    return ""


@asynccontextmanager
async def connect_stdio(
    command: str,
    args: tuple[str, ...],
    policy: PinPolicy,
    *,
    store: PinStore | None = None,
):
    """Connect to a stdio server and yield a `PinningClient`.

    Identity comes from the arguments to this function, not from the
    connection. The command and its arguments are what the host configured;
    nothing the server says can change them. `pin/identity.py` has the spec
    citations for why the alternative, keying pins by `serverInfo.name`, is
    keying them by a value the specification says not to rely on.
    """
    from mcp.client import Client
    from mcp.client.stdio import StdioServerParameters, stdio_client

    identity = from_stdio_command(command, args)
    params = StdioServerParameters(command=command, args=list(args))
    # `Client` takes the transport itself and enters it. Entering it here first
    # and handing over the yielded streams passes a tuple where a context
    # manager is expected.
    async with Client(stdio_client(params)) as client:
        info = client.server_info
        yield PinningClient(
            session=client.session,
            identity=identity,
            store=store if store is not None else PinStore(policy),
            reported_name=info.name if info is not None else None,
        )
