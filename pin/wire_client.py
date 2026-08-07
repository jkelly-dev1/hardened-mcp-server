"""An MCP client that will not call a tool whose definition moved.

The pinning logic lives in `pin/store.py` and knows nothing about the network.
This module is the part that has to touch the protocol, and it exists so the
measurement is made against real frames from a real server rather than against
a description of what a server would send.

WHY IT DOES NOT USE `Client.list_tools()`, which is the obvious call. That
method returns `ListToolsResult`, whose `tools` are `mcp_types.Tool` instances,
and `Tool` is declared with `ConfigDict(extra="ignore")`. Any top-level key the
schema does not name is gone before the caller sees it. Fingerprinting those
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

    def __init__(self, session: Any, identity: ServerIdentity, store: PinStore) -> None:
        self._session = session
        self.identity = identity
        self.store = store

    # ------------------------------------------------------------------ #

    async def raw_tool_list(self) -> list[dict[str, Any]]:
        """`tools/list` as JSON, with nothing filtered out.

        See the module docstring for why this is not `client.list_tools()`.
        """
        import mcp_types as types
        from pydantic import TypeAdapter

        # `ClientRequest` is a union alias in the 2.x types, not a wrapper
        # class, so the request model is passed directly.
        payload: dict[str, Any] = await self._session.send_request(
            types.ListToolsRequest(), TypeAdapter(dict[str, Any])
        )
        tools = payload.get("tools")
        return [t for t in tools if isinstance(t, dict)] if isinstance(tools, list) else []

    async def verify(self) -> dict[str, ToolGate]:
        """Check every offered tool against the pins on file.

        Returns a gate per tool NAME as the server offered it. Names are not
        deduplicated against other servers here on purpose; this client talks
        to one server and the store is keyed by identity, so shadowing is
        resolved by the key rather than by anything this method does. See
        `pin/shadow.py`.
        """
        gates: dict[str, ToolGate] = {}
        for definition in await self.raw_tool_list():
            result = self.store.observe(self.identity, definition)
            gates[result.tool] = ToolGate(check=result, findings=scan(definition))
        return gates

    async def call(self, name: str, arguments: dict[str, Any]) -> Any:
        """Call a tool, or refuse and say which verdict refused it.

        The check re-reads the listing rather than trusting the last one. A pin
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


def _explain(check: CheckResult) -> str:
    if check.verdict is Verdict.UNPINNED:
        return "no approval on file for this server and tool"
    if check.verdict is Verdict.CHANGED:
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
        yield PinningClient(
            session=client.session,
            identity=identity,
            store=store if store is not None else PinStore(policy),
        )
