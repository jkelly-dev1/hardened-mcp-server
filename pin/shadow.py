"""What a pin is worth when a second server claims the first one's name.

The 2026-07-28 specification says two things about aggregating tools from
several servers, and a client that reads only the first one builds this bug:

  "Clients or proxies that aggregate tools from multiple servers MAY encounter
   naming collisions ... and SHOULD implement a disambiguation strategy such as
   prefixing tool names with a server identifier."

  "The server `name` (from `serverInfo`) is not guaranteed to be unique across
   servers and SHOULD NOT be relied upon for disambiguation."

Namespace by server, and not by the name the server gives you. What identifier
remains is the one the HOST chose when it decided what to launch, which is what
`pin/identity.py` returns and what the shipped client path uses.

This measurement is a difference, not a demonstration. Both arms run the same
tools against the same pins over real stdio connections. The only variable is
where the pin's key comes from. One arm hands a rogue server an approval it
never received; the other refuses it. Quoting the specification would have been
cheaper and would not have produced a number.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from pin import corpus
from pin.identity import ServerIdentity, from_self_reported_name, from_stdio_command
from pin.models import PinPolicy, Verdict
from pin.store import PinStore

#: The name the legitimate server reports, and the name the rogue one claims.
TRUSTED_NAME = "acme-support"

#: The tool the rogue server shadows. Chosen because it takes a credential:
#: an approval that leaks onto the wrong server is worth most when the tool it
#: authorizes is the one handling secrets.
SHADOWED_TOOL = "export_records"


@dataclass(frozen=True, slots=True)
class ShadowResult:
    binding: str
    rationale: str
    #: Verdict when the LEGITIMATE server offers the tool it was approved for.
    trusted_verdict: Verdict
    #: Verdict when the ROGUE server offers a tool of the same name while
    #: self-reporting the trusted server's name.
    rogue_verdict: Verdict

    @property
    def rogue_was_allowed(self) -> bool:
        return self.rogue_verdict is Verdict.MATCH

    @property
    def trusted_still_works(self) -> bool:
        return self.trusted_verdict is Verdict.MATCH

    @property
    def sound(self) -> bool:
        """A binding is sound only if it does both jobs.

        Refusing everything would stop the rogue server and is not a control;
        `trusted_still_works` is in the conjunction so that arm cannot be
        mistaken for a pass.
        """
        return self.trusted_still_works and not self.rogue_was_allowed


async def _offered_tool(args: tuple[str, ...], tool: str) -> dict:
    """Connect to a server and return one raw tool definition."""
    from pin.wire_client import connect_stdio
    from pin.models import RECOMMENDED

    async with connect_stdio(sys.executable, args, RECOMMENDED) as client:
        for definition in await client.raw_tool_list():
            if definition.get("name") == tool:
                return definition
    raise LookupError(f"{tool} not offered by {args}")


def _trusted_args() -> tuple[str, ...]:
    return ("-m", "pin.wire_server", "--rogue", "--server-name", TRUSTED_NAME)


def _rogue_args() -> tuple[str, ...]:
    """A different process, the same self-reported name, IDENTICAL bytes.

    The definition is not mutated. A rogue server that served a rug-pulled
    definition would leave both bindings sound: the content hash catches the
    difference and the identity question is never reached. That measurement
    reports on the wrong variable while looking like it works.

    A server impersonating another does not need to change the tool it
    advertises. It advertises exactly what the operator approved and runs
    something else behind it. Every byte a fingerprint could examine is
    correct, so no field set and no canonicalization has anything to catch:
    content pinning is structurally blind to server substitution, and identity
    binding is not a refinement of it but the only control that applies.

    The `--flip-after` marker below is what makes the two launch commands
    differ as strings without changing a single byte the server emits.
    """
    return (
        "-m",
        "pin.wire_server",
        "--rogue",
        "--server-name",
        TRUSTED_NAME,
        "--flip-after",
        "0",
    )


async def run() -> tuple[ShadowResult, ...]:
    """Both bindings, against both servers."""
    from pin.models import RECOMMENDED

    trusted_def = await _offered_tool(_trusted_args(), SHADOWED_TOOL)
    rogue_def = await _offered_tool(_rogue_args(), SHADOWED_TOOL)

    results: list[ShadowResult] = []

    for binding, rationale, trusted_id, rogue_id in (
        (
            "self-reported name",
            "pins keyed by serverInfo.name, which the spec says not to rely on",
            from_self_reported_name(TRUSTED_NAME),
            from_self_reported_name(TRUSTED_NAME),
        ),
        (
            "host launch command",
            "pins keyed by what the host configured; the server cannot alter it",
            from_stdio_command(sys.executable, _trusted_args()),
            from_stdio_command(sys.executable, _rogue_args()),
        ),
    ):
        results.append(
            _evaluate(
                binding, rationale, RECOMMENDED, trusted_id, rogue_id,
                trusted_def, rogue_def,
            )
        )
    return tuple(results)


def _evaluate(
    binding: str,
    rationale: str,
    policy: PinPolicy,
    trusted_id: ServerIdentity,
    rogue_id: ServerIdentity,
    trusted_def: dict,
    rogue_def: dict,
) -> ShadowResult:
    store = PinStore(policy)
    # The operator approved the tool as offered by the LEGITIMATE server. That
    # is the only approval that ever happened in this scenario.
    store.approve(trusted_id, corpus.by_name(SHADOWED_TOOL), approved_by="operator")

    return ShadowResult(
        binding=binding,
        rationale=rationale,
        trusted_verdict=store.check(trusted_id, trusted_def).verdict,
        rogue_verdict=store.check(rogue_id, rogue_def).verdict,
    )


def format_table(results: tuple[ShadowResult, ...]) -> str:
    lines = [
        f"{'pin bound to':<22} {'trusted server':>16} {'rogue server':>16} {'sound':>7}",
        "-" * 66,
    ]
    for r in results:
        lines.append(
            f"{r.binding:<22} {r.trusted_verdict.value:>16} "
            f"{r.rogue_verdict.value:>16} {('yes' if r.sound else 'NO'):>7}"
        )
    return "\n".join(lines)
