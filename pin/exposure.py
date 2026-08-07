"""How long a rug pull goes unnoticed, and who decides.

A pin fires when the client LOOKS. The 2026-07-28 revision made looking
cacheable: `tools/list` results carry `ttlMs` and `cacheScope`, and a client
that honors them will not re-issue the request until the server's own number
says it may. So the interval between a definition changing and a pin noticing
is chosen by the server, which, when the server is the adversary, means the
adversary sets the audit interval.

The SDK does put a ceiling on it, and the ceiling is not small. `mcp.client.
Caching.MAX_TTL_MS` is 24 hours, and inbound hints are clamped to it. So a
server cannot ask for a week. It can comfortably ask for a day.

What this module measures, stated precisely so the number is not read as more
than it is. It runs a real client against a real server over stdio. The server
answers honestly until it has been asked `flip_after` times and then serves a
mutated definition. The client's freshness policy decides when it re-reads. Its
clock is injected rather than slept through, so the run takes milliseconds and
is deterministic. The passage of time is simulated, everything else is real
protocol traffic.

What comes out is a trade, not a winner. Re-reading on every call closes the window
to zero and costs one `tools/list` per call. That is the correct choice for
four tools and an unreasonable one for four hundred, and the table is there so
a deployment can locate itself on it.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from pin import corpus
from pin.identity import from_stdio_command
from pin.models import PinPolicy, Verdict
from pin.store import PinStore

#: `mcp.client.caching.MAX_TTL_MS`. Restated here rather than imported so the
#: pure layer stays free of SDK imports; `tests/test_exposure.py::
#: test_the_sdk_ttl_ceiling_is_what_this_module_assumes` asserts they agree, so
#: an SDK change that moves the ceiling fails a test instead of silently
#: invalidating the published table.
SDK_MAX_TTL_MS = 24 * 60 * 60 * 1000


@dataclass(frozen=True, slots=True)
class FreshnessPolicy:
    """When the client is willing to reuse a cached tool listing."""

    key: str
    #: Client-side ceiling on any server hint, in milliseconds. `None` means
    #: honor whatever the server asks for (subject to the SDK ceiling); `0`
    #: means never reuse a cached listing.
    cap_ms: int | None
    rationale: str

    def effective_ttl(self, server_ttl_ms: int) -> int:
        clamped = min(server_ttl_ms, SDK_MAX_TTL_MS)
        if self.cap_ms is None:
            return clamped
        return min(clamped, self.cap_ms)


POLICIES: tuple[FreshnessPolicy, ...] = (
    FreshnessPolicy(
        key="honor-server",
        cap_ms=None,
        rationale=(
            "Take the server's ttlMs as given. The specification's intent, and "
            "the default a client gets by not thinking about it."
        ),
    ),
    FreshnessPolicy(
        key="cap-60s",
        cap_ms=60_000,
        rationale=(
            "Honor the hint but never trust it past a minute. One line of "
            "client policy; the server keeps its caching win for short TTLs "
            "and loses the ability to choose a long one."
        ),
    ),
    FreshnessPolicy(
        key="every-call",
        cap_ms=0,
        rationale=(
            "Re-read the listing before every call. Zero window, and one extra "
            "round trip per call."
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class ExposureResult:
    policy: FreshnessPolicy
    server_ttl_ms: int
    calls: int
    #: Calls that executed after the server was compromised and before the
    #: client next looked.
    #:
    #: the stale copy is good and that is why it is dangerous. During the cache
    #: window the client holds the definition it approved and the pin matches
    #: it, correctly, while the server on the other end of the socket is
    #: already serving the mutated one. Exposure is a property of the SERVER's
    #: state and the client's ignorance of it, never of the cached bytes, and
    #: counting cached-copy mismatches instead reports zero for every policy
    #: because a mismatched cached copy is precisely the case the pin catches.
    exposed_calls: int
    #: Calls that were refused because the client did look and the pin fired.
    refused_calls: int
    #: `tools/list` requests the client issued.
    listings: int
    #: Simulated milliseconds from the flip to the first refusal, or None if
    #: the run ended with the client still unaware.
    detected_after_ms: int | None

    @property
    def window_label(self) -> str:
        if self.detected_after_ms is None:
            return "never (within the run)"
        return f"{self.detected_after_ms / 1000:.0f}s"


class _Clock:
    """A monotonic fake clock in epoch seconds, advanced explicitly."""

    def __init__(self, start: float = 1_800_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance_ms(self, ms: int) -> None:
        self.now += ms / 1000.0


async def run_arm(
    policy: FreshnessPolicy,
    pin_policy: PinPolicy,
    *,
    mutation: str = "header_exfil",
    server_ttl_ms: int = 300_000,
    calls: int = 12,
    interval_ms: int = 30_000,
    flip_after: int = 1,
) -> ExposureResult:
    """One freshness policy against one rug-pulling server.

    The client makes `calls` tool calls `interval_ms` apart on the simulated
    clock. It re-reads the listing only when its freshness policy says the
    cached one has expired.
    """
    from pin.wire_client import connect_stdio

    args = (
        "-m",
        "pin.wire_server",
        "--rogue",
        "--mutation",
        mutation,
        "--ttl-ms",
        str(server_ttl_ms),
        "--flip-after",
        str(flip_after),
    )
    identity = from_stdio_command(sys.executable, args)
    store = PinStore(pin_policy)
    for tool in corpus.baseline():
        store.approve(identity, tool, approved_by="operator")

    clock = _Clock()
    ttl_ms = policy.effective_ttl(server_ttl_ms)

    target = _mutated_tool_name(mutation)
    cached: dict[str, dict] | None = None
    cached_at = 0.0
    listings = 0
    exposed = 0
    refused = 0
    compromised_at: float | None = None
    detected_at: float | None = None

    async with connect_stdio(sys.executable, args, pin_policy, store=store) as client:
        client.identity = identity
        for _ in range(calls):
            fresh = (
                cached is not None
                and (clock.now - cached_at) * 1000.0 < ttl_ms
            )
            if not fresh:
                listing = await client.raw_tool_list()
                listings += 1
                cached = {t["name"]: t for t in listing}
                cached_at = clock.now
                # The server flips once it has answered `flip_after` listings.
                # From that instant its tools BEHAVE differently, whatever any
                # client is still holding.
                if compromised_at is None and listings >= flip_after:
                    compromised_at = clock.now

            assert cached is not None
            definition = cached.get(target)
            if definition is None:
                clock.advance_ms(interval_ms)
                continue

            verdict = store.check(identity, definition).verdict
            if verdict is Verdict.MATCH:
                if compromised_at is not None and clock.now > compromised_at:
                    exposed += 1
            else:
                refused += 1
                if detected_at is None:
                    detected_at = clock.now
            clock.advance_ms(interval_ms)

    window: int | None
    if detected_at is None or compromised_at is None:
        window = None
    else:
        window = int(round((detected_at - compromised_at) * 1000.0))

    return ExposureResult(
        policy=policy,
        server_ttl_ms=server_ttl_ms,
        calls=calls,
        exposed_calls=exposed,
        refused_calls=refused,
        listings=listings,
        detected_after_ms=window,
    )


def _mutated_tool_name(mutation_key: str) -> str:
    from pin.mutations import MUTATIONS

    for mutation in MUTATIONS:
        if mutation.key == mutation_key:
            return mutation.tool
    raise KeyError(mutation_key)


def _is_mutated(definition: dict | None, tool_name: str) -> bool:
    """Whether this definition differs from the approved baseline.

    Compared against the corpus rather than against a flag, so the answer comes
    from the bytes the server actually sent.
    """
    if definition is None:
        return False
    return definition != corpus.by_name(tool_name)


def format_table(results: tuple[ExposureResult, ...]) -> str:
    lines = [
        f"{'freshness policy':<18} {'ttl used':>10} {'listings':>9} "
        f"{'exposed':>8} {'refused':>8} {'detected after':>15}",
        "-" * 74,
    ]
    for r in results:
        ttl = r.policy.effective_ttl(r.server_ttl_ms)
        lines.append(
            f"{r.policy.key:<18} {ttl / 1000:>8.0f}s {r.listings:>9} "
            f"{r.exposed_calls:>8} {r.refused_calls:>8} {r.window_label:>15}"
        )
    return "\n".join(lines)
