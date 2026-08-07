"""Legs 2 and 3, and the properties that make their tables trustworthy.

Both legs launch real servers, so both skip without the SDK. The assertions are
about SHAPE rather than exact counts wherever an exact count would just restate
the arithmetic: that shortening the freshness window strictly shrinks the
exposure and strictly costs more requests is the claim worth defending, and it
survives changing the call count or the interval.
"""

from __future__ import annotations

import sys

import pytest

from pin.models import RECOMMENDED, Verdict

pytest.importorskip("mcp", reason="the mcp SDK is not installed")
pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


# --------------------------------------------------------------------------- #
# leg 2
# --------------------------------------------------------------------------- #


async def test_a_shorter_freshness_window_trades_requests_for_exposure() -> None:
    """The whole table in one assertion, stated as a monotone trade.

    Exposure falls and request count rises as the client trusts the server's
    ttlMs less. Anything else means the arms are not measuring what the column
    headings say.
    """
    from pin import exposure

    results = [
        await exposure.run_arm(policy, RECOMMENDED) for policy in exposure.POLICIES
    ]
    exposed = [r.exposed_calls for r in results]
    listings = [r.listings for r in results]
    assert exposed == sorted(exposed, reverse=True)
    assert listings == sorted(listings)
    assert exposed[-1] == 0


async def test_honoring_the_server_hint_makes_the_server_choose_the_window() -> None:
    """The finding: the interval is the number the server sent.

    Mutation-checked: capping the TTL client-side inside `honor-server` makes
    the detection window stop matching the advertised hint and turns this red.
    """
    from pin import exposure

    honor = next(p for p in exposure.POLICIES if p.key == "honor-server")
    for advertised in (120_000, 300_000):
        result = await exposure.run_arm(
            honor, RECOMMENDED, server_ttl_ms=advertised, calls=20, interval_ms=30_000
        )
        assert result.detected_after_ms == advertised


async def test_the_client_cannot_be_asked_to_cache_beyond_the_sdk_ceiling() -> None:
    from pin import exposure

    honor = next(p for p in exposure.POLICIES if p.key == "honor-server")
    week = 7 * 24 * 60 * 60 * 1000
    assert honor.effective_ttl(week) == exposure.SDK_MAX_TTL_MS


async def test_re_reading_before_every_call_closes_the_window() -> None:
    from pin import exposure

    every = next(p for p in exposure.POLICIES if p.key == "every-call")
    result = await exposure.run_arm(every, RECOMMENDED)
    assert result.exposed_calls == 0
    assert result.listings == result.calls


# --------------------------------------------------------------------------- #
# leg 3
# --------------------------------------------------------------------------- #


async def test_a_pin_bound_to_the_self_reported_name_is_handed_to_an_imposter() -> None:
    """The failure the specification warns about, reproduced.

    The rogue server offers a byte-identical definition, so there is nothing
    for a fingerprint to catch. Any repair here has to change the KEY.
    """
    from pin import shadow

    results = await shadow.run()
    named = next(r for r in results if r.binding == "self-reported name")
    assert named.rogue_verdict is Verdict.MATCH
    assert named.rogue_was_allowed
    assert not named.sound


async def test_a_pin_bound_to_the_host_launch_command_refuses_the_imposter() -> None:
    from pin import shadow

    results = await shadow.run()
    anchored = next(r for r in results if r.binding == "host launch command")
    assert anchored.rogue_verdict is Verdict.UNPINNED
    assert anchored.trusted_verdict is Verdict.MATCH
    assert anchored.sound


async def test_both_arms_still_accept_the_server_that_was_actually_approved() -> None:
    """Refusing everything would stop the imposter and would not be a control."""
    from pin import shadow

    for result in await shadow.run():
        assert result.trusted_still_works, result.binding


async def test_the_imposter_serves_bytes_a_fingerprint_cannot_distinguish() -> None:
    """The premise of the leg, checked rather than assumed.

    If the two servers' definitions differed, the content hash would catch the
    rogue one and the leg would be reporting on the wrong variable. Serving a
    mutated definition from the trusted side is the specific way that happens,
    and it does not announce itself.
    """
    from pin import shadow

    trusted = await shadow._offered_tool(shadow._trusted_args(), shadow.SHADOWED_TOOL)
    rogue = await shadow._offered_tool(shadow._rogue_args(), shadow.SHADOWED_TOOL)
    assert trusted == rogue
    assert shadow._trusted_args() != shadow._rogue_args()


async def test_the_two_servers_are_separate_processes_reporting_one_name() -> None:
    import shlex

    from pin import shadow
    from pin.identity import from_stdio_command

    trusted = from_stdio_command(sys.executable, shadow._trusted_args())
    rogue = from_stdio_command(sys.executable, shadow._rogue_args())
    assert trusted.key != rogue.key
    assert shadow.TRUSTED_NAME in shlex.split(trusted.value)
    assert shadow.TRUSTED_NAME in shlex.split(rogue.value)
