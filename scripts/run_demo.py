"""Run all three measurements and print the capture SAMPLE_RUN.md carries.

    python scripts/run_demo.py            all three legs
    python scripts/run_demo.py --matrix   the policy grid only (offline)

The matrix leg is pure arithmetic over the corpus and needs nothing but the
standard library. The exposure and shadow legs launch real MCP servers as
subprocesses and speak the protocol to them over stdio, so they need the `mcp`
SDK installed; they are skipped with a stated reason if it is not.

Output is byte-identical between runs, on purpose. No timestamps, no durations,
no process ids, no sampling. `SAMPLE_RUN.md` holds this text verbatim, and a
capture a reader cannot reproduce exactly is a screenshot.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pin import matrix  # noqa: E402
from pin.models import INTUITIVE, RECOMMENDED  # noqa: E402
from pin.mutations import ADVERSARIAL, BENIGN, MUTATIONS  # noqa: E402


def rule(title: str) -> str:
    return f"\n{'=' * 78}\n{title}\n{'=' * 78}"


def leg_matrix() -> None:
    print(rule("LEG 1: WHICH BYTES YOU HASH DECIDES WHAT YOU CAN SEE"))
    print(
        f"\n{len(MUTATIONS)} changes to tool definitions "
        f"({len(ADVERSARIAL)} adversarial, {len(BENIGN)} benign) against "
        f"{len(matrix.POLICY_GRID)} pinning policies.\n"
    )
    results = matrix.run()
    print(matrix.format_grid(results))
    print()
    print(matrix.format_cross(results))
    print()

    intuitive = next(a for a in results if a.policy == INTUITIVE)
    recommended = next(a for a in results if a.policy == RECOMMENDED)
    print(
        f"The policy an approval dialog implies ({INTUITIVE.label}) detects "
        f"{intuitive.detected} of {len(ADVERSARIAL)}."
    )
    print(
        f"The widest policy ({RECOMMENDED.label}) detects "
        f"{recommended.detected} of {len(ADVERSARIAL)}."
    )
    missed = matrix.universally_missed(results)
    print(f"Missed by all {len(matrix.POLICY_GRID)} policies: {', '.join(missed)}.")
    print()
    print("What each policy missed, and where each one fired wrongly:")
    print()
    print(matrix.format_detail(results))


async def leg_exposure() -> None:
    from pin import exposure

    print(rule("LEG 2: THE SERVER CHOOSES HOW LONG THE PIN STAYS UNCHECKED"))
    print(
        "\nA server that rug-pulls after the client has trusted it once. "
        f"12 calls, 30s apart on an injected clock, server ttlMs = 300000.\n"
        f"The SDK clamps any inbound hint to {exposure.SDK_MAX_TTL_MS} ms "
        f"({exposure.SDK_MAX_TTL_MS // 3_600_000} hours).\n"
    )
    results = []
    for policy in exposure.POLICIES:
        results.append(await exposure.run_arm(policy, RECOMMENDED))
    print(exposure.format_table(tuple(results)))
    print()
    for policy in exposure.POLICIES:
        print(f"  {policy.key:<14} {policy.rationale}")


async def leg_shadow() -> None:
    from pin import shadow

    print(rule("LEG 3: A PIN IS A STATEMENT ABOUT A TOOL OFFERED BY SOMEONE"))
    print(
        "\nTwo servers. The second self-reports the first one's name and "
        "offers a\nBYTE-IDENTICAL definition for a tool the operator approved "
        "on the first.\nOnly the pin's key differs between the two arms.\n"
    )
    results = await shadow.run()
    print(shadow.format_table(results))
    print()
    for result in results:
        print(f"  {result.binding:<22} {result.rationale}")
    print()
    leaked = [r for r in results if r.rogue_was_allowed]
    if leaked:
        print(
            "The name-bound arm returns MATCH for a server the operator never "
            "approved.\nEvery byte a fingerprint could examine is correct, so "
            "no field set and no\ncanonicalization changes this answer."
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--matrix", action="store_true", help="run the offline leg only"
    )
    args = parser.parse_args(argv)

    leg_matrix()
    if args.matrix:
        return 0

    try:
        import mcp  # noqa: F401
    except ImportError:
        print(rule("LEGS 2 AND 3: SKIPPED"))
        print(
            "\nThe `mcp` SDK is not installed, so no server can be launched "
            "and no\nprotocol traffic can be measured. Install it with "
            "`pip install -r requirements.txt`.\nLeg 1 above is unaffected: it "
            "imports nothing outside the standard library."
        )
        return 0

    asyncio.run(leg_exposure())
    asyncio.run(leg_shadow())
    return 0


if __name__ == "__main__":
    sys.exit(main())
