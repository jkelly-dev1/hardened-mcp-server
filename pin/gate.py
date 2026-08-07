"""The offline gate: every published claim, re-derived, with no network.

Run it with `python -m pin.gate`. It exits non-zero if any claim in README.md
stops holding. Nothing here imports the SDK, opens a socket, or launches a
process, so it is the same nine checks in CI, in a clean virtualenv, and on a
machine with no Python packages installed beyond the standard library.

Why a gate and not just the test suite. The tests check behavior; this checks
the numbers that appear in the prose. A refactor that leaves every test green
while moving `wire/semantic` from 7/8 to 6/8 has silently made README.md wrong,
and the README is the artifact a reader judges. These are the assertions whose
failure means "go and edit the page", which is a different job from "go and fix
the code" and deserves its own exit code.
"""

from __future__ import annotations

import sys

from pin import matrix
from pin.canonical import fold_text
from pin.models import (
    INTUITIVE,
    RECOMMENDED,
    Canonicalization,
    FieldSet,
    PinPolicy,
)
from pin.mutations import ADVERSARIAL, BENIGN

Check = tuple[str, bool, str]


def _arm(results: tuple[matrix.ArmResult, ...], policy: PinPolicy) -> matrix.ArmResult:
    for arm in results:
        if arm.policy == policy:
            return arm
    raise KeyError(policy.label)


def checks() -> list[Check]:
    results = matrix.run()
    out: list[Check] = []

    intuitive = _arm(results, INTUITIVE)
    out.append(
        (
            "the intuitive policy detects 1 of 8",
            intuitive.detected == 1 and len(ADVERSARIAL) == 8,
            f"{INTUITIVE.label} detected {intuitive.detected}/{len(ADVERSARIAL)}",
        )
    )

    recommended = _arm(results, RECOMMENDED)
    out.append(
        (
            "the recommended policy detects 7 of 8",
            recommended.detected == 7,
            f"{RECOMMENDED.label} detected {recommended.detected}/{len(ADVERSARIAL)}",
        )
    )

    universally = matrix.universally_missed(results)
    out.append(
        (
            "exactly one change is missed by every policy",
            universally == ("remote_schema_edit",),
            f"missed by all: {universally or '(none)'}",
        )
    )

    ceiling = max(arm.detected for arm in results)
    out.append(
        (
            "no policy exceeds the 7 of 8 ceiling",
            ceiling == 7,
            f"best detection on the grid is {ceiling}/{len(ADVERSARIAL)}",
        )
    )

    # The trade, stated as an exchange rather than as a preference.
    folded = _arm(results, PinPolicy(FieldSet.WIRE, Canonicalization.SEMANTIC_FOLDED))
    unfolded = _arm(results, PinPolicy(FieldSet.WIRE, Canonicalization.SEMANTIC))
    lost = set(folded.missed_keys()) - set(unfolded.missed_keys())
    gained = set(unfolded.false_alarm_keys()) - set(folded.false_alarm_keys())
    out.append(
        (
            "text folding costs exactly trojan_source",
            lost == {"trojan_source"},
            f"detections lost to folding: {sorted(lost) or '(none)'}",
        )
    )
    out.append(
        (
            "text folding buys exactly whitespace_only",
            gained == {"whitespace_only"},
            f"false alarms removed by folding: {sorted(gained) or '(none)'}",
        )
    )

    # The two safe normalizations cost nothing.
    raw = _arm(results, PinPolicy(FieldSet.WIRE, Canonicalization.RAW))
    out.append(
        (
            "structural and semantic normalization cost no detection",
            unfolded.detected == raw.detected
            and unfolded.false_alarms < raw.false_alarms,
            f"wire/raw {raw.detected}/{raw.false_alarms} vs "
            f"wire/semantic {unfolded.detected}/{unfolded.false_alarms} "
            f"(detected/false alarms)",
        )
    )

    # Detection may only rise as the field set widens.
    order = (FieldSet.NAME, FieldSet.REVIEWED, FieldSet.DECLARED, FieldSet.WIRE)
    monotone = True
    for canonical in Canonicalization:
        scores = [
            _arm(results, PinPolicy(fields, canonical)).detected for fields in order
        ]
        if scores != sorted(scores):
            monotone = False
    out.append(
        (
            "detection is monotone in the field set",
            monotone,
            "widening the field set never lowers detection",
        )
    )

    # NFKC is not confusable folding. Both halves, because either alone is a
    # half-truth that leads a reader to the opposite conclusion.
    out.append(
        (
            "NFKC folds compatibility forms but not Cyrillic lookalikes",
            # U+FF41 fullwidth a (a compatibility form, folded) and
            # U+0430 Cyrillic a (a distinct letter, NOT folded).
            fold_text("\uff41") == "a" and fold_text("\u0430") != "a",
            "fullwidth a -> a, Cyrillic a unchanged",
        )
    )

    assert len(BENIGN) == 3, "the benign count is quoted in README.md"
    return out


def main() -> int:
    results = checks()
    width = max(len(name) for name, _, _ in results)
    failed = 0
    for name, ok, detail in results:
        mark = "PASS" if ok else "FAIL"
        if not ok:
            failed += 1
        print(f"[{mark}] {name:<{width}}  {detail}")
    print()
    print(f"{len(results) - failed}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
