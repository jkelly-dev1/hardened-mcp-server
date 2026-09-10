"""The published grid, and the properties that make it readable as a grid."""

from __future__ import annotations

import pytest

from pin import corpus, matrix
from pin.models import (
    INTUITIVE,
    POLICY_GRID,
    RECOMMENDED,
    Canonicalization,
    FieldSet,
    PinPolicy,
    Verdict,
)
from pin.mutations import ADVERSARIAL, BENIGN, MUTATIONS
from pin.store import PinStore


@pytest.fixture(scope="module")
def results() -> tuple[matrix.ArmResult, ...]:
    return matrix.run()


def arm(results: tuple[matrix.ArmResult, ...], policy: PinPolicy) -> matrix.ArmResult:
    return next(a for a in results if a.policy == policy)


def test_the_grid_covers_every_policy_and_every_mutation(results) -> None:
    assert len(results) == len(POLICY_GRID) == 20
    assert all(len(a.cells) == len(MUTATIONS) for a in results)
    assert len(ADVERSARIAL) == 8
    assert len(BENIGN) == 3


def test_pinning_the_reviewed_surface_detects_one_of_eight(results) -> None:
    """The headline. What an approval dialog shows is not what an attack uses."""
    assert arm(results, INTUITIVE).detected == 1


def test_pinning_the_wire_with_safe_normalization_detects_seven_of_eight(results) -> None:
    assert arm(results, RECOMMENDED).detected == 7


def test_detection_is_monotone_in_the_field_set(results) -> None:
    """Each field set is a superset of the last, so detection cannot fall.

    A non-monotone cell is a bug in the field selector, not a finding, and
    without this assertion it would read as one.
    """
    order = (FieldSet.NAME, FieldSet.REVIEWED, FieldSet.DECLARED, FieldSet.WIRE)
    for canonical in Canonicalization:
        scores = [arm(results, PinPolicy(f, canonical)).detected for f in order]
        assert scores == sorted(scores), f"{canonical.value}: {scores}"


def test_the_two_safe_normalizations_cost_no_detection(results) -> None:
    """STRUCTURAL and SEMANTIC remove false alarms and take nothing away.

    This is half of the module's thesis. The other half is the next test.
    """
    for fields in FieldSet:
        raw = arm(results, PinPolicy(fields, Canonicalization.RAW))
        structural = arm(results, PinPolicy(fields, Canonicalization.STRUCTURAL))
        semantic = arm(results, PinPolicy(fields, Canonicalization.SEMANTIC))
        assert structural.detected == raw.detected
        assert semantic.detected == raw.detected
        assert structural.false_alarms <= raw.false_alarms
        assert semantic.false_alarms <= structural.false_alarms


def test_text_folding_trades_one_detection_for_one_false_alarm(results) -> None:
    """The other half. Folding is not a stronger normalization, it is a trade.

    Mutation-checked: removing the invisible-character stripping from
    `fold_text` makes the exchange stop being one-for-one and turns this red.
    """
    plain = arm(results, PinPolicy(FieldSet.WIRE, Canonicalization.SEMANTIC))
    folded = arm(results, PinPolicy(FieldSet.WIRE, Canonicalization.SEMANTIC_FOLDED))
    lost = set(folded.missed_keys()) - set(plain.missed_keys())
    gained = set(plain.false_alarm_keys()) - set(folded.false_alarm_keys())
    assert lost == {"trojan_source"}
    assert gained == {"whitespace_only"}


def test_one_change_is_missed_by_every_policy(results) -> None:
    """The ceiling, and the reason it is a property of the technique.

    If this ever returns empty, either the corpus lost its unpinnable case or
    something started resolving absolute references; both change what the
    README may claim.
    """
    assert matrix.universally_missed(results) == ("remote_schema_edit",)
    assert max(a.detected for a in results) == 7


def test_the_header_mirroring_change_is_invisible_to_the_reviewed_surface(results) -> None:
    """Named on its own because it is the case the project is built around."""
    assert "header_exfil" in arm(results, INTUITIVE).missed_keys()
    assert "header_exfil" not in arm(results, RECOMMENDED).missed_keys()


def test_the_reviewed_surface_misses_six_changes_that_the_wire_catches(results) -> None:
    """The sentence under the grid in README.md, derived rather than typed.

    `reviewed/text_folded` misses seven of eight and `wire/semantic` misses
    one, so the difference is six. It is six and not five because
    `trojan_source` is in it: that change is in the description a reviewer IS
    shown, and folding deletes exactly the characters it adds, while the
    other five are in fields the reviewer never sees.
    """
    intuitive = arm(results, INTUITIVE)
    recommended = arm(results, RECOMMENDED)
    assert intuitive.missed == 7
    assert set(intuitive.missed_keys()) - set(recommended.missed_keys()) == {
        "header_exfil",
        "schema_widening",
        "annotation_flip",
        "display_swap",
        "unknown_field_plant",
        "trojan_source",
    }


def test_swapping_a_local_defs_for_an_external_ref_is_caught_by_ten_of_twenty() -> None:
    """The figure in `_a5_remote_schema_edit`'s docstring, derived.

    Replacing search_kb's `$defs` entry with an external `$ref` is a plain
    byte change inside `inputSchema`, so every policy whose field set reaches
    the schema fires: all five declared/* and all five wire/*. The ten that
    hash only the name or the reviewed text stay silent.
    """
    original = corpus.by_name("search_kb")
    swapped = corpus.by_name("search_kb")
    schema = swapped["inputSchema"]
    del schema["$defs"]
    for prop in ("published", "updated"):
        schema["properties"][prop] = {
            "$ref": "https://schemas.example.net/support/date-range.json"
        }

    caught: set[str] = set()
    for policy in POLICY_GRID:
        store = PinStore(policy)
        store.approve(matrix.SERVER, original, approved_by="operator")
        if store.check(matrix.SERVER, swapped).verdict is Verdict.CHANGED:
            caught.add(policy.label)
    assert len(caught) == 10
    assert caught == {
        p.label for p in POLICY_GRID if p.fields in (FieldSet.DECLARED, FieldSet.WIRE)
    }


def test_only_the_wire_field_set_sees_a_planted_unknown_key(results) -> None:
    for canonical in Canonicalization:
        declared = arm(results, PinPolicy(FieldSet.DECLARED, canonical))
        wire = arm(results, PinPolicy(FieldSet.WIRE, canonical))
        assert "unknown_field_plant" in declared.missed_keys()
        assert "unknown_field_plant" not in wire.missed_keys()


def test_the_grid_renders_without_losing_a_column(results) -> None:
    rendered = matrix.format_cross(results)
    for policy in POLICY_GRID:
        assert policy.label in rendered

    # Read the legend row and the policy rows as marker sequences. Counting
    # substrings would undercount the last column, which `rstrip` leaves
    # without a trailing space.
    lines = rendered.splitlines()
    legend = lines[-1].split("|", 1)[1].split()
    assert legend == [
        "A" if m.kind == "adversarial" else "B" for m in MUTATIONS
    ]

    for arm_line in lines:
        if arm_line.startswith(RECOMMENDED.label):
            marks = arm_line.split("|", 1)[1].split()
            assert len(marks) == len(MUTATIONS)
            assert set(marks) <= {"X", "."}
            break
    else:  # pragma: no cover - only reachable if the renderer drops a row
        pytest.fail(f"{RECOMMENDED.label} row missing from the grid")
