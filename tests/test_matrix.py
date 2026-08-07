"""The published grid, and the properties that make it readable as a grid."""

from __future__ import annotations

import pytest

from pin import matrix
from pin.models import (
    INTUITIVE,
    POLICY_GRID,
    RECOMMENDED,
    Canonicalization,
    FieldSet,
    PinPolicy,
)
from pin.mutations import ADVERSARIAL, BENIGN, MUTATIONS


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
