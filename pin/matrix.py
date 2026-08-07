"""The headline measurement: every pinning policy against every change.

One arm per policy. Each arm approves the baseline definition of the tool a
mutation targets, applies the mutation, and asks the store whether the pin
still holds. Nothing here is stochastic and nothing here calls a model, so the
whole grid is reproducible offline and byte-identical between runs, which is
what lets `SAMPLE_RUN.md` carry it verbatim.

What the two halves mean, because one number would hide it:

  detection    fraction of ADVERSARIAL changes the policy noticed. A policy
               scoring 1.000 here has told you nothing on its own; pinning
               the raw bytes with no normalization scores 1.000 and alarms on
               a key reorder.

  false alarm  fraction of BENIGN changes the policy also noticed. This is
               the number that decides whether the control survives contact
               with an operator, the number pinning write-ups almost never
               publish.

A policy is only interesting where both are good, and the result is that the
two axes contribute to them independently: widening the FIELD SET only ever
raises detection, and the choice of CANONICALIZATION is what moves false
alarms: with one exception, recorded below.
"""

from __future__ import annotations

from dataclasses import dataclass

from pin import corpus
from pin.identity import from_stdio_command
from pin.models import POLICY_GRID, PinPolicy, Verdict
from pin.mutations import ADVERSARIAL, BENIGN, MUTATIONS, Mutation
from pin.store import PinStore

#: The server every arm pins against. Identity is held constant so the grid
#: measures the policy and nothing else; pin/shadow.py is where identity varies.
SERVER = from_stdio_command("python", ("-m", "pin.wire_server", "--honest"))


@dataclass(frozen=True, slots=True)
class Cell:
    """One policy's verdict on one mutation."""

    policy: PinPolicy
    mutation: Mutation
    verdict: Verdict

    @property
    def noticed(self) -> bool:
        return self.verdict is Verdict.CHANGED

    @property
    def correct(self) -> bool:
        """Detected an attack, or stayed quiet on a benign change."""
        if self.mutation.kind == "adversarial":
            return self.noticed
        return not self.noticed


@dataclass(frozen=True, slots=True)
class ArmResult:
    policy: PinPolicy
    cells: tuple[Cell, ...]

    @property
    def detected(self) -> int:
        return sum(1 for c in self.cells if c.mutation.kind == "adversarial" and c.noticed)

    @property
    def missed(self) -> int:
        return len(ADVERSARIAL) - self.detected

    @property
    def false_alarms(self) -> int:
        return sum(1 for c in self.cells if c.mutation.kind == "benign" and c.noticed)

    @property
    def detection_rate(self) -> float:
        return self.detected / len(ADVERSARIAL)

    @property
    def false_alarm_rate(self) -> float:
        return self.false_alarms / len(BENIGN)

    def missed_keys(self) -> tuple[str, ...]:
        return tuple(
            c.mutation.key
            for c in self.cells
            if c.mutation.kind == "adversarial" and not c.noticed
        )

    def false_alarm_keys(self) -> tuple[str, ...]:
        return tuple(
            c.mutation.key
            for c in self.cells
            if c.mutation.kind == "benign" and c.noticed
        )


def run_arm(policy: PinPolicy) -> ArmResult:
    """Evaluate one policy against the full mutation set."""
    cells: list[Cell] = []
    for mutation in MUTATIONS:
        # A fresh store per mutation. Sharing one would let an earlier
        # quarantine change the answer to a later question, and every cell in
        # this grid is meant to be an independent trial.
        store = PinStore(policy)
        original = corpus.by_name(mutation.tool)
        store.approve(SERVER, original, approved_by="operator")
        changed = mutation(original)
        result = store.observe(SERVER, changed)
        cells.append(Cell(policy=policy, mutation=mutation, verdict=result.verdict))
    return ArmResult(policy=policy, cells=tuple(cells))


def run() -> tuple[ArmResult, ...]:
    """Every policy in the grid."""
    return tuple(run_arm(policy) for policy in POLICY_GRID)


def universally_missed(results: tuple[ArmResult, ...]) -> tuple[str, ...]:
    """Adversarial changes no policy in the grid detected.

    Reported on its own line rather than left inside the rates. A case every
    arm misses adds nothing to the comparison BETWEEN policies while lowering
    every detection number by the same amount, so a reader who does not know it
    is there will read the ceiling as a property of the best policy instead of
    a property of the technique. It is the opposite of a caveat: it is the
    result that says where pinning stops.
    """
    keys = [m.key for m in ADVERSARIAL]
    return tuple(
        key
        for key in keys
        if all(key in arm.missed_keys() for arm in results)
    )


def format_grid(results: tuple[ArmResult, ...]) -> str:
    """The detection/false-alarm table, one row per policy."""
    lines = [
        f"{'policy':<26} {'detected':>10} {'missed':>7} {'false alarms':>13}",
        "-" * 60,
    ]
    for arm in results:
        lines.append(
            f"{arm.policy.label:<26} "
            f"{arm.detected:>4}/{len(ADVERSARIAL):<5} "
            f"{arm.missed:>7} "
            f"{arm.false_alarms:>9}/{len(BENIGN)}"
        )
    return "\n".join(lines)


def format_detail(results: tuple[ArmResult, ...]) -> str:
    """Per-policy list of what was missed and what fired wrongly.

    Rates are a summary; these are the lines that let a reader check the
    summary rather than accept it.
    """
    lines: list[str] = []
    for arm in results:
        lines.append(arm.policy.label)
        missed = arm.missed_keys()
        alarms = arm.false_alarm_keys()
        lines.append(f"    missed       : {', '.join(missed) if missed else '(none)'}")
        lines.append(f"    false alarms : {', '.join(alarms) if alarms else '(none)'}")
    return "\n".join(lines)


def format_cross(results: tuple[ArmResult, ...]) -> str:
    """The full grid: policies down, mutations across.

    `.` means the pin stayed quiet, `X` means it fired. For an adversarial
    column `X` is the right answer; for a benign column `.` is.
    """
    header_keys = [m.key for m in MUTATIONS]
    width = max(len(k) for k in header_keys)
    lines: list[str] = []
    for depth in range(width):
        row = " " * 27
        for key in header_keys:
            padded = key.rjust(width)
            row += padded[depth] + " "
        lines.append(row.rstrip())
    lines.append(" " * 26 + "+" + "--" * len(header_keys))
    for arm in results:
        marks = "".join(
            ("X " if cell.noticed else ". ") for cell in arm.cells
        )
        lines.append(f"{arm.policy.label:<26}|{marks.rstrip()}")
    kinds = "".join(("A " if m.kind == "adversarial" else "B ") for m in MUTATIONS)
    lines.append(" " * 26 + "+" + "--" * len(header_keys))
    lines.append(f"{'A=adversarial B=benign':<26}|{kinds.rstrip()}")
    return "\n".join(lines)
