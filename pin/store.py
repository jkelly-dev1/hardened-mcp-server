"""The pin registry: what was approved, by whom, and whether it still holds.

The state machine is three states and the middle one is the whole design.

    unpinned  --approve()-->  pinned  --definition moves-->  quarantined
                                 ^                                |
                                 +---------- approve() -----------+

A quarantined tool is NOT blocked and NOT allowed. It is a tool whose approval
on file no longer describes what is being offered, which is a statement about
the RECORD and not about the tool. Collapsing that into "blocked" would claim
the store detected an attack; collapsing it into "allowed with a warning" would
make the pin decorative. Both collapses are common and both are wrong.

Trust on first use is recorded as a decision, not performed as a default.
`observe()` never creates a pin. Something has to call `approve()`, and the
approver is stored alongside the digest. A store that pins whatever it sees the
first time has an approval step that cannot say no, and every number this
repository produces about detection would then be measured against a control
that was never armed.

What pinning proves, and the sentence is load bearing: it proves UNCHANGED. It
does not prove SAFE. A tool whose description carried a planted instruction at
first approval is pinned faithfully, forever, with that instruction intact. See
README.md section 6; `pin/scan.py` is the separate, weaker control that looks
at content, and it is separate because content inspection has a false-negative
rate and integrity checking does not.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pin.fingerprint import describe_change, fingerprint
from pin.identity import ServerIdentity
from pin.models import CheckResult, PinPolicy, Verdict


@dataclass(frozen=True, slots=True)
class PinEntry:
    """One approved tool definition, kept whole rather than as a hash alone.

    `definition` is the full raw object, not just its digest. Keeping it costs
    a few kilobytes and buys the only thing that makes a re-approval prompt
    actionable: a diff. A store holding digests can say "this changed" and
    nothing else, and an operator who cannot see what changed approves it.
    """

    server: str
    tool: str
    digest: str
    policy: PinPolicy
    definition: dict[str, Any]
    approved_by: str

    #: Free-text note from whoever approved it. Not interpreted.
    note: str = ""


class PinStore:
    """In-memory pin registry for one host.

    Deliberately not persistent. Persistence is a deployment concern and would
    add a file format, a schema version and a migration path to a repository
    whose subject is which bytes get hashed. `scripts/run_matrix.py` builds a
    fresh store per arm, which is also what keeps the arms independent.
    """

    def __init__(self, policy: PinPolicy) -> None:
        self.policy = policy
        self._entries: dict[tuple[str, str], PinEntry] = {}
        self._quarantined: dict[tuple[str, str], CheckResult] = {}

    # ------------------------------------------------------------------ #
    # recording decisions
    # ------------------------------------------------------------------ #

    def approve(
        self,
        identity: ServerIdentity,
        definition: dict[str, Any],
        *,
        approved_by: str,
        note: str = "",
    ) -> PinEntry:
        """Record a human decision that this definition, from this server, is
        acceptable. Overwrites any prior pin for the same key, which is what
        re-approval after a quarantine means.
        """
        name = definition.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("cannot pin a tool with no name")
        entry = PinEntry(
            server=identity.key,
            tool=name,
            digest=fingerprint(definition, self.policy).digest,
            policy=self.policy,
            definition=dict(definition),
            approved_by=approved_by,
            note=note,
        )
        self._entries[(identity.key, name)] = entry
        self._quarantined.pop((identity.key, name), None)
        return entry

    # ------------------------------------------------------------------ #
    # checking
    # ------------------------------------------------------------------ #

    def check(
        self, identity: ServerIdentity, definition: dict[str, Any]
    ) -> CheckResult:
        """Compare an offered definition against the pin on file.

        Pure: it records nothing and changes nothing. `observe()` is the
        stateful wrapper. Splitting them means a test can ask what the store
        WOULD say without moving the store into the state it is asking about.
        """
        name = definition.get("name")
        if not isinstance(name, str) or not name:
            return CheckResult(
                tool="", verdict=Verdict.UNPINNED, policy=self.policy
            )

        entry = self._entries.get((identity.key, name))
        if entry is None:
            # A pin under a DIFFERENT identity for the same tool name is the
            # shadowing case. The store reports it as unpinned and not as a
            # mismatch. "Some other server's approval does not apply here" is
            # the accurate statement; a mismatch would imply this server's
            # own definition moved.
            return CheckResult(
                tool=name,
                verdict=Verdict.UNPINNED,
                policy=self.policy,
                observed_digest=fingerprint(definition, self.policy).digest,
            )

        observed = fingerprint(definition, self.policy)
        if observed.digest == entry.digest:
            return CheckResult(
                tool=name,
                verdict=Verdict.MATCH,
                policy=self.policy,
                pinned_digest=entry.digest,
                observed_digest=observed.digest,
            )

        return CheckResult(
            tool=name,
            verdict=Verdict.CHANGED,
            policy=self.policy,
            pinned_digest=entry.digest,
            observed_digest=observed.digest,
            diff=describe_change(entry.definition, definition),
        )

    def observe(
        self, identity: ServerIdentity, definition: dict[str, Any]
    ) -> CheckResult:
        """Check, and move the tool to quarantine if the definition moved.

        Never creates a pin. See the module docstring.
        """
        result = self.check(identity, definition)
        if result.verdict is Verdict.CHANGED:
            self._quarantined[(identity.key, result.tool)] = result
        return result

    # ------------------------------------------------------------------ #
    # inspection
    # ------------------------------------------------------------------ #

    def entry(self, identity: ServerIdentity, tool: str) -> PinEntry | None:
        return self._entries.get((identity.key, tool))

    def quarantined(self) -> dict[tuple[str, str], CheckResult]:
        return dict(self._quarantined)

    def __len__(self) -> int:
        return len(self._entries)


@dataclass
class ApprovalLog:
    """An append-only record of every verdict, for the exposure measurement.

    Separate from the store because the store answers "may this call proceed"
    and this answers "how long was the answer wrong". `pin/exposure.py` reads
    it to count calls that executed against a definition nobody had re-checked.
    """

    entries: list[tuple[int, str, Verdict]] = field(default_factory=list)

    def record(self, tick: int, tool: str, verdict: Verdict) -> None:
        self.entries.append((tick, tool, verdict))

    def count(self, verdict: Verdict) -> int:
        return sum(1 for _, _, seen in self.entries if seen is verdict)
