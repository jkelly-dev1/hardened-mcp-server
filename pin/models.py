"""The typed vocabulary of tool-definition pinning.

The one distinction this project turns on is that "normalization" names two
different operations that behave in opposite ways, and implementations conflate
them because they share a word.

  STRUCTURAL normalization changes the ENCODING and leaves the MEANING alone.
             Sorting object keys, dropping insignificant JSON whitespace, and
             resolving a $ref to the schema it names are all in this family.
             Every one of them removes a false alarm and opens no bypass,
             because nothing an attacker can express survives the transform in
             a form the model would read differently.

  TEXT folding changes the CHARACTERS the model will actually read. NFKC,
             zero-width stripping and whitespace collapsing are in this family.
             Each removes a false alarm AND opens a bypass, because the
             transform exists to make two different strings compare equal,
             and "two different strings that compare equal" is the
             definition of a hash collision an attacker can steer.

A pin is a hash. Which of these you apply before hashing decides what the pin
can see, and the two families must not be chosen with one switch. Section 4 of
README.md carries the measurement; `PolicyGrid` below is what produces it.

The second distinction, the headline: the field a human reviews and the field
an attack uses are different fields. An approval dialog shows a name and a
description. The 2026-07-28 revision lets a tool carry `annotations`,
`outputSchema`, `icons`, `title`, and an `inputSchema` whose property-level
`x-mcp-header` annotation mirrors an argument value into an HTTP header that
every proxy on the path can read. A pin over what was displayed is a pin over
the one part of the definition an attacker has no need to touch.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class FieldSet(str, Enum):
    """Which parts of a tool definition enter the fingerprint.

    Ordered from narrowest to widest. The ordering is meaningful: each level is
    a superset of the one above it, so a mutation detected at one level is
    detected at every wider level, and the matrix should be monotone down each
    column. `tests/test_matrix.py::test_detection_is_monotone_in_the_field_set`
    asserts that, because a non-monotone cell means a bug in the field
    selector rather than an interesting result.
    """

    NAME = "name"
    """The tool name alone. Present as the floor of the ladder, not as a
    proposal. It catches a renamed tool and nothing else."""

    REVIEWED = "reviewed"
    """Name plus description: what the human was shown. This is the level that
    matters, because it is what an approval dialog displays and therefore what
    an implementor's intuition reaches for. The measurement exists to say how
    much of the attack surface it covers."""

    DECLARED = "declared"
    """Every field the 2026-07-28 `Tool` model declares: name, title,
    description, inputSchema, outputSchema, annotations, icons. This is the
    honest answer to "pin the tool definition"."""

    WIRE = "wire"
    """The entire JSON object as it arrived, including keys the SDK's `Tool`
    model does not declare.

    Not redundant with declared, and this is easy to miss: `mcp_types` builds
    `Tool` with `ConfigDict(extra="ignore")`, so a top-level key the schema
    does not name is dropped at parse time and is invisible to anything
    fingerprinting the parsed object. Whether that key reaches the model
    depends on how the host serializes tools into the prompt, which is a host
    decision the protocol does not constrain. Pinning the parsed model is
    pinning a lossy view of what the server sent."""


class Canonicalization(str, Enum):
    """How the selected bytes are normalized before hashing.

    Read the module docstring first. RAW and STRUCTURAL are in one family;
    TEXT_FOLDED is in the other; SEMANTIC returns to the first. The ladder is
    deliberately NOT ordered by strength, because it is not a strength
    ordering, that is the finding.
    """

    RAW = "raw"
    """Hash the bytes exactly as received. Maximum sensitivity and maximum
    false alarms: re-serializing an unchanged tool through a different JSON
    library trips it."""

    STRUCTURAL = "structural"
    """Parse, sort object keys, re-serialize with fixed separators. Removes
    encoding-level noise. Changes no character the model will read."""

    TEXT_FOLDED = "text_folded"
    """STRUCTURAL, then NFKC-normalize strings, strip zero-width and
    bidirectional control characters, and collapse runs of whitespace.

    This is the trade, the only level on this ladder that is one. Every
    character this removes is a character the model still reads. A homoglyph
    the fold maps onto its ASCII twin is a character an attacker can change
    freely without moving the hash."""

    SEMANTIC = "semantic"
    """STRUCTURAL, then resolve `$ref`/`$defs` and expand the schema to a
    normal form, WITHOUT text folding.

    Accepts a schema rewritten through `$defs` that validates identically, at
    no cost to any detection. Deliberately NOT a superset of TEXT_FOLDED: the
    safe normalizations and the unsafe one are separable, and a policy can
    take every one of the first family and none of the second."""

    SEMANTIC_FOLDED = "semantic_folded"
    """SEMANTIC and TEXT_FOLDED together: every normalization this module
    knows how to do.

    Present because it is the obvious question and it deserves a number rather
    than an argument. It is the quietest policy on the grid, the only one that
    reaches zero false alarms with a wide field set, and it buys that silence
    with exactly one detection. Whether that is a good trade is a deployment's
    decision and not this repository's; what the measurement can do is put the
    price on the label instead of leaving "normalize the text" to sound
    free."""


@dataclass(frozen=True, slots=True)
class PinPolicy:
    """One point in the grid: a field set crossed with a canonicalization.

    Frozen and hashable so a policy can key a results table.
    """

    fields: FieldSet
    canonical: Canonicalization

    @property
    def label(self) -> str:
        return f"{self.fields.value}/{self.canonical.value}"

    def __str__(self) -> str:  # pragma: no cover - display only
        return self.label


#: Every policy the measurement evaluates. The full cross product is 16 cells
#: and costs nothing to compute, and reporting the whole grid is what makes the
#: two axes visibly independent. A table with the interesting rows pre-selected
#: would be an argument rather than a measurement.
POLICY_GRID: tuple[PinPolicy, ...] = tuple(
    PinPolicy(fields=f, canonical=c) for f in FieldSet for c in Canonicalization
)


#: The policy this project recommends, and the reasoning is in README.md
#: section 5. Widest field set, every safe normalization, no text folding.
RECOMMENDED = PinPolicy(fields=FieldSet.WIRE, canonical=Canonicalization.SEMANTIC)

#: The policy an approval dialog implies, which is the one being measured
#: against. Not a straw man: it is what "hash the tool description" means.
INTUITIVE = PinPolicy(fields=FieldSet.REVIEWED, canonical=Canonicalization.TEXT_FOLDED)


class Verdict(str, Enum):
    """The outcome of checking a tool definition against its pin."""

    MATCH = "match"
    """Fingerprint equals the pinned value. The call may proceed."""

    CHANGED = "changed"
    """Fingerprint differs. That tool is quarantined pending re-approval. NOT
    "blocked": a changed definition is not evidence of an attack, only evidence
    that the approval on file no longer describes what is being offered."""

    UNPINNED = "unpinned"
    """No pin exists for this (server identity, tool name). Trust on first use
    is a DECISION the store records, not a state it silently resolves."""

    IDENTITY_UNVERIFIED = "identity_unverified"
    """The pin exists but the server identity it was bound to cannot be
    confirmed for this connection. See pin/identity.py: the 2026-07-28 spec
    states that `serverInfo.name` is self-reported and SHOULD NOT be relied on
    for security decisions, so a pin bound to it is bound to nothing."""


@dataclass(frozen=True, slots=True)
class Fingerprint:
    """A pin: one hash, plus everything needed to recompute and explain it."""

    digest: str
    """Hex SHA-256 of the canonical form."""

    policy: PinPolicy
    canonical_form: str
    """The exact string that was hashed. Kept because a pin that cannot show
    its own input produces a diff nobody can act on, and the re-approval
    prompt is what detecting a change is for."""


@dataclass(frozen=True, slots=True)
class ToolRecord:
    """A tool definition as it arrived on the wire, before the SDK parses it.

    `raw` is the JSON object from `tools/list`, unmodified. Everything the
    fingerprinter needs is derived from it; nothing here is taken from a
    parsed model, so FieldSet.WIRE has something to see.
    """

    server: str
    """The identity the pin is bound to. See pin/identity.py; this is a
    transport-anchored value, never `serverInfo.name`."""

    raw: dict[str, Any]

    @property
    def name(self) -> str:
        value = self.raw.get("name")
        return value if isinstance(value, str) else ""


@dataclass(slots=True)
class CheckResult:
    """What the client learned when it checked one tool before calling it."""

    tool: str
    verdict: Verdict
    policy: PinPolicy
    pinned_digest: str | None = None
    observed_digest: str | None = None
    diff: list[str] = field(default_factory=list)
    """Human-readable lines describing what moved. Empty on MATCH."""

    @property
    def may_call(self) -> bool:
        """Only a MATCH authorizes a call without a fresh human decision.

        UNPINNED is deliberately not callable. A store that pins on first sight
        and proceeds has converted an approval into a formality, and every
        measurement in this repository would then be describing a control that
        never says no.
        """
        return self.verdict is Verdict.MATCH
