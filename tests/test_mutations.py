"""The corpus itself: that each change is what it claims to be.

A mutation corpus is an instrument, and an instrument that is wrong produces
confident numbers about nothing. These tests check the changes rather than the
policies, that the adversarial ones really alter what the tool accepts or
says, and that the benign ones really do not.
"""

from __future__ import annotations

import json

import pytest

from pin import corpus
from pin.canonical import fold_text
from pin.mutations import ADVERSARIAL, BENIGN, MUTATIONS
from pin.scan import header_mirrored_parameters, hidden_text, reviewer_surface


def test_every_mutation_targets_a_tool_that_exists() -> None:
    names = set(corpus.NAMES)
    for mutation in MUTATIONS:
        assert mutation.tool in names, mutation.key


def test_mutation_keys_are_unique() -> None:
    keys = [m.key for m in MUTATIONS]
    assert len(keys) == len(set(keys))


def test_a_mutation_does_not_modify_the_corpus() -> None:
    """Every arm of the grid must start from the same baseline."""
    before = json.dumps(corpus.baseline(), sort_keys=True)
    for mutation in MUTATIONS:
        mutation(corpus.by_name(mutation.tool))
    assert json.dumps(corpus.baseline(), sort_keys=True) == before


@pytest.mark.parametrize(
    "mutation", [m for m in ADVERSARIAL if m.key != "remote_schema_edit"],
    ids=lambda m: m.key,
)
def test_each_adversarial_mutation_actually_changes_the_definition(mutation) -> None:
    original = corpus.by_name(mutation.tool)
    assert mutation(original) != original


def test_the_remote_schema_edit_leaves_the_definition_byte_identical() -> None:
    """The one deliberate no-op, asserted so nobody "fixes" it.

    The change happened in a document the client never fetched. Every policy
    reports MATCH and every one is correct about the bytes it was given; the
    information needed to notice was never in them.
    """
    original = corpus.by_name("attach_file")
    mutation = next(m for m in MUTATIONS if m.key == "remote_schema_edit")
    assert mutation(original) == original


def test_the_tool_it_targets_carries_an_unresolvable_reference() -> None:
    """Without this, the no-op above would be a no-op about nothing."""
    from pin.scan import unresolvable_refs

    assert unresolvable_refs(corpus.by_name("attach_file"))


@pytest.mark.parametrize("mutation", BENIGN, ids=lambda m: m.key)
def test_each_benign_mutation_preserves_the_words_a_reader_sees(mutation) -> None:
    """Benign means the encoding moved, not the meaning.

    Compared after folding, which is the operation that removes exactly the
    presentational differences these changes are allowed to make. A benign
    mutation that altered a word would fail here, and the false-alarm column
    would otherwise be measuring the wrong thing.
    """
    original = corpus.by_name(mutation.tool)
    changed = mutation(original)
    assert fold_text(reviewer_surface(original)) == fold_text(reviewer_surface(changed))


def test_the_header_mutation_adds_a_header_channel_to_a_credential() -> None:
    original = corpus.by_name("export_records")
    mutation = next(m for m in MUTATIONS if m.key == "header_exfil")
    changed = mutation(original)
    before = header_mirrored_parameters(original)
    after = header_mirrored_parameters(changed)
    assert len(after) == len(before) + 1
    assert any("export_token" in f.path for f in after)
    assert not any("export_token" in f.path for f in before)


def test_the_header_mutation_changes_nothing_a_reviewer_is_shown() -> None:
    """The claim the whole project turns on, asserted directly."""
    original = corpus.by_name("export_records")
    mutation = next(m for m in MUTATIONS if m.key == "header_exfil")
    assert reviewer_surface(mutation(original)) == reviewer_surface(original)


def test_the_trojan_source_mutation_adds_no_words() -> None:
    """It moves rendering, not content, so folding hides it."""
    original = corpus.by_name("ticket_lookup")
    mutation = next(m for m in MUTATIONS if m.key == "trojan_source")
    changed = mutation(original)
    assert changed["description"] != original["description"]
    assert fold_text(changed["description"]) == fold_text(original["description"])


def test_the_planted_key_is_text_outside_the_reviewed_surface() -> None:
    original = corpus.by_name("ticket_lookup")
    mutation = next(m for m in MUTATIONS if m.key == "unknown_field_plant")
    changed = mutation(original)
    assert any("pre-authorized" in chunk for chunk in hidden_text(changed))


def test_the_baseline_already_mirrors_one_parameter_by_design() -> None:
    """So the measurement can tell "mirrors" from "started mirroring"."""
    findings = header_mirrored_parameters(corpus.by_name("ticket_lookup"))
    assert len(findings) == 1
    assert "region" in findings[0].path
