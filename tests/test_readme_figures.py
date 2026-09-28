"""README.md's offline figures against the code that produces them.

The gate re-derives the claims from the code; this checks that the PAGE says
what the code says. Legs 2 and 3 are checked beside their own tests, which
need the SDK.
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

import pytest

from pin import gate, matrix

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")


def _flat(text: str) -> str:
    return " ".join(text.split())


def test_the_readme_grid_is_the_grid_the_matrix_produces() -> None:
    assert _flat(matrix.format_grid(matrix.run())) in _flat(README)


def test_the_readme_counts_the_gate_checks_there_are() -> None:
    stated = re.search(r"python -m pin\.gate\s+# (\d+) checks", README)
    assert stated, "README no longer states the gate's check count"
    assert int(stated.group(1)) == len(gate.checks())


def _uncollected_module_tests(collected_files: set[str]) -> int:
    """Test functions in modules that skipped at import.

    Without the SDK, the two protocol modules call `pytest.importorskip` at
    module level, so collection never sees their tests. CI's offline job runs
    in exactly that shape, and the README states the count of the whole
    suite. The functions are counted from the source instead. A parametrized
    one would make that count wrong, so it fails here rather than
    undercounting.
    """
    total = 0
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        rel = path.relative_to(ROOT).as_posix()
        if rel in collected_files:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name.startswith("test_")):
                assert not any("parametrize" in ast.unparse(d)
                               for d in node.decorator_list), (
                    f"{rel}::{node.name} is parametrized; count it by collection")
                total += 1
    return total


def test_the_readme_test_count_is_the_collected_count() -> None:
    stated = re.search(r"pytest -q -rs\s+# (\d+) tests", README)
    assert stated, "README no longer states a test count"
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q",
         "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True, timeout=120,
    ).stdout
    collected = int(re.search(r"(\d+) tests? collected", out).group(1))
    files = {line.split("::", 1)[0] for line in out.splitlines() if "::" in line}
    assert int(stated.group(1)) == collected + _uncollected_module_tests(files)


# --------------------------------------------------------------------------- #
# Figures stated in prose. Each row is a pattern anchored on the words around
# its figure, so it matches one sentence and no other, and the values the code
# produces for it. A figure written as a word is read as the number it names.

_WORDS = {w: i for i, w in enumerate(
    "zero one two three four five six seven eight nine ten eleven twelve".split())}


def _as_int(text: str) -> int:
    return int(text) if text.isdigit() else _WORDS[text.lower()]


def _figures() -> dict[str, object]:
    import importlib.util
    import inspect

    from pin import exposure
    from pin.mutations import ADVERSARIAL, BENIGN
    from pin.models import POLICY_GRID

    spec = importlib.util.spec_from_file_location(
        "real_run", ROOT / "scripts" / "real_run.py")
    real_run = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("real_run", real_run)  # its dataclasses look it up
    spec.loader.exec_module(real_run)

    results = matrix.run()
    arm = {r.policy.label: r for r in results}
    intuitive, wire_sem = arm["reviewed/text_folded"], arm["wire/semantic"]
    wire_raw, folded = arm["wire/raw"], arm["wire/semantic_folded"]
    six = set(intuitive.missed_keys()) - set(wire_sem.missed_keys())
    unshown = six & set(arm["reviewed/raw"].missed_keys())
    defaults = inspect.signature(exposure.run_arm).parameters
    per_vendor = len(real_run.ARMS) * 2 * real_run.TRIALS
    return {
        "adv": len(ADVERSARIAL), "benign": len(BENIGN), "grid": len(POLICY_GRID),
        "intuitive": intuitive.detected, "intuitive_fa": intuitive.false_alarms,
        "intuitive_pct": int(100 * intuitive.detection_rate),
        "wire_raw": wire_raw.detected, "wire_raw_fa": wire_raw.false_alarms,
        "wire_sem": wire_sem.detected, "wire_sem_fa": wire_sem.false_alarms,
        "folded": folded.detected, "folded_fa": folded.false_alarms,
        "fold_trade": (wire_sem.detected - folded.detected,
                       wire_sem.false_alarms - folded.false_alarms),
        "six": len(six), "unshown": len(unshown),
        "missed_by_all": len(matrix.universally_missed(results)),
        "calls": defaults["calls"].default,
        "interval_s": defaults["interval_ms"].default // 1000,
        "server_ttl": defaults["server_ttl_ms"].default,
        "arms": len(real_run.ARMS), "trials": real_run.TRIALS,
        "vendors": len(real_run.VENDORS), "per_vendor": per_vendor,
        "both_vendors": per_vendor * len(real_run.VENDORS),
        "probe": len(re.findall(r"= call\(", inspect.getsource(real_run.probe))),
        "checks": len(gate.checks()),
        "tests": int(re.search(r"pytest -q -rs\s+# (\d+) tests", README).group(1)),
    }


_ROWS = [
    ("README.md", r"showed you catches (\d+) of (\d+) changes",
     lambda f: (f["intuitive"], f["adv"])),
    ("README.md", r"raw wire object catches (\d+) of (\d+); and the eighth is missed by all (\d+) policies",
     lambda f: (f["wire_raw"], f["adv"], f["grid"])),
    ("README.md", r"from (\d+) calls across (\w+) vendors",
     lambda f: (f["both_vendors"], f["vendors"])),
    ("README.md", r"Against (\d+) adversarial changes that must be detected and (\d+) benign",
     lambda f: (f["adv"], f["benign"])),
    ("README.md", r"It detects (\w+) of (\w+), and it raises no alarm",
     lambda f: (f["intuitive"], f["adv"]) if f["intuitive_fa"] == 0 else None),
    ("README.md", r"false-alarm record and a (\d+)% detection rate",
     lambda f: (f["intuitive_pct"],)),
    ("README.md", r"The (\w+) it misses that `wire/semantic` catches",
     lambda f: (f["six"],)),
    ("README.md", r"(\w+) of them are changes to fields the reviewer was never shown",
     lambda f: (f["unshown"],)),
    ("README.md", r"`wire/raw` and `wire/semantic` both detect (\d+) of (\d+); false alarms drop from (\d+) to (\d+)\.",
     lambda f: (f["wire_raw"], f["adv"], f["wire_raw_fa"], f["wire_sem_fa"])
     if f["wire_raw"] == f["wire_sem"] else None),
    ("README.md", r"`remote_schema_edit` is missed by all (\d+) policies",
     lambda f: (f["grid"],)),
    ("README.md", r"(\w+) simulated calls, (\d+)s apart on an injected clock, server advertising `ttlMs` (\d+)\.",
     lambda f: (f["calls"], f["interval_s"], f["server_ttl"])),
    ("README.md", r"description-only pin misses (\w+) of (\w+) changes, and that (\w+) of those",
     lambda f: (f["adv"] - f["intuitive"], f["adv"], f["unshown"])),
    ("README.md", r"The capture is (\d+) calls: (\d+) against `claude-opus-5` and the same (\d+) against",
     lambda f: (f["both_vendors"], f["per_vendor"], f["per_vendor"])),
    ("README.md", r"(\w+) mutations, each with its own paired control",
     lambda f: (f["arms"],)),
    ("README.md", r"one field different\. (\w+) trials per cell\.",
     lambda f: (f["trials"],)),
    ("README.md", r"### The same (\d+) calls against a second vendor",
     lambda f: (f["per_vendor"],)),
    ("README.md", r"cannot drift\. (\d+) calls total\.",
     lambda f: (f["both_vendors"],)),
    ("README.md", r"one task per arm\.\*\* (\d+) calls total\.",
     lambda f: (f["both_vendors"],)),
    ("README.md", r"real_run\.py --probe # (\d+) calls",
     lambda f: (f["probe"],)),
    ("README.md", r"scripts/real_run\.py # (\d+) calls",
     lambda f: (f["per_vendor"],)),
    ("README.md", r"`wire/semantic`: the whole payload, every free normalization, no text folding\. (\d+) of (\d+) detected, (\d+) false alarm\.",
     lambda f: (f["wire_sem"], f["adv"], f["wire_sem_fa"])),
    ("README.md", r"`wire/semantic_folded` at (\d+) of (\d+) with a clean false-alarm record",
     lambda f: (f["folded"], f["adv"]) if f["folded_fa"] == 0 else None),
    ("SAMPLE_RUN.md", r"(\w+) checks over the numbers that appear in `README\.md`",
     lambda f: (f["checks"],)),
    ("SAMPLE_RUN.md", r"(\d+) passed in [\d.]+s",
     lambda f: (f["tests"],)),
    ("SAMPLE_RUN.md", r"This is (\d+) calls against `claude-opus-5`",
     lambda f: (f["per_vendor"],)),
    ("GITHUB_DESCRIPTION.txt", r"catches (\d+) of (\d+) rug pulls; pinning the raw wire object catches (\d+)\.",
     lambda f: (f["intuitive"], f["adv"], f["wire_raw"])),
    ("GITHUB_DESCRIPTION.txt", r"trades exactly (\w+) detection for (\w+) false alarm",
     lambda f: f["fold_trade"]),
    ("GITHUB_DESCRIPTION.txt", r"(\w+) attack is missed by all (\d+) policies",
     lambda f: (f["missed_by_all"], f["grid"])),
]


@pytest.mark.parametrize("doc, pattern, expected", _ROWS,
                         ids=[f"{d}:{p[:40]}" for d, p, _ in _ROWS])
def test_a_figure_stated_in_prose_is_the_figure_the_code_produces(doc, pattern, expected) -> None:
    text = _flat((ROOT / doc).read_text(encoding="utf-8"))
    hits = list(re.finditer(pattern, text))
    assert len(hits) == 1, f"{doc}: {len(hits)} sentences match {pattern!r}"
    stated = tuple(_as_int(g) for g in hits[0].groups())
    assert stated == expected(_FIGURES), f"{doc}: {hits[0].group(0)!r}"


_FIGURES = _figures()
