"""Diff SAMPLE_RUN.md against a fresh run, so the capture stays a capture.

    python scripts/check_sample_run.py            gate block and all three legs
    python scripts/check_sample_run.py --offline  gate block only; no SDK needed

SAMPLE_RUN.md says its output is verbatim and byte-identical between runs.
This is what makes that a claim that can fail rather than a promise: for each
command the page quotes, the fenced block that follows the command is compared
with the output of running that command now. Exit status is 1, with a unified
diff, when they differ.

The test-suite block is not compared here. Its last line carries a duration,
which is the one thing on the page that is not byte-identical between runs;
its count is checked against the collected suite by the portfolio audit.
"""

from __future__ import annotations

import contextlib
import difflib
import io
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_RUN = ROOT / "SAMPLE_RUN.md"

_FENCE = re.compile(r"^```(\w*)\s*$")


def fenced_blocks(text: str) -> list[tuple[str, str, int, int]]:
    """Every fenced block as (language, content, first line, last line).

    Line numbers are those of the fences themselves, 1-based, so a caller can
    tell whether two blocks are adjacent.
    """
    blocks: list[tuple[str, str, int, int]] = []
    lang: str | None = None
    body: list[str] = []
    opened = 0
    for number, line in enumerate(text.splitlines(), start=1):
        match = _FENCE.match(line)
        if match and lang is None:
            lang, body, opened = match.group(1), [], number
        elif match:
            blocks.append((lang, "\n".join(body), opened, number))
            lang = None
        elif lang is not None:
            body.append(line)
    return blocks


def quoted_output(text: str, command: str) -> str | None:
    """The block the page shows as the output of `command`.

    That is the plain fenced block immediately after a `sh` block whose only
    content is the command, with nothing but blank lines between the two. A
    `sh` block followed by prose is the command being introduced, not run.
    """
    lines = text.splitlines()
    blocks = fenced_blocks(text)
    for (lang, content, _, end), (_, following, start, _) in zip(blocks, blocks[1:]):
        between = lines[end:start - 1]
        adjacent = all(not line.strip() for line in between)
        if lang == "sh" and content.strip() == command and adjacent:
            return following
    return None


def gate_output() -> str:
    from pin.gate import main

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        main()
    return buffer.getvalue()


def demo_output() -> str:
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "run_demo.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout


def _compare(label: str, quoted: str | None, fresh: str) -> list[str]:
    if quoted is None:
        return [f"{label}: SAMPLE_RUN.md has no output block after that command"]
    expected = quoted.rstrip("\n").splitlines()
    actual = fresh.rstrip("\n").splitlines()
    if expected == actual:
        return []
    diff = difflib.unified_diff(
        expected, actual, fromfile="SAMPLE_RUN.md", tofile=label, lineterm=""
    )
    return [f"{label}: the quoted output differs from a fresh run", *diff]


def problems(offline: bool) -> list[str]:
    """Every way the page disagrees with a fresh run; empty when it agrees."""
    text = SAMPLE_RUN.read_text(encoding="utf-8")
    found = _compare("python -m pin.gate", quoted_output(text, "python -m pin.gate"), gate_output())
    if offline:
        return found
    found += _compare(
        "python scripts/run_demo.py",
        quoted_output(text, "python scripts/run_demo.py"),
        demo_output(),
    )
    return found


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    offline = "--offline" in args
    found = problems(offline=offline)
    checked = "gate block" if offline else "gate block and three-leg block"
    if found:
        print("\n".join(found))
        print(f"\nSAMPLE_RUN.md is stale ({checked} checked)")
        return 1
    print(f"SAMPLE_RUN.md matches a fresh run ({checked} checked)")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    sys.exit(main())
