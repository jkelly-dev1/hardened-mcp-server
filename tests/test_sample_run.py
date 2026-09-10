"""SAMPLE_RUN.md is a capture, and a capture is checkable or it is a screenshot."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _check_sample_run():
    path = ROOT / "scripts" / "check_sample_run.py"
    spec = importlib.util.spec_from_file_location("check_sample_run", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_the_gate_capture_in_sample_run_is_what_the_gate_prints_today() -> None:
    """The offline half of `scripts/check_sample_run.py`, run as a test.

    The gate fires when the README's numbers move. This fires when the gate's
    own output moves and the page that quotes it verbatim does not.
    """
    assert _check_sample_run().problems(offline=True) == []
