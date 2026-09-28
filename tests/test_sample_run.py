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


def test_check_sample_run_main_returns_a_verdict_ci_can_act_on(monkeypatch, tmp_path, capsys):
    """CI runs main(); its exit code is the verdict. 0 on the shipped page, 1
    on a page whose gate block no longer matches a fresh run."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    monkeypatch.syspath_prepend(str(root / "scripts"))
    import check_sample_run as csr
    assert csr.main(["--offline"]) == 0
    page = (root / "SAMPLE_RUN.md").read_text(encoding="utf-8")
    broken = tmp_path / "SAMPLE_RUN.md"
    assert "9/9 checks passed" in page
    broken.write_text(page.replace("9/9 checks passed", "8/9 checks passed"),
                      encoding="utf-8")
    monkeypatch.setattr(csr, "SAMPLE_RUN", broken)
    assert csr.main(["--offline"]) == 1
