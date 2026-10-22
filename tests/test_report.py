"""Tests for stage 6 report rendering. Deterministic; writes to a temp dir."""
import json, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from lib.report import render_report, write_reports  # noqa: E402

ANALYZED = json.load(open(ROOT / "tests/fixtures/analyzed-confirmed.json"))


def test_only_confirmed_candidates_are_drafted():
    with tempfile.TemporaryDirectory() as d:
        written = write_reports(ANALYZED, "example-program", True, Path(d))
        names = sorted(p.name for p in written)
        # cve is confirmed; exposed-git is not.
        assert names == ["cve-2021-41773.md"]


def test_report_has_banner_disclosure_and_no_submission():
    c = ANALYZED["candidates"][0]
    md = render_report(c, "example-program", ai_disclosure=True)
    assert md.startswith("# [HUMAN REVIEW REQUIRED]")
    assert "[HUMAN REVIEW REQUIRED]" in md
    assert "AI-assisted" in md
    assert "NOT submitted" in md
    assert "non-destructive" in md


def test_disclosure_omitted_when_not_required():
    c = ANALYZED["candidates"][0]
    md = render_report(c, "example-program", ai_disclosure=False)
    assert "AI-assisted" not in md
    assert "[HUMAN REVIEW REQUIRED]" in md  # banner always present


def _run():
    passed = 0
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        try: t()
        except Exception as exc: print(f"FAIL  {t.__name__}: {type(exc).__name__}: {exc}")
        else: passed += 1; print(f"pass  {t.__name__}")
    print(f"\n{passed}/{len(tests)} passed")
    return 0 if passed == len(tests) else 1

if __name__ == "__main__":
    raise SystemExit(_run())
