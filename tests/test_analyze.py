"""Tests for stage 5 analyze. No model, no network — fake call_llm injected."""
import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from lib.analyze import AnalyzeError, analyze, deterministic_analysis, validate_analysis  # noqa: E402

RANKED = {"version": 1, "program": "unit-test", "candidates": [
    {"id": "cve-2021-41773", "title": "Apache traversal", "severity": "high",
     "confidence": "high", "likely_false_positive": False,
     "hosts": ["www.example.com"], "templates": ["CVE-2021-41773"], "rationale": "x"}]}

GOOD = {"version": 1, "program": "unit-test", "candidates": [
    {"id": "cve-2021-41773", "title": "Apache traversal",
     "hosts": ["www.example.com"], "templates": ["CVE-2021-41773"],
     "analysis": {"exploitability": "reachable", "in_scope": True, "severity": "high",
                  "cvss_vector": "", "reproduction_outline": ["probe once"],
                  "confirmed": True, "needs_manual_proof": False,
                  "out_of_policy_to_prove": False, "notes": "ok"}}]}


def test_validator_rejects_missing_analysis_booleans():
    bad = json.loads(json.dumps(GOOD))
    del bad["candidates"][0]["analysis"]["confirmed"]
    bad["candidates"][0]["analysis"]["severity"] = "nope"
    errs = validate_analysis(bad)
    assert any("confirmed" in e for e in errs)
    assert any("severity" in e for e in errs)
    assert validate_analysis(GOOD) == []


def test_analyze_retries_then_succeeds():
    n = {"c": 0}
    def llm(_):
        n["c"] += 1
        return "oops" if n["c"] == 1 else json.dumps(GOOD)
    out = analyze(RANKED, llm)
    assert n["c"] == 2 and out["source"] == "model"


def test_analyze_raises_when_never_valid():
    try:
        analyze(RANKED, lambda p: "{}", max_retries=1)
    except AnalyzeError:
        pass
    else:
        raise AssertionError("expected AnalyzeError")


def test_deterministic_confirms_nothing_and_flags():
    out = deterministic_analysis(RANKED)
    assert validate_analysis(out) == []
    a = out["candidates"][0]["analysis"]
    assert a["confirmed"] is False and a["needs_manual_proof"] is True


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
