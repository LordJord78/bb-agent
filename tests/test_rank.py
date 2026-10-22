"""Tests for stage 4b ranking. No model, no network — a fake call_llm is injected."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.rank import (  # noqa: E402
    RankError,
    deterministic_ranking,
    rank,
    validate_ranking,
)

# A realistic 4a shortlist (as stage 4a would emit for example.com).
SHORTLIST = {
    "program": "unit-test",
    "assets": {
        "www.example.com": [
            {"template": "CVE-2021-41773", "name": "Apache Path Traversal", "host": "www.example.com", "severity": "high", "location": "www.example.com/cgi-bin"},
            {"template": "apache-detect", "name": "Apache Detect", "host": "www.example.com", "severity": "medium", "location": "www.example.com"},
        ],
        "shop.example.com": [
            {"template": "exposed-git", "name": "Exposed .git", "host": "shop.example.com", "severity": "low", "location": "shop.example.com/.git/config"},
        ],
    },
}

GOOD = {
    "version": 1,
    "program": "unit-test",
    "candidates": [{
        "id": "cve-2021-41773",
        "title": "Apache path traversal",
        "severity": "high",
        "confidence": "high",
        "likely_false_positive": False,
        "hosts": ["www.example.com"],
        "templates": ["CVE-2021-41773"],
        "rationale": "Known RCE-adjacent traversal on a live host.",
    }],
}


def test_validator_accepts_good_and_rejects_bad():
    assert validate_ranking(GOOD) == []
    bad = json.loads(json.dumps(GOOD))
    bad["candidates"][0]["severity"] = "spicy"      # not an enum value
    bad["candidates"][0]["hosts"] = []               # empty
    errs = validate_ranking(bad)
    assert any("severity" in e for e in errs)
    assert any("hosts" in e for e in errs)


def test_rank_retries_once_then_succeeds():
    calls = {"n": 0}

    def flaky_llm(prompt: str) -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            return "here you go: {not valid json"      # first reply is garbage
        return json.dumps(GOOD)                          # retry is valid

    out = rank(SHORTLIST, flaky_llm)
    assert calls["n"] == 2                               # exactly one retry
    assert out["source"] == "model"
    assert out["candidates"][0]["id"] == "cve-2021-41773"


def test_rank_raises_when_never_valid():
    try:
        rank(SHORTLIST, lambda p: "still not json", max_retries=1)
    except RankError:
        pass
    else:
        raise AssertionError("expected RankError when output never validates")


def test_deterministic_fallback_is_schema_valid():
    out = deterministic_ranking(SHORTLIST)
    assert validate_ranking(out) == []
    assert out["source"] == "deterministic-fallback"
    # Highest severity cluster ranks first.
    assert out["candidates"][0]["severity"] == "high"
    # Only hosts/templates from the input appear.
    hosts = {h for c in out["candidates"] for h in c["hosts"]}
    assert hosts <= {"www.example.com", "shop.example.com"}


def _run():
    passed = 0
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        try:
            t()
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL  {t.__name__}: {type(exc).__name__}: {exc}")
        else:
            passed += 1
            print(f"pass  {t.__name__}")
    print(f"\n{passed}/{len(tests)} passed")
    return 0 if passed == len(tests) else 1


if __name__ == "__main__":
    raise SystemExit(_run())
