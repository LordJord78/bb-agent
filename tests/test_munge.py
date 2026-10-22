"""Tests for stage 4a munge. All example.com; no network, no model."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.munge import munge  # noqa: E402

SCOPE = {
    "program": "unit-test",
    "in_scope": ["*.example.com", "example.com"],
    "out_of_scope": ["blog.example.com"],
}
FIXTURE = (ROOT / "tests/fixtures/nuclei-sample.jsonl").read_text().splitlines()


def test_dedupe_threshold_scope_and_grouping():
    out = munge(FIXTURE, SCOPE, severity_min="low")
    c = out["counts"]
    # Two identical apache-detect rows collapse to one.
    assert c["deduplicated"] == 1
    # The three info findings (2 on api, 1 on www) are dropped by the low threshold.
    assert c["dropped_below_threshold"] == 3
    # blog.example.com (out_of_scope, critical) and evil-example.com (lookalike)
    # are both dropped by the safety-net scope check.
    assert c["dropped_out_of_scope"] == 2
    # The non-JSON line is skipped.
    assert c["skipped_malformed"] == 1
    # Survivors: apache-detect(med), CVE(high) on www; exposed-git(low) on shop.
    assert c["surviving"] == 3
    assert set(out["assets"].keys()) == {"www.example.com", "shop.example.com"}
    # www's findings are severity-sorted (high before medium).
    sev = [f["severity"] for f in out["assets"]["www.example.com"]]
    assert sev == ["high", "medium"]
    # No dropped host leaked into the output.
    assert "blog.example.com" not in out["assets"]
    assert "evil-example.com" not in out["assets"]


def test_keep_info_raises_survivors():
    out = munge(FIXTURE, SCOPE, severity_min="info")
    assert out["counts"]["dropped_below_threshold"] == 0
    assert out["counts"]["surviving"] == 6  # 3 + 3 info on in-scope hosts


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
