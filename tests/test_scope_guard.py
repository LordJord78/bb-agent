"""Tests for the Scope Guard.

Runs with plain `python3 tests/test_scope_guard.py` (no pytest needed) and is
also collectable by pytest if you install it. Everything here uses example.com;
no network, no real hosts.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.scope_guard import (  # noqa: E402
    ScopeError,
    ScopeRefusal,
    assert_active_testing_allowed,
    assert_automation_allowed,
    host_in_scope,
    load_scope,
    normalize_host,
    scope_filter,
)

# A representative scope used by most tests.
SCOPE = {
    "program": "unit-test",
    "in_scope": ["*.example.com", "example.com", "api.example.com"],
    "out_of_scope": ["blog.example.com", "*.internal.example.com"],
    "automation_allowed": True,
    "active_testing_allowed": False,
}


def test_exact_host_in_scope():
    assert host_in_scope("api.example.com", SCOPE) is True


def test_wildcard_matches_subdomain():
    assert host_in_scope("shop.example.com", SCOPE) is True
    assert host_in_scope("a.b.example.com", SCOPE) is True


def test_wildcard_does_not_match_apex_implicitly():
    # Apex passes only because it is listed explicitly, not via "*.example.com".
    apex_only = {"in_scope": ["*.example.com"], "out_of_scope": []}
    assert host_in_scope("example.com", apex_only) is False


def test_apex_listed_explicitly_is_in_scope():
    assert host_in_scope("example.com", SCOPE) is True


def test_wildcard_apex_optin_is_per_program():
    # Opt-in off (default): wildcard does NOT cover the apex.
    off = {"in_scope": ["*.example.com"], "out_of_scope": []}
    assert host_in_scope("example.com", off) is False
    # Opt-in on: the same wildcard now covers the apex for this program only.
    on = {"in_scope": ["*.example.com"], "out_of_scope": [], "wildcard_includes_apex": True}
    assert host_in_scope("example.com", on) is True
    # Opt-in must not weaken out_of_scope or admit lookalikes.
    assert host_in_scope("evil-example.com", on) is False
    guarded = dict(on, out_of_scope=["example.com"])
    assert host_in_scope("example.com", guarded) is False


def test_lookalikes_are_rejected():
    assert host_in_scope("evil-example.com", SCOPE) is False
    assert host_in_scope("example.com.evil.com", SCOPE) is False
    assert host_in_scope("notexample.com", SCOPE) is False


def test_out_of_scope_overrides_in_scope():
    # REQUIRED: out_of_scope must beat in_scope even though the wildcard matches.
    assert host_in_scope("blog.example.com", SCOPE) is False
    assert host_in_scope("db.internal.example.com", SCOPE) is False


def test_unlisted_host_rejected():
    assert host_in_scope("example.org", SCOPE) is False
    assert host_in_scope("", SCOPE) is False


def test_scope_filter_normalizes_dedupes_and_preserves_order():
    raw = [
        "https://API.example.com:443/login",   # scheme/port/path/case -> api.example.com
        "shop.example.com",
        "api.example.com",                      # duplicate of the first
        "blog.example.com",                     # out of scope -> dropped
        "example.org",                          # not in scope -> dropped
        "a.b.example.com",
    ]
    assert scope_filter(raw, SCOPE) == [
        "api.example.com",
        "shop.example.com",
        "a.b.example.com",
    ]


def test_normalize_host_strips_scheme_port_path():
    assert normalize_host("HTTPS://Foo.Example.com:8443/x?y=1") == "foo.example.com"
    assert normalize_host("user@host.example.com.") == "host.example.com"
    assert normalize_host(None) == ""


def test_automation_disallowed_refusal():
    # REQUIRED: automation_allowed=false is a hard stop for active tools.
    locked = dict(SCOPE, automation_allowed=False)
    try:
        assert_automation_allowed(locked)
    except ScopeRefusal:
        pass
    else:
        raise AssertionError("expected ScopeRefusal when automation_allowed is false")
    # When allowed, it must NOT raise.
    assert_automation_allowed(dict(SCOPE, automation_allowed=True))


def test_active_testing_gate():
    try:
        assert_active_testing_allowed(dict(SCOPE, active_testing_allowed=False))
    except ScopeRefusal:
        pass
    else:
        raise AssertionError("expected ScopeRefusal when active_testing_allowed is false")
    assert_active_testing_allowed(dict(SCOPE, active_testing_allowed=True))


def test_load_example_scope_defaults():
    scope = load_scope("example-program")
    assert scope["program"] == "example-program"
    assert "example.com" in scope["in_scope"]
    assert scope["rate_limit_rps"] == 2
    assert scope["active_testing_allowed"] is False
    # Fail-closed: a scope with no in_scope must refuse to load.
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write("program: empty\nin_scope: []\n")
        empty_path = fh.name
    try:
        load_scope(empty_path)
    except ScopeError:
        pass
    else:
        raise AssertionError("expected ScopeError for empty in_scope")


def _run():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
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
