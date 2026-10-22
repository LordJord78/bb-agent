"""Scope Guard — the gatekeeper every host must pass before any tool sees it.

This is the security-critical core of the pipeline. Its rules are deliberately
strict and fail-closed:

  * ``out_of_scope`` ALWAYS beats ``in_scope``. If a host matches both, it is
    rejected.
  * A host matching nothing in ``in_scope`` is rejected. Silence is "no".
  * The wildcard ``*.example.com`` matches strict subdomains only
    (``a.example.com``, ``a.b.example.com``) and NEVER the apex ``example.com``.
    If the apex is authorized it must be listed explicitly. This avoids
    accidentally widening scope.
  * Lookalikes never match: ``*.example.com`` rejects ``evil-example.com`` and
    ``example.com.evil.com``.
  * Missing rules-of-engagement flags default to the SAFE value:
    ``automation_allowed`` / ``active_testing_allowed`` default to False (refuse),
    ``ai_disclosure_required`` defaults to True (over-disclose), and
    ``rate_limit_rps`` defaults to a low 2.

Nothing here sends network traffic. It only decides what is allowed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RATE_LIMIT_RPS = 2


class ScopeError(Exception):
    """The scope file is missing, malformed, or internally invalid."""


class ScopeRefusal(Exception):
    """The program's rules of engagement forbid the requested action.

    Raising this is a hard stop: the caller must not proceed.
    """


# --------------------------------------------------------------------------- #
# Host normalization and matching
# --------------------------------------------------------------------------- #
def normalize_host(raw: object) -> str:
    """Reduce any host-ish string to a bare, comparable hostname.

    Strips scheme, userinfo, path, a trailing port, surrounding whitespace, a
    trailing dot, and lowercases. Defensive against tools that emit URLs where
    we expect hostnames. Returns "" for anything empty.
    """
    if raw is None:
        return ""
    h = str(raw).strip().lower()
    if not h:
        return ""
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/", 1)[0]          # drop any path
    if "@" in h:                    # drop userinfo
        h = h.split("@", 1)[1]
    if h.count(":") == 1:           # drop host:port (leave IPv6 literals alone)
        h = h.split(":", 1)[0]
    return h.rstrip(".")


def _match(host: str, pattern: object, apex_ok: bool = False) -> bool:
    """True if a normalized ``host`` matches a single scope ``pattern``.

    ``*``            matches everything (use sparingly; a program-wide wildcard).
    ``*.base``       matches strict subdomains of ``base``. It covers the apex
                     ``base`` only when ``apex_ok`` is set (per-program opt-in).
    anything else    is an exact hostname match.
    """
    pat = normalize_host(pattern) if pattern != "*" else "*"
    if not pat:
        return False
    if pat == "*":
        return True
    if pat.startswith("*."):
        base = pat[2:]
        if not base:
            return False
        # endswith("." + base) covers strict subdomains; the apex needs opt-in.
        return host.endswith("." + base) or (apex_ok and host == base)
    return host == pat


def host_in_scope(host: object, scope: dict) -> bool:
    """True if ``host`` is authorized: in ``in_scope`` and not ``out_of_scope``.

    ``out_of_scope`` is checked first and always wins. Denial wildcards stay
    strict (they never need the apex opt-in). A wildcard in ``in_scope`` covers
    the apex only if the program sets ``wildcard_includes_apex: true``.
    """
    h = normalize_host(host)
    if not h:
        return False
    for pattern in scope.get("out_of_scope") or []:
        if _match(h, pattern):
            return False
    apex_ok = bool(scope.get("wildcard_includes_apex", False))
    for pattern in scope.get("in_scope") or []:
        if _match(h, pattern, apex_ok=apex_ok):
            return True
    return False


def scope_filter(host_list: Iterable[object], scope: dict) -> list[str]:
    """Return the in-scope hosts from ``host_list``, normalized and deduped.

    This is the single choke point: no tool should receive a host that has not
    passed through here. Order of first appearance is preserved.
    """
    seen: set[str] = set()
    allowed: list[str] = []
    for raw in host_list:
        h = normalize_host(raw)
        if not h or h in seen:
            continue
        if host_in_scope(h, scope):
            seen.add(h)
            allowed.append(h)
    return allowed


# --------------------------------------------------------------------------- #
# Rules-of-engagement gates (hard stops)
# --------------------------------------------------------------------------- #
def assert_automation_allowed(scope: dict) -> None:
    """Hard-refuse if the program does not allow automation at all."""
    if not scope.get("automation_allowed", False):
        raise ScopeRefusal(
            f"automation_allowed is false for program "
            f"'{scope.get('program', '?')}'. The pipeline refuses to run active "
            f"tools against it. Work this program manually."
        )


def assert_active_testing_allowed(scope: dict) -> None:
    """Hard-refuse active tools (nuclei/naabu/katana) when not permitted.

    This is the code-level half of gate G2; the per-run human "yes" is enforced
    separately by the stage scripts.
    """
    if not scope.get("active_testing_allowed", False):
        raise ScopeRefusal(
            f"active_testing_allowed is false for program "
            f"'{scope.get('program', '?')}'. Active tools are refused; passive "
            f"recon only."
        )


# --------------------------------------------------------------------------- #
# Loading and validation
# --------------------------------------------------------------------------- #
def _resolve_scope_path(program_or_path: str) -> Path:
    p = Path(program_or_path)
    if p.suffix in (".yaml", ".yml") and p.exists():
        return p
    candidate = ROOT / "targets" / program_or_path / "scope.yaml"
    if candidate.exists():
        return candidate
    raise ScopeError(
        f"No scope file for '{program_or_path}'. Expected a .yaml path or "
        f"targets/<program>/scope.yaml (looked at {candidate})."
    )


def load_scope(program_or_path: str) -> dict:
    """Load, validate, and normalize a program's ``scope.yaml``.

    Applies fail-closed defaults and guarantees ``in_scope`` / ``out_of_scope``
    are lists. Raises :class:`ScopeError` on anything structurally wrong.
    """
    path = _resolve_scope_path(program_or_path)
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ScopeError(f"{path} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ScopeError(f"{path} must be a YAML mapping, got {type(raw).__name__}.")

    scope: dict = dict(raw)
    scope.setdefault("program", path.parent.name)

    for key in ("in_scope", "out_of_scope"):
        value = scope.get(key) or []
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list):
            raise ScopeError(f"{path}: '{key}' must be a list, got {type(value).__name__}.")
        scope[key] = [normalize_host(v) for v in value if normalize_host(v)]

    if not scope["in_scope"]:
        raise ScopeError(
            f"{path}: 'in_scope' is empty. A program with no authorized hosts "
            f"cannot be scanned; refusing to load an open-ended scope."
        )

    # Fail-closed defaults for the rules-of-engagement flags.
    scope["automation_allowed"] = bool(scope.get("automation_allowed", False))
    scope["active_testing_allowed"] = bool(scope.get("active_testing_allowed", False))
    scope["ai_disclosure_required"] = bool(scope.get("ai_disclosure_required", True))
    # Conservative default: a wildcard does NOT cover the apex. A program whose
    # RoE says otherwise opts in per-program with wildcard_includes_apex: true.
    scope["wildcard_includes_apex"] = bool(scope.get("wildcard_includes_apex", False))

    rps = scope.get("rate_limit_rps", DEFAULT_RATE_LIMIT_RPS)
    try:
        rps = float(rps)
    except (TypeError, ValueError):
        rps = DEFAULT_RATE_LIMIT_RPS
    if rps <= 0:
        rps = DEFAULT_RATE_LIMIT_RPS
    scope["rate_limit_rps"] = rps

    return scope


def format_scope(scope: dict) -> str:
    """Human-readable summary printed back to the operator for gate G1."""
    lines = [
        f"program:                {scope.get('program', '?')}",
        f"in_scope:               {scope.get('in_scope', [])}",
        f"out_of_scope:           {scope.get('out_of_scope', [])}",
        f"rate_limit_rps:         {scope.get('rate_limit_rps')}",
        f"automation_allowed:     {scope.get('automation_allowed')}",
        f"active_testing_allowed: {scope.get('active_testing_allowed')}",
        f"ai_disclosure_required: {scope.get('ai_disclosure_required')}",
        f"wildcard_includes_apex: {scope.get('wildcard_includes_apex')}",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("usage: python3 lib/scope_guard.py <program|path-to-scope.yaml>", file=sys.stderr)
        raise SystemExit(2)
    try:
        parsed = load_scope(sys.argv[1])
    except ScopeError as exc:
        print(f"scope error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    print(format_scope(parsed))
