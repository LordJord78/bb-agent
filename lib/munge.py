"""Stage 4a — deterministic munge. No model, no network.

Takes raw scanner output (nuclei-style JSON lines), and:
  * parses each finding into a normalized record (template, host, severity, location),
  * re-applies the Scope Guard as a safety net (defense in depth — nothing
    out-of-scope should survive even if an earlier stage slipped),
  * drops findings below a severity threshold (info is dropped by default),
  * deduplicates on a NORMALIZED key so near-duplicates collapse,
  * groups the survivors by asset (host).

Output is a compact JSON object that stage 4b consumes. This must be instant
and 100% reproducible; malformed input lines are counted and skipped, never
allowed to crash the run or pass through unparsed.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.scope_guard import load_scope, normalize_host  # noqa: E402

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _normalize_location(raw: str) -> str:
    """Collapse a matched URL/location to a stable dedupe-friendly form."""
    loc = (raw or "").strip().lower()
    if not loc:
        return ""
    if "://" in loc:
        scheme, rest = loc.split("://", 1)
    else:
        scheme, rest = "", loc
    host_part, _, path = rest.partition("/")
    host_part = host_part.split("@")[-1]
    if host_part.count(":") == 1:                       # strip default ports
        h, port = host_part.split(":", 1)
        if port in ("80", "443"):
            host_part = h
    path = path.split("?", 1)[0].rstrip("/")            # drop query, trailing slash
    rebuilt = host_part + ("/" + path if path else "")
    return rebuilt


def _parse_nuclei_line(obj: dict) -> dict | None:
    """Map one nuclei JSON object to our normalized record, or None if unusable."""
    template = obj.get("template-id") or obj.get("templateID") or obj.get("template")
    info = obj.get("info") or {}
    severity = (info.get("severity") or obj.get("severity") or "unknown").lower()
    host = normalize_host(obj.get("host") or obj.get("ip") or "")
    location = _normalize_location(obj.get("matched-at") or obj.get("matched") or obj.get("host") or "")
    name = info.get("name") or template
    if not template or not host:
        return None
    return {
        "template": str(template),
        "name": str(name),
        "host": host,
        "severity": severity,
        "location": location,
    }


def munge(lines, scope: dict, severity_min: str = "low") -> dict:
    min_rank = SEVERITY_ORDER.get(severity_min, 1)
    in_scope_hosts = set(scope.get("in_scope", []))  # for reporting only
    from lib.scope_guard import host_in_scope

    parsed = 0
    skipped_malformed = 0
    dropped_out_of_scope = 0
    dropped_below_threshold = 0
    deduped = 0

    seen: set[tuple] = set()
    by_asset: dict[str, list[dict]] = defaultdict(list)

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            skipped_malformed += 1
            continue
        rec = _parse_nuclei_line(obj) if isinstance(obj, dict) else None
        if rec is None:
            skipped_malformed += 1
            continue
        parsed += 1

        # Safety net: never let an out-of-scope host through, whatever upstream did.
        if not host_in_scope(rec["host"], scope):
            dropped_out_of_scope += 1
            continue

        rank = SEVERITY_ORDER.get(rec["severity"], 0)
        if rank < min_rank:
            dropped_below_threshold += 1
            continue

        key = (rec["template"], rec["host"], rec["location"], rec["severity"])
        if key in seen:
            deduped += 1
            continue
        seen.add(key)
        by_asset[rec["host"]].append(rec)

    # Sort each asset's findings by severity (desc) then template for stable output.
    for host in by_asset:
        by_asset[host].sort(key=lambda r: (-SEVERITY_ORDER.get(r["severity"], 0), r["template"]))

    assets = dict(sorted(by_asset.items(), key=lambda kv: (-len(kv[1]), kv[0])))
    return {
        "program": scope.get("program"),
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "severity_min": severity_min,
        "counts": {
            "parsed": parsed,
            "skipped_malformed": skipped_malformed,
            "dropped_out_of_scope": dropped_out_of_scope,
            "dropped_below_threshold": dropped_below_threshold,
            "deduplicated": deduped,
            "surviving": sum(len(v) for v in assets.values()),
            "assets": len(assets),
            "in_scope_rules": len(in_scope_hosts),
        },
        "assets": assets,
    }


def _read_inputs(paths: list[str]):
    if not paths or paths == ["-"]:
        yield from sys.stdin
        return
    for p in paths:
        if p == "-":
            yield from sys.stdin
        else:
            yield from Path(p).read_text().splitlines()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Stage 4a deterministic munge (no model).")
    ap.add_argument("--program", required=True, help="program name or path to scope.yaml")
    ap.add_argument("--severity-min", default="low",
                    choices=list(SEVERITY_ORDER), help="drop findings below this (default: low)")
    ap.add_argument("--keep-info", action="store_true", help="shortcut for --severity-min info")
    ap.add_argument("inputs", nargs="*", help="nuclei JSONL files, or - for stdin")
    args = ap.parse_args(argv)

    scope = load_scope(args.program)
    sev_min = "info" if args.keep_info else args.severity_min
    result = munge(_read_inputs(args.inputs), scope, sev_min)
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
