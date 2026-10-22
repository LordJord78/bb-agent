"""Stage 4b — fuzzy ranking of the stage-4a shortlist.

Takes the deterministic per-asset grouping from 4a and produces a ranked list of
candidate clusters: related findings grouped across assets, each with a severity
view, a confidence, a likely-false-positive flag, and a short rationale.

The model only ever sees the already-shrunk 4a output (lean context). Its JSON is
SCHEMA-VALIDATED and retried once; a malformed object is never passed downstream.
A deterministic fallback (no model) produces a valid ranking from the 4a data so
the stage is exercisable offline and can't hard-fail a run.
"""

from __future__ import annotations

import json
import re

SEVERITIES = ("info", "low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


class RankError(Exception):
    """The model did not return a schema-valid ranking (even after one retry)."""


# --------------------------------------------------------------------------- #
# Schema validation (dependency-free)
# --------------------------------------------------------------------------- #
def validate_ranking(obj) -> list[str]:
    """Return a list of schema errors; empty list means valid."""
    errs: list[str] = []
    if not isinstance(obj, dict):
        return ["top-level value is not an object"]
    if obj.get("version") != 1:
        errs.append("version must be 1")
    if not isinstance(obj.get("program"), str) or not obj["program"]:
        errs.append("program must be a non-empty string")
    cands = obj.get("candidates")
    if not isinstance(cands, list):
        return errs + ["candidates must be a list"]
    for i, c in enumerate(cands):
        p = f"candidates[{i}]"
        if not isinstance(c, dict):
            errs.append(f"{p} is not an object")
            continue
        if not isinstance(c.get("id"), str) or not c["id"]:
            errs.append(f"{p}.id must be a non-empty string")
        if not isinstance(c.get("title"), str) or not c["title"]:
            errs.append(f"{p}.title must be a non-empty string")
        if c.get("severity") not in SEVERITIES:
            errs.append(f"{p}.severity must be one of {SEVERITIES}")
        if c.get("confidence") not in CONFIDENCES:
            errs.append(f"{p}.confidence must be one of {CONFIDENCES}")
        if not isinstance(c.get("likely_false_positive"), bool):
            errs.append(f"{p}.likely_false_positive must be a boolean")
        for key in ("hosts", "templates"):
            v = c.get(key)
            if not isinstance(v, list) or not v or not all(isinstance(x, str) for x in v):
                errs.append(f"{p}.{key} must be a non-empty list of strings")
        if not isinstance(c.get("rationale"), str) or not c["rationale"]:
            errs.append(f"{p}.rationale must be a non-empty string")
    return errs


# --------------------------------------------------------------------------- #
# Prompt construction + model-output parsing
# --------------------------------------------------------------------------- #
_SCHEMA_HINT = """Return ONLY a JSON object, no prose, matching exactly:
{
  "version": 1,
  "program": "<program>",
  "candidates": [
    {
      "id": "<short-stable-id>",
      "title": "<short human title>",
      "severity": "info|low|medium|high|critical",
      "confidence": "low|medium|high",
      "likely_false_positive": true|false,
      "hosts": ["host", ...],
      "templates": ["template-id", ...],
      "rationale": "<one or two sentences>"
    }
  ]
}
Rank candidates most-actionable first. Cluster the same issue across hosts into
one candidate. Only use hosts/templates that appear in the input."""


def build_prompt(shortlist: dict) -> str:
    assets = shortlist.get("assets", {})
    return (
        "You are triaging authorized bug-bounty scan output. Below is a "
        "deterministic, already-deduplicated grouping of findings by asset for "
        f"program '{shortlist.get('program')}'. Cluster related findings across "
        "assets, judge likely false positives, and rank by how worth a human's "
        "time each cluster is.\n\n"
        f"FINDINGS BY ASSET:\n{json.dumps(assets, indent=2)}\n\n" + _SCHEMA_HINT
    )


def parse_model_json(text: str):
    """Pull a JSON object out of model text (tolerates code fences / wrapping)."""
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
    return None


def rank(shortlist: dict, call_llm, max_retries: int = 1) -> dict:
    """Prompt the model, validate, retry once, or raise RankError.

    ``call_llm`` is a callable ``str -> str`` (so tests can inject a fake).
    """
    prompt = build_prompt(shortlist)
    last_errs: list[str] = ["no response"]
    for attempt in range(max_retries + 1):
        p = prompt if attempt == 0 else (
            prompt + "\n\nYour previous reply was not valid. Problems: "
            + "; ".join(last_errs) + "\nReturn ONLY the JSON object."
        )
        obj = parse_model_json(call_llm(p) or "")
        if obj is None:
            last_errs = ["output was not parseable JSON"]
            continue
        last_errs = validate_ranking(obj)
        if not last_errs:
            obj.setdefault("program", shortlist.get("program"))
            obj["source"] = "model"
            return obj
    raise RankError("model did not return schema-valid JSON: " + "; ".join(last_errs))


# --------------------------------------------------------------------------- #
# Deterministic fallback (no model) — valid by construction
# --------------------------------------------------------------------------- #
def deterministic_ranking(shortlist: dict) -> dict:
    """Group 4a findings by template across assets. No judgment, always valid."""
    clusters: dict[str, dict] = {}
    for host, findings in (shortlist.get("assets") or {}).items():
        for f in findings:
            t = f["template"]
            c = clusters.setdefault(t, {
                "id": t,
                "title": f.get("name", t),
                "severity": f["severity"],
                "confidence": "low",
                "likely_false_positive": False,
                "hosts": [],
                "templates": [t],
                "rationale": "Deterministic fallback: grouped by template across assets; no model judgment applied.",
            })
            if host not in c["hosts"]:
                c["hosts"].append(host)
            if _SEV_RANK.get(f["severity"], 0) > _SEV_RANK.get(c["severity"], 0):
                c["severity"] = f["severity"]
    ordered = sorted(clusters.values(), key=lambda c: (-_SEV_RANK.get(c["severity"], 0), c["id"]))
    return {
        "version": 1,
        "program": shortlist.get("program"),
        "source": "deterministic-fallback",
        "candidates": ordered,
    }


if __name__ == "__main__":
    import subprocess
    import sys

    args = sys.argv[1:]
    if args[:1] == ["--deterministic"] and len(args) == 2:
        shortlist = json.load(open(args[1]))
        json.dump(deterministic_ranking(shortlist), sys.stdout, indent=2)
        sys.stdout.write("\n")
        raise SystemExit(0)

    if args[:1] == ["--llm"] and len(args) == 3:
        llm_path, infile = args[1], args[2]
        shortlist = json.load(open(infile))

        def call_llm(prompt: str) -> str:
            res = subprocess.run([llm_path], input=prompt, capture_output=True, text=True)
            return res.stdout

        try:
            result = rank(shortlist, call_llm)
        except RankError as exc:
            print(f"rank error: {exc}", file=sys.stderr)
            raise SystemExit(1)
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
        raise SystemExit(0)

    print("usage: rank.py --deterministic <shortlist.json>\n"
          "       rank.py --llm <llm-cmd> <shortlist.json>", file=sys.stderr)
    raise SystemExit(2)
