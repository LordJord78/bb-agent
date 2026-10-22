"""Stage 5 — exploitability analysis of the ranked candidates.

For each candidate from stage 4b, produce a structured analysis: whether it is
in scope and plausibly exploitable, a HIGH-LEVEL non-destructive reproduction
outline, a severity view, whether it is confirmed enough to draft a report, and
— critically — whether proving it would require any out-of-policy action (DoS,
touching other users' data, exfiltration beyond minimal proof, etc.). If it
would, the candidate is flagged for the human and NOT auto-confirmed.

Model output is schema-validated and retried once; a deterministic fallback
confirms nothing (offline we cannot assess exploitability) and flags everything
for manual analysis. No network here — it reasons over collected findings only.
"""

from __future__ import annotations

import json
import re

SEVERITIES = ("info", "low", "medium", "high", "critical")


class AnalyzeError(Exception):
    pass


def validate_analysis(obj) -> list[str]:
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
            errs.append(f"{p} is not an object"); continue
        if not isinstance(c.get("id"), str) or not c["id"]:
            errs.append(f"{p}.id must be a non-empty string")
        a = c.get("analysis")
        if not isinstance(a, dict):
            errs.append(f"{p}.analysis must be an object"); continue
        if not isinstance(a.get("exploitability"), str) or not a["exploitability"]:
            errs.append(f"{p}.analysis.exploitability must be a non-empty string")
        if not isinstance(a.get("in_scope"), bool):
            errs.append(f"{p}.analysis.in_scope must be a boolean")
        if a.get("severity") not in SEVERITIES:
            errs.append(f"{p}.analysis.severity must be one of {SEVERITIES}")
        ro = a.get("reproduction_outline")
        if not isinstance(ro, list) or not ro or not all(isinstance(x, str) for x in ro):
            errs.append(f"{p}.analysis.reproduction_outline must be a non-empty list of strings")
        for b in ("confirmed", "needs_manual_proof", "out_of_policy_to_prove"):
            if not isinstance(a.get(b), bool):
                errs.append(f"{p}.analysis.{b} must be a boolean")
        if not isinstance(a.get("notes"), str):
            errs.append(f"{p}.analysis.notes must be a string")
    return errs


_SCHEMA_HINT = """Return ONLY a JSON object, no prose, matching exactly:
{
  "version": 1,
  "program": "<program>",
  "candidates": [
    {
      "id": "<candidate id from input>",
      "title": "<title>",
      "hosts": ["host", ...],
      "templates": ["template-id", ...],
      "analysis": {
        "exploitability": "<concise judgment of whether/how this is exploitable in scope>",
        "in_scope": true|false,
        "severity": "info|low|medium|high|critical",
        "cvss_vector": "<CVSS v3.1 vector or empty string>",
        "reproduction_outline": ["<high-level, NON-destructive step>", ...],
        "confirmed": true|false,
        "needs_manual_proof": true|false,
        "out_of_policy_to_prove": true|false,
        "notes": "<short notes, incl. impact>"
      }
    }
  ]
}
Rules: the reproduction outline must be HIGH-LEVEL and non-destructive. If
proving the issue would require DoS, accessing other users' data, exfiltration
beyond minimal proof, account creation, social engineering, or CAPTCHA solving,
set out_of_policy_to_prove=true, needs_manual_proof=true, and confirmed=false,
and say so in notes. Only set confirmed=true for a clearly in-scope issue whose
minimal proof is within policy."""


def build_prompt(ranked: dict) -> str:
    return (
        "You are analyzing ranked findings from an AUTHORIZED bug-bounty scan "
        f"for program '{ranked.get('program')}'. For each candidate, assess "
        "exploitability strictly within scope and policy.\n\n"
        f"CANDIDATES:\n{json.dumps(ranked.get('candidates', []), indent=2)}\n\n"
        + _SCHEMA_HINT
    )


def parse_model_json(text: str):
    text = (text or "").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if not m:
            return None
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return None


def analyze(ranked: dict, call_llm, max_retries: int = 1) -> dict:
    prompt = build_prompt(ranked)
    last = ["no response"]
    for attempt in range(max_retries + 1):
        p = prompt if attempt == 0 else (
            prompt + "\n\nYour previous reply was invalid. Problems: "
            + "; ".join(last) + "\nReturn ONLY the JSON object."
        )
        obj = parse_model_json(call_llm(p))
        if obj is None:
            last = ["output was not parseable JSON"]; continue
        last = validate_analysis(obj)
        if not last:
            obj.setdefault("program", ranked.get("program"))
            obj["source"] = "model"
            return obj
    raise AnalyzeError("model did not return schema-valid JSON: " + "; ".join(last))


def deterministic_analysis(ranked: dict) -> dict:
    """Offline: confirm nothing, flag everything for manual analysis."""
    cands = []
    for c in ranked.get("candidates", []):
        cands.append({
            "id": c["id"],
            "title": c.get("title", c["id"]),
            "hosts": c.get("hosts", []),
            "templates": c.get("templates", []),
            "analysis": {
                "exploitability": "Not assessed offline; a model or human must judge exploitability.",
                "in_scope": True,
                "severity": c.get("severity", "info"),
                "cvss_vector": "",
                "reproduction_outline": ["Manual verification required (deterministic fallback did not analyze)."],
                "confirmed": False,
                "needs_manual_proof": True,
                "out_of_policy_to_prove": False,
                "notes": "Deterministic fallback: no exploitability judgment was made.",
            },
        })
    return {"version": 1, "program": ranked.get("program"),
            "source": "deterministic-fallback", "candidates": cands}


if __name__ == "__main__":
    import subprocess
    import sys

    args = sys.argv[1:]
    if args[:1] == ["--deterministic"] and len(args) == 2:
        json.dump(deterministic_analysis(json.load(open(args[1]))), sys.stdout, indent=2)
        sys.stdout.write("\n"); raise SystemExit(0)
    if args[:1] == ["--llm"] and len(args) == 3:
        llm_path, infile = args[1], args[2]
        ranked = json.load(open(infile))

        def call_llm(prompt: str) -> str:
            return subprocess.run([llm_path], input=prompt, capture_output=True, text=True).stdout

        try:
            json.dump(analyze(ranked, call_llm), sys.stdout, indent=2); sys.stdout.write("\n")
        except AnalyzeError as exc:
            print(f"analyze error: {exc}", file=sys.stderr); raise SystemExit(1)
        raise SystemExit(0)
    print("usage: analyze.py --deterministic <ranked.json>\n"
          "       analyze.py --llm <llm-cmd> <ranked.json>", file=sys.stderr)
    raise SystemExit(2)
