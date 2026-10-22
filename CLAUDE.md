# bb-agent — guardrails for any Claude Code session in this repo

This is a **semi-autonomous bug-bounty recon/triage assistant for AUTHORIZED
testing only**. The operator points it only at programs they are enrolled in,
with scope they paste themselves. Your job is to build and run the *pipeline*,
never to freelance an attack. These rules are non-negotiable; honor them in
code, not just docs.

## The five guardrails

1. **Scope Guard is the center.** Everything routes through
   `lib/scope_guard.py`. `out_of_scope` always beats `in_scope`; wildcards match
   strict subdomains only (never the apex); unknown hosts are rejected. No tool
   may receive a host that has not passed `scope_filter`. If
   `automation_allowed` is false, active tooling is hard-refused.

2. **Three human gates.**
   - **G1 (scope):** print parsed scope; the operator confirms before any network call.
   - **G2 (active testing):** nuclei/naabu/katana/anything sending crafted
     requests needs an explicit per-run "yes" AND `active_testing_allowed: true`.
     Passive recon (crt.sh, passive subfinder) may run without G2.
   - **G3 (submission):** NEVER submit anywhere. Write drafts to `reports/` and stop.

3. **Politeness always on.** Honor `rate_limit_rps` on every active tool; global
   concurrency caps; jitter; the `BB_HALT=1` kill-switch every stage checks;
   identifying User-Agent where tools allow it.

4. **No destructive / out-of-policy actions, ever:** no DoS/stress, no data
   exfiltration beyond minimal proof, no touching other users' data, no social
   engineering, no automated account creation, no CAPTCHA solving. If proving a
   finding would need any of these, STOP and flag it for the operator.

5. **AI disclosure.** If `ai_disclosure_required`, every report draft carries the
   "AI-assisted, human-reviewed" note and a `[HUMAN REVIEW REQUIRED]` banner
   until the operator clears it.

## Inference routing

Deterministic work is CODE, not an LLM. Stage 4a (normalize/dedupe/threshold/
group) is pure Python and must stay reproducible. Only stage 4b (fuzzy ranking)
and stages 5–6 use a model, selected by `BB_INFERENCE_BACKEND`
(default `claude`; `local`/`auto` are optional and never auto-pull a model on
this box). 4b must schema-validate its output and retry once; never pass a
malformed object downstream. Log Claude `total_cost_usd` to `logs/cost.log`.

## Defaults

- `BB_DRY_RUN=1` by default — stages stub all network tools. Real runs set it to
  `0` explicitly, per program, after G1/G2.
- During development: `example.com` placeholders only. Do not scan a real host
  while building or testing.
