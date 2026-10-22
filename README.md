# bb-agent

A **semi-autonomous bug-bounty recon & triage assistant for AUTHORIZED testing
only.** You point it only at programs you are enrolled in, using scope you paste
yourself. It is draft-only and read-mostly: it enumerates, probes (within the
rules you give it), triages, and drafts reports for your review. **It never
submits anything.**

`CLAUDE.md` holds the full guardrail contract; this is the operator runbook.

---

## Runbook — a real program, in the safe order

Do these in order. Nothing touches the network until step 3, and you expand one
stage at a time.

**1. Write the scope.** Create `targets/<program>/scope.yaml` (copy
`targets/example-program/scope.yaml`) and fill every field from the program's
rules-of-engagement page — see [the field map](#reading-a-roe-page-into-scopeyaml).

**2. Confirm scope (gate G1).**
```bash
make init P=<program>        # prints the parsed scope; no network
```
Read it back. If anything is wrong, fix the YAML and re-run. Nothing has been
contacted. Optionally `bin/gate-check <program>` to see whether the RoE permits
active testing at all.

**3. Passive recon first** (no active traffic, no G2):
```bash
BB_DRY_RUN=0 make passive P=<program>
# review recon/<program>/hosts.txt — these are the in-scope hosts kept
```

**4. Then active probing — one stage at a time.** Each active stage echoes the
plan and makes you **type the exact program name** to proceed (gate G2):
```bash
BB_DRY_RUN=0 make probe P=<program>   # stage 2: httpx (title/tech/status)
# review recon/<program>/probed.jsonl and alive.txt, then:
BB_DRY_RUN=0 make recon P=<program>   # stage 3: crawl + top-ports
```
Do **not** un-stub all stages at once. Watch G1 and the G2 prompt actually fire
before enabling the next stage. Stages are idempotent and use `anew`, so re-runs
surface only newly-seen items.

**5. Triage, analyze, draft** (no target traffic — these reason over what was
collected; stage 4 triage/nuclei feeds `findings/shortlist.json`):
```bash
make rank    P=<program>     # 4b: cluster + rank (model, schema-validated)
make analyze P=<program>     # 5:  exploitability + non-destructive repro outline
make report  P=<program>     # 6:  draft per CONFIRMED candidate -> reports/, then STOP
```
Review the drafts in `reports/<program>/`. **Submitting is 100% manual, by you**
(gate G3).

> First, prove the whole flow offline: `make test` (unit tests) and
> `make dry-run` (stages 0–6 on example.com, every network tool stubbed).

---

## Reading a RoE page into scope.yaml

| field | where it comes from on the policy page |
|---|---|
| `in_scope` | the "In scope" / "Targets" list. Wildcards (`*.example.com`) cover **strict subdomains only** — list the apex (`example.com`) separately unless you set `wildcard_includes_apex`. |
| `out_of_scope` | the "Out of scope" / excluded-assets list. **These always win** over `in_scope`. |
| `rate_limit_rps` | any stated request-rate ceiling ("no more than N req/s", "no aggressive scanning"). If unstated, leave the default **2** or go lower. |
| `automation_allowed` | whether automated tooling is permitted at all. If the page forbids automation, set `false` — **the pipeline then refuses every active stage** for this program and tells you to work it manually. |
| `active_testing_allowed` | whether sending requests to targets is allowed (vs. passive-only / report-from-public-data programs). Gates stages 2–3. |
| `ai_disclosure_required` | whether submissions must disclose AI assistance. When `true`, every report draft carries the AI-assisted note. Many programs now require this. |
| `wildcard_includes_apex` | **per-program opt-in.** Default (absent/false) is conservative: a wildcard does **not** include the bare apex. Set `true` only if this program's wording says it does — never a global default. |
| `notes` | paste the relevant RoE text verbatim, so any reviewer can see exactly what was authorized. |

Fail-closed defaults: if a flag is omitted, `automation_allowed` and
`active_testing_allowed` default to **false**, `ai_disclosure_required` to
**true**, and `rate_limit_rps` to **2**. An empty `in_scope` is refused.

---

## The three gates (and why)

1. **G1 — scope confirmation.** `make init` prints the parsed scope and stops so
   you verify it *before* any network call. *Why:* scope mistakes (a stray
   wildcard, a stale target) are how testing strays out of bounds — catch them
   while it's still just a file.
2. **G2 — typed active-testing confirmation.** Every stage that sends crafted
   requests (httpx/katana/naabu, later nuclei) requires `active_testing_allowed:
   true` **and** an explicit per-run "yes": it echoes the plan (program, in-scope
   target count, `rate_limit_rps`) and you must type the exact program name at a
   prompt read from `/dev/tty`. No env var, flag, or piped stdin can satisfy it;
   anything but the exact name aborts with no traffic; it only triggers at
   `BB_DRY_RUN=0`. *Why:* sending real traffic to someone else's systems is the
   point of no return — it should take a deliberate, un-scriptable human act.
3. **G3 — never submit.** The agent writes drafts to `reports/` and stops;
   submission is manual. *Why:* a human must own every word of what gets filed,
   and must confirm each finding is real, in-scope, and proven within policy.

**No destructive or out-of-policy actions, ever:** no DoS/stress, no data
exfiltration beyond minimal proof, no touching other users' data, no social
engineering, account creation, or CAPTCHA solving. If proving a finding would
require any of these, stage 5 flags it (`out_of_policy_to_prove`) and does not
auto-confirm it — you handle it manually.

---

## Safety controls

- **`BB_DRY_RUN` (default `1`).** While set, every network tool is stubbed with a
  fixture and nothing is contacted. A real run sets `BB_DRY_RUN=0` explicitly,
  per program, after G1/G2.
- **`BB_HALT=1` kill-switch.** `export BB_HALT=1` and every stage aborts (exit
  42) at entry and between items. Unset to resume.
- **Rate limiting + politeness.** Every active tool is capped at the program's
  `rate_limit_rps`, with small jitter and an identifying User-Agent.
- **Target data is never committed.** `recon/`, `findings/`, `reports/`, and
  `logs/` are git-ignored (only `.gitkeep` is tracked), so enumerated hosts,
  drafts, and logs for a real program stay local.

---

## Pipeline stages

| stage | make target | traffic | gate |
|---|---|---|---|
| 0 init | `init` | none | prints G1 |
| 1 passive | `passive` | none (third-party + DNS) | — |
| 2 probe (httpx) | `probe` | active, rate-limited | G2 + `active_testing_allowed` |
| 3 recon (katana+naabu) | `recon` | active, rate-limited | G2 + `active_testing_allowed` |
| 4a munge | `munge` | none (pure code) | — |
| 4b rank | `rank` | local/Claude inference | — (reasons over findings) |
| 5 analyze | `analyze` | local/Claude inference | — (reasons over findings) |
| 6 report | `report` | none (deterministic render) | drafts only; **G3** |

Stages 4b and 5 schema-validate their model output and retry once, with a
deterministic fallback so a run never hard-fails offline. Stage 6 renders drafts
deterministically from the reviewed stage-5 analysis (it adds no fresh prose of
its own) for **confirmed** candidates only.

**Inference:** deterministic work (stage 4a) is plain Python. Only 4b/5 use a
model, chosen by `BB_INFERENCE_BACKEND` (default `claude`; `local`/`auto` use a
local Ollama model via `bin/llm` but never auto-pull one). Claude cost per run is
logged to `logs/cost.log`.

## Layout

```
targets/<program>/scope.yaml   you write this, per program
recon/<program>/               enumerated hosts, probes, endpoints (git-ignored)
findings/                      stage-4a shortlist + 4b/5 JSON (git-ignored)
reports/                       stage-6 drafts, for your review (git-ignored)
logs/                          per-stage logs + cost.log (git-ignored)
lib/                           scope_guard.py, munge.py, rank.py, analyze.py, report.py, common.sh
bin/                           stage scripts, gate-check, llm
```
