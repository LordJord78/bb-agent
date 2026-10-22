# bb-agent

A **semi-autonomous bug-bounty recon & triage assistant for AUTHORIZED testing
only.** You point it only at programs you are enrolled in, using scope you paste
yourself. It is draft-only and read-mostly: it enumerates, probes (within the
rules you give it), triages, and drafts reports for your review. It never
submits anything.

Read [`CLAUDE.md`](CLAUDE.md) for the full guardrail contract. The short version
is below.

## The three gates

1. **G1 — scope.** Before any network call, the pipeline prints the parsed scope
   and stops. You confirm it is correct and current. (`make init P=<program>`.)
2. **G2 — active testing.** Anything that sends crafted/HTTP requests to the
   target (httpx probe, crawl, port scan, nuclei) requires both
   `active_testing_allowed: true` in the program's scope **and** your explicit
   per-run "yes". That "yes" is a typed confirmation: the stage echoes the plan
   (program, number of in-scope targets, `rate_limit_rps`) and you must type the
   exact program name at the prompt to proceed — anything else aborts with no
   traffic. It is read from the terminal (`/dev/tty`), so no env var, flag, or
   piped stdin can pre-satisfy it, and it only triggers at `BB_DRY_RUN=0`.
   Passive enumeration (cert transparency, passive sources, DNS resolution)
   does not need G2.
3. **G3 — submission.** The agent writes report drafts to `reports/` and stops.
   Submitting a report is 100% manual, done by you.

## The kill switch

`export BB_HALT=1` — every stage checks this at entry and between items and
aborts (exit 42). Unset it to resume. There is also `BB_DRY_RUN` (default `1`):
while set, every network tool is stubbed with a fixture and nothing is
contacted. A real run sets `BB_DRY_RUN=0` explicitly, per program, after G1/G2.

## Adding a program

1. `mkdir -p targets/<program>` and copy the shape of
   [`targets/example-program/scope.yaml`](targets/example-program/scope.yaml).
2. Fill every field from the program's **policy / rules-of-engagement page**:

   | field | where it comes from on the policy page |
   |---|---|
   | `in_scope` | the "In scope" / "Targets" list. Wildcards (`*.example.com`) cover **strict subdomains only** — list the apex (`example.com`) separately unless you also set `wildcard_includes_apex`. |
   | `out_of_scope` | the "Out of scope" / excluded-assets list. These always win. |
   | `rate_limit_rps` | any stated request-rate ceiling ("no more than N req/s", "no aggressive scanning"). If unstated, leave the default **2** or go lower. |
   | `automation_allowed` | whether automated tooling/scanners are permitted at all. If the page forbids automation, set `false` — the pipeline then refuses active tools for this program. |
   | `active_testing_allowed` | whether sending requests to targets is allowed (vs. passive-only / report-from-public-data programs). |
   | `ai_disclosure_required` | whether submissions must disclose AI assistance. Many programs now require this. |
   | `wildcard_includes_apex` | set `true` **only** if this program's wording says a wildcard includes the bare apex. Per-program; never a global default. |
   | `notes` | paste the relevant RoE text verbatim, so a reviewer can see exactly what was authorized. |

3. `make init P=<program>` and read the G1 print-back. If it's wrong, fix the
   file; nothing has touched the network yet.

## Running (first run stays incremental)

```bash
make test                     # unit tests (scope guard + munge)
make dry-run                  # whole flow on example.com, everything stubbed
make init    P=<program>      # G1 scope print-back
gate-check   <program>        # does the RoE allow active testing? (bin/gate-check)

# A real run, one stage at a time — do NOT un-stub everything at once:
BB_DRY_RUN=0 make passive P=<program>   # stage 1: passive only, no G2 needed
#   ...review recon/<program>/hosts.txt...
BB_DRY_RUN=0 make probe   P=<program>   # stage 2: httpx (needs RoE + your G2 yes)
BB_DRY_RUN=0 make recon   P=<program>   # stage 3: crawl + ports (needs RoE + G2)
```

Watch G1 and the G2 gate actually fire on stage 1/2 before enabling more. The
stages are idempotent and use `anew`, so re-runs surface only newly-seen items.

## Pipeline stages

| stage | make target | traffic | gate |
|---|---|---|---|
| 0 init | `init` | none | prints G1 |
| 1 passive | `passive` | none (third-party + DNS) | — |
| 2 probe (httpx) | `probe` | active, rate-limited | G2 + `active_testing_allowed` |
| 3 recon (katana+naabu) | `recon` | active, rate-limited | G2 + `active_testing_allowed` |
| 4a munge | `munge` | none (pure code) | — |
| 4b rank | `rank` | local/Claude inference | — (reasons over collected findings) |
| 5 analyze | `analyze` | local/Claude inference | — (reasons over collected findings) |
| 6 report | `report` | none (deterministic render) | drafts only; **G3** |

Stages 4b and 5 schema-validate their model output and retry once, with a
deterministic fallback so a run never hard-fails offline. Stage 6 renders
drafts deterministically from the reviewed stage-5 analysis (it adds no fresh
prose of its own) for **confirmed** candidates only, each with the
`[HUMAN REVIEW REQUIRED]` banner and — when the program requires it — the
AI-disclosure note. It then stops: submission is manual (G3).

## Inference

Deterministic work (stage 4a: normalize/dedupe/threshold/group) is plain Python.
Only the fuzzy ranking (4b) and analysis/report stages use a model, chosen by
`BB_INFERENCE_BACKEND` (default `claude`). `local`/`auto` use a local Ollama
model via `bin/llm` but never auto-pull one. Claude cost per run is logged to
`logs/cost.log`.

## Layout

```
targets/<program>/scope.yaml   you write this, per program
recon/<program>/               enumerated hosts, probes, endpoints (git-ignored)
findings/                      stage-4a shortlist JSON (git-ignored)
reports/                       stage-6 drafts, for your review (git-ignored)
logs/                          per-stage logs + cost.log (git-ignored)
lib/                           scope_guard.py, munge.py, common.sh
bin/                           stage scripts, gate-check, llm
```

`recon/`, `findings/`, `reports/`, and `logs/` are git-ignored so target data
and drafts are never committed.
