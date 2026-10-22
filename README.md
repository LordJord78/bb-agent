# bb-agent

A semi-autonomous bug-bounty **recon & triage assistant for AUTHORIZED testing only** —
a **scout, not a soldier**. It enumerates hosts, probes them within the rules you give it,
sorts the noise, and drafts reports. Every step that could touch someone else's systems is
human-gated, and **it never submits anything**: you confirm scope, you approve active
traffic, and you reproduce and file findings yourself. Point it only at programs you are
enrolled in, with scope you paste yourself.

New here? The operator field reference is **[OPS-CARD.md](OPS-CARD.md)**. This file is the
reviewer/engineering entry point.

---

## Safety model (read this first)

**The fence.** A program's rules of engagement say what you may touch. You write that into
`targets/<program>/scope.yaml` — the fence. Every host is checked against it before any
tool sees it (`lib/scope_guard.py`). `out_of_scope` always beats `in_scope`; wildcards
cover strict subdomains only (the apex must be listed, unless a per-program
`wildcard_includes_apex: true`); unknown hosts are rejected. If `automation_allowed: false`,
the pipeline refuses every active stage. Fail-closed: missing permission flags default to
the safe value. **When unsure, draw the fence smaller.**

**The three gates.**
- **G1 — confirm scope.** `make init` prints the parsed fence and stops; you verify it
  before any network call. *Catch scope mistakes while it's still just a file.*
- **G2 — approve active testing.** Any stage that sends real requests requires
  `active_testing_allowed: true` **and** a typed confirmation: it echoes the plan (program,
  in-scope target count, rate), and you must type the exact program name at a prompt read
  from `/dev/tty`. No env var, flag, or piped stdin can satisfy it; it only fires at
  `BB_DRY_RUN=0`. *Sending traffic to someone else's systems should take a deliberate,
  un-scriptable human act.*
- **G3 — never submit.** Stage 6 writes a draft stamped `[HUMAN REVIEW REQUIRED]` / NOT
  SUBMITTED and stops. *A human owns every word that gets filed.*

**Switches.** `BB_DRY_RUN=1` is the **default** — every network tool is stubbed, nothing is
contacted; a real run sets `BB_DRY_RUN=0` explicitly, per program, after G1/G2.
`BB_HALT=1` is the kill switch — every stage aborts (exit 42). Active tools are rate-limited
to the program's `rate_limit_rps` with jitter and an identifying User-Agent.

---

## What to review first

The security-critical surface, in priority order:

1. **`lib/scope_guard.py`** + **`tests/test_scope_guard.py`** — the fence. Confirm
   `out_of_scope` beats `in_scope`, `automation_allowed: false` hard-refuses, wildcards
   don't silently include the apex, and lookalikes (`evil-example.com`) are rejected.
2. **G2 typed confirmation** — `bb_confirm_g2` in **`lib/common.sh`**, enforced in
   **`bin/stage2-probe`** / **`bin/stage3-recon`**, proven through a real pty in
   **`tests/test_g2_confirm.py`** (wrong/empty answer aborts with no traffic; exact name
   proceeds). Check it reads `/dev/tty`, not stdin, and honors no bypass.
3. **`.gitignore`** — why `recon/ findings/ reports/ logs/` are excluded: enumerated hosts,
   drafts, and logs for a real program must never be committed (only `.gitkeep` is tracked).
4. **G3 draft-only path** — **`lib/report.py`** / **`bin/stage6-report`**: drafts for
   confirmed candidates only, each with the banner and the NOT-SUBMITTED footer; it writes
   files and stops. Nothing anywhere submits.

---

## File map

| path | what it is |
|---|---|
| `lib/scope_guard.py` | **The fence.** Host/URL matching + the RoE gates. Security-critical. |
| `lib/common.sh` | Shared stage helpers: `BB_HALT`, logging, rate-limit/jitter, scope-filter bridge, and `bb_confirm_g2` (the G2 prompt). |
| `lib/munge.py` | Stage 4a — deterministic normalize/dedupe/threshold/group (no model). |
| `lib/rank.py` | Stage 4b — fuzzy ranking; schema-validated + one retry, deterministic fallback. |
| `lib/analyze.py` | Stage 5 — exploitability analysis; flags out-of-policy proof; same validate/retry/fallback. |
| `lib/report.py` | Stage 6 — renders drafts (banner + AI-disclosure); G3 stop. |
| `bin/stage0-init` | Stage 0 — validate scope, print it back (G1). |
| `bin/stage1-passive` | Stage 1 — passive enum + resolve. No active traffic. |
| `bin/stage2-probe` | Stage 2 — httpx probe. Active: G2 + `active_testing_allowed`. |
| `bin/stage3-recon` | Stage 3 — katana crawl + naabu ports. Active: G2 + `active_testing_allowed`. |
| `bin/stage4b-rank` · `bin/stage5-analyze` · `bin/stage6-report` | Stage wrappers for 4b / 5 / 6. |
| `bin/gate-check` | Does a program's RoE allow active testing? (reads scope; touches nothing). |
| `bin/llm` | Inference backend dispatcher (`BB_INFERENCE_BACKEND`, default `claude`; never auto-pulls a model). |
| `bin/tools.lock` | Pinned versions of the installed ProjectDiscovery toolchain. |
| `Makefile` | Orchestrates every stage, `test`, and `dry-run`. |
| `tests/` | 29 tests — scope guard, munge, rank, analyze, report, and the pty G2 test (+ fixtures). |
| `CLAUDE.md` | Full guardrail contract for any future Claude Code session in this repo. |
| `targets/example-program/scope.yaml` | Placeholder scope (example.com only — no real data). |
| `OPS-CARD.md` | Operator field reference. |

---

## How to run

Prove it offline first:
```bash
make test        # 29 tests: scope guard, munge, rank, analyze, report, pty G2
make dry-run     # walks stages 0-6 on example.com with every network tool stubbed
```

**The daily loop** (a real program — nothing touches the network until step 3):
1. Pick a program you're enrolled in; read its policy (RoE).
2. Fill `targets/<program>/scope.yaml` to match the policy exactly
   (see [the field map](#reading-a-roe-page-into-scopeyaml) below).
3. `make init P=<program>` → verify the **G1** scope print-back.
4. `BB_DRY_RUN=0 make passive P=<program>` → review `recon/<program>/hosts.txt`.
5. `BB_DRY_RUN=0 make probe P=<program>` (type the name at **G2**), then
   `BB_DRY_RUN=0 make recon P=<program>` — one stage at a time.
6. `make rank`, `make analyze`, `make report` → read the drafts in
   `reports/<program>/`, **reproduce by hand**, and submit yourself (**G3**).

Do not un-stub all stages at once. Stages are idempotent and use `anew`, so re-runs surface
only newly-seen items.

---

## Reading a RoE page into scope.yaml

| field | where it comes from on the policy page |
|---|---|
| `in_scope` | the "In scope" / "Targets" list. Wildcards (`*.example.com`) cover **strict subdomains only** — list the apex (`example.com`) separately unless you set `wildcard_includes_apex`. |
| `out_of_scope` | the "Out of scope" / excluded-assets list. **These always win** over `in_scope`. |
| `rate_limit_rps` | any stated request-rate ceiling. If unstated, leave the default **2** or go lower. |
| `automation_allowed` | whether automated tooling is permitted at all. `false` ⇒ the pipeline refuses every active stage and tells you to work it manually. |
| `active_testing_allowed` | whether sending requests to targets is allowed (vs. passive-only). Gates stages 2–3. |
| `ai_disclosure_required` | whether submissions must disclose AI assistance; when `true`, every draft carries the AI-assisted note. |
| `wildcard_includes_apex` | **per-program opt-in.** Default (absent/false) is conservative: a wildcard does not include the bare apex. Set `true` only if the program's wording says so. |
| `notes` | paste the relevant RoE text verbatim, so any reviewer sees exactly what was authorized. |

Fail-closed defaults if a flag is omitted: `automation_allowed`/`active_testing_allowed` →
**false**, `ai_disclosure_required` → **true**, `rate_limit_rps` → **2**. Empty `in_scope`
is refused.

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

Stages 4b and 5 schema-validate their model output and retry once, with a deterministic
fallback so a run never hard-fails offline. Stage 6 renders drafts deterministically from
the reviewed stage-5 analysis (it adds no fresh prose of its own) for confirmed candidates
only. Inference uses `BB_INFERENCE_BACKEND` (default `claude`); Claude cost per run is
logged to `logs/cost.log`.

**No destructive or out-of-policy actions, ever:** no DoS/stress, no exfiltration beyond
minimal proof, no touching other users' data, no social engineering, account creation, or
CAPTCHA solving. If proving a finding would need any of these, stage 5 flags it and does not
auto-confirm it — you handle it manually.
