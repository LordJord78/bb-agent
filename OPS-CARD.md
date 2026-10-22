# Bug Bounty Ops Card

> **Field reference for operating the `bb-agent` pipeline.**
> The pipeline is a **scout, not a soldier**: it looks, sorts the noise, and hands you a draft.
> **You** decide, reproduce by hand, and submit. Scope (permission) is the only thing that makes any of this legal.
>
> `it looks & reports → you reproduce & submit`

**Legend:** safe — no traffic / reading only · active — sends real requests (gated) · stop — your job, not the tool's

## The one idea: the fence
A program tells you what you may touch. You write that into `scope.yaml` — that's the **fence**. The tool physically can't step outside it; every host is checked first.
- **Inside the fence** = legal, protected (safe harbor).
- **Outside** = unauthorized access, instant ban.
> Getting the fence right is 90% of operating this safely. When unsure, draw it **smaller**.

## The 3 gates
| Gate | | What it does |
|---|---|---|
| **G1 · Confirm scope** | safe | It prints the fence back. You eyeball it before anything runs. |
| **G2 · Approve active testing** | active | Before real requests go out, type the program name **exactly**. Typo or blank = abort. Reads the terminal only — no env var or pipe can skip it. |
| **G3 · Never submit** | stop | It writes a DRAFT stamped `[HUMAN REVIEW REQUIRED]` / NOT SUBMITTED, then stops. **You** reproduce and send. |

## Pipeline at a glance
| Stage | Does | |
|---|---|---|
| `0 init` | prints scope | G1 |
| `1 passive` | find hosts, quietly | no traffic |
| `2 probe` | knock: what's alive | G2 |
| `3 recon` | crawl + ports | G2 |
| `4a munge` | dedupe, drop noise | code |
| `4b rank` | cluster survivors | AI |
| `5 analyze` | exploitability | AI |
| `6 report` | draft per finding | G3 |

## Safety switches
- **Practice mode is ON by default.** `BB_DRY_RUN=1` touches nothing. You must set `BB_DRY_RUN=0` to send real traffic.
- **Kill switch.** `BB_HALT=1` -> every stage aborts.
- **Rate limited.** `rate_limit_rps` keeps it slow and polite. Fast = banned, not paid.
- **Loot stays private.** `recon/ findings/ reports/ logs/` are git-ignored — target data never gets committed.

## Run it: the daily loop
1. Pick a program **you're enrolled in**. Open its policy & read the rules (RoE).
2. Fill `targets/<prog>/scope.yaml` to match the policy **exactly**.
3. `make init` -> watch **G1** print the fence.
4. Run **stage 1 (passive) only** at `BB_DRY_RUN=0`. Looks right?
5. Enable stage 2 (type the name at **G2**), then stage 3 — one at a time.
6. Read the draft. **Reproduce it by hand.** If it's real, submit it yourself.

## The 5 rules you never break
1. Only point it at programs you've enrolled in.
2. Read the rules first. No automation where it's banned.
3. Draw the fence tight. Unsure -> make it smaller.
4. Never auto-submit. You reproduce and send, always.
5. Go slow. Speed gets you banned.

## Where to find bounties
| Platform | Link | Notes |
|---|---|---|
| **HackerOne** | hackerone.com | Biggest, 2,000+ programs, beginner-friendly. |
| **Bugcrowd** | bugcrowd.com | Strong onboarding, clear scope docs. |
| **Intigriti** | intigriti.com | EU-centric, beginner-friendly, timely payouts. |
| **YesWeHack** | yeswehack.com | EU, open-source spirit, less crowded. |
| **Immunefi** | immunefi.com | Crypto / smart contracts — the big payouts. |
| **huntr** | huntr.com | AI/ML & open source — a gentle entry. |
| **First-party VRPs** | — | Google, Microsoft MSRC, Apple, GitHub — apply direct. |
> Start on **VDPs** (disclosure programs, often unpaid) to build a track record -> earn private invites. Directory: **disclose.io**. Synack is invite-only — not a first stop.

## Best practice for landing bounties
- **Read the policy every time.** Scope, allowed tests, rate caps, AI-disclosure.
- **Go deep, not wide.** Pick one target and learn it cold.
- **The money is in logic, not scanners.** Broken access control / IDOR, auth, and business-logic bugs beat generic scan hits.
- **Reproduce before you report.** No exceptions.
- **Write impact-first reports:** what an attacker gains, exact repro steps, PoC, affected asset, suggested fix. One bug per report.
- **Check for duplicates first** — a dupe pays nothing.
- **Minimal proof only.** Never pivot, exfiltrate, or touch other users' data.
- **Be professional & patient** with triage — reputation compounds into invites.
- **No public disclosure** without the program's OK. Disclose AI use if asked.

*Built for the Omarchy `bb-agent` pipeline · keep it close · hunt in scope · v2*
