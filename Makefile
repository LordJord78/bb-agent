# bb-agent — authorized bug-bounty recon/triage pipeline.
# Deterministic stages run for real; live-traffic stages are scope-gated,
# rate-limited, and stubbed under BB_DRY_RUN (the default). The first real run
# against a program is done stage-by-stage by hand, not via `dry-run`.
#
#   make test             run all unit tests (scope guard + munge)
#   make init P=<prog>     stage 0: validate scope + print G1 (no network)
#   make passive P=<prog>  stage 1: passive enum (no active traffic)
#   make probe P=<prog>    stage 2: httpx probe (active; needs RoE + G2)
#   make recon P=<prog>    stage 3: crawl + ports (active; needs RoE + G2)
#   make munge P=<prog> IN=<file>   stage 4a: deterministic normalize/dedupe
#   make dry-run           walk the whole flow on example.com, network stubbed
#
# rank / analyze / report are the next review step and refuse until wired.

SHELL := /usr/bin/bash
P     ?= example-program
IN    ?= tests/fixtures/nuclei-sample.jsonl
PY    ?= python3
export BB_DRY_RUN ?= 1

.PHONY: test init passive probe recon munge rank analyze report dry-run

test:
	@for t in scope_guard munge rank analyze report g2_confirm; do $(PY) tests/test_$$t.py || exit 1; echo; done

init:    ; @bin/stage0-init $(P)
passive: ; @bin/stage1-passive $(P)
probe:   ; @bin/stage2-probe $(P)
recon:   ; @bin/stage3-recon $(P)
munge:   ; @$(PY) lib/munge.py --program $(P) $(IN)
rank:    ; @bin/stage4b-rank $(P) findings/shortlist.json
analyze: ; @bin/stage5-analyze $(P) findings/ranked.json
report:  ; @bin/stage6-report $(P) findings/analyzed.json

dry-run:
	@echo "### DRY-RUN (BB_DRY_RUN=$(BB_DRY_RUN)) — no host is contacted ###"; echo
	@echo "--- stage 0: init / G1 ---"
	@bin/stage0-init $(P) >/dev/null && echo "    scope validated + printed (see 'make init')"
	@echo
	@echo "--- gate G2 demo: active testing refused on example-program ---"
	@bin/gate-check $(P)
	@echo
	@echo "--- stage 1: passive enum (stubbed) ---"
	@bin/stage1-passive $(P) >/dev/null
	@echo "    in-scope hosts kept:"; sed 's/^/        /' recon/$(P)/hosts.txt
	@echo "    (blog.example.com, db.internal.example.com, evil-example.com, cdn.example.org were filtered by the Scope Guard)"
	@echo
	@echo "--- stage 2: httpx probe (stubbed) ---"
	@bin/stage2-probe $(P) >/dev/null && echo "    alive URLs -> recon/$(P)/alive.txt ($$(wc -l < recon/$(P)/alive.txt | tr -d ' '))"
	@echo
	@echo "--- stage 3: crawl + ports (stubbed) ---"
	@bin/stage3-recon $(P) >/dev/null && echo "    endpoints -> $$(wc -l < recon/$(P)/endpoints.txt | tr -d ' ') · ports -> $$(wc -l < recon/$(P)/ports.txt | tr -d ' ')"
	@echo
	@echo "--- stage 4a: deterministic munge (runs for real) ---"
	@mkdir -p findings
	@$(PY) lib/munge.py --program $(P) $(IN) > findings/shortlist.example.json
	@$(PY) -c "import json;d=json.load(open('findings/shortlist.example.json'));print('    counts:',json.dumps(d['counts']));print('    assets:',list(d['assets']))"
	@echo
	@echo "--- stage 4b: fuzzy rank (deterministic fallback in dry-run) ---"
	@bin/stage4b-rank $(P) findings/shortlist.example.json >/dev/null
	@$(PY) -c "import json;d=json.load(open('findings/ranked.json'));print('    source:',d['source'],'· candidates:',len(d['candidates']));[print('      -',c['severity'],c['id'],'on',c['hosts']) for c in d['candidates']]"
	@echo
	@echo "--- stage 5: analyze (deterministic fallback) ---"
	@bin/stage5-analyze $(P) findings/ranked.json >/dev/null
	@$(PY) -c "import json;d=json.load(open('findings/analyzed.json'));print('    source:',d['source'],'· confirmed:',sum(1 for c in d['candidates'] if c['analysis']['confirmed']),'· flagged for manual:',sum(1 for c in d['candidates'] if c['analysis']['needs_manual_proof']))"
	@echo
	@echo "--- stage 6: report (confirmed only; G3 stop, never submits) ---"
	@bin/stage6-report $(P) findings/analyzed.json >/dev/null 2>&1 || true
	@echo "    live flow drafted $$(ls reports/$(P)/*.md 2>/dev/null | wc -l | tr -d ' ') report(s) (deterministic analysis confirms nothing)."
	@echo "    sample draft from a confirmed fixture, to show the format:"
	@$(PY) lib/report.py $(P) tests/fixtures/analyzed-confirmed.json >/dev/null
	@echo "      -> reports/$(P)/cve-2021-41773.md"; sed -n '1,6p;$$p' reports/$(P)/cve-2021-41773.md | sed 's/^/        /'
	@echo; echo "### dry-run complete — full pipeline (stages 0-6) proven on example.com ###"
