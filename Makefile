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

.PHONY: test init passive probe recon munge dry-run rank analyze report _todo

test:
	@$(PY) tests/test_scope_guard.py
	@echo
	@$(PY) tests/test_munge.py

init:    ; @bin/stage0-init $(P)
passive: ; @bin/stage1-passive $(P)
probe:   ; @bin/stage2-probe $(P)
recon:   ; @bin/stage3-recon $(P)
munge:   ; @$(PY) lib/munge.py --program $(P) $(IN)

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
	@echo "--- stage 4b: fuzzy rank (stubbed via bin/llm) ---"
	@printf '    backend=%s  llm stub -> ' "$${BB_INFERENCE_BACKEND:-claude}"; bin/llm "rank" 2>/dev/null
	@echo
	@echo "--- stages 5-6: analyze / report ---"
	@echo "    [stubbed] not wired yet. No report is ever submitted (G3)."
	@echo; echo "### dry-run complete — stages 0-4a proven on example.com ###"

rank analyze report: _todo
_todo:
	@echo "stage '$(MAKECMDGOALS)' is not wired yet — next reviewable step."
	@echo "4b will schema-validate + retry via bin/llm; 5-6 draft reports with the"
	@echo "[HUMAN REVIEW REQUIRED] banner. Nothing is ever submitted (G3)."
	@exit 2
