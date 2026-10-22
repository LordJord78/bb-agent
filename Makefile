# bb-agent — authorized bug-bounty recon/triage pipeline.
# Deterministic stages run for real; live-traffic stages are gated and, until
# wired + reviewed, print a notice. Everything defaults to DRY-RUN.
#
#   make test            run all unit tests (scope guard + munge)
#   make init P=<prog>    stage 0: validate scope + print G1 (no network)
#   make munge P=<prog> IN=<file>   stage 4a: deterministic normalize/dedupe
#   make dry-run          exercise the flow on example.com, network stubbed
#
# Live stages (passive/probe/recon/rank/analyze/report) are the next review
# step and currently refuse to pretend they ran.

SHELL := /usr/bin/bash
P     ?= example-program
IN    ?= tests/fixtures/nuclei-sample.jsonl
PY    ?= python3
export BB_DRY_RUN ?= 1

.PHONY: test init munge dry-run passive probe recon rank analyze report _todo

test:
	@$(PY) tests/test_scope_guard.py
	@echo
	@$(PY) tests/test_munge.py

init:
	@bin/stage0-init $(P)

munge:
	@$(PY) lib/munge.py --program $(P) $(IN)

dry-run:
	@echo "### DRY-RUN (BB_DRY_RUN=$(BB_DRY_RUN)) — no host is contacted ###"
	@echo
	@echo "--- stage 0: init / G1 ---"
	@bin/stage0-init $(P) || true
	@echo
	@echo "--- stages 1-3: passive / probe / recon ---"
	@echo "    [stubbed] live-traffic stages are not wired yet (next review step)."
	@echo
	@echo "--- stage 4a: deterministic munge (runs for real) ---"
	@mkdir -p findings
	@$(PY) lib/munge.py --program $(P) $(IN) > findings/shortlist.example.json
	@$(PY) -c "import json;d=json.load(open('findings/shortlist.example.json'));print('    counts:',json.dumps(d['counts']));print('    assets:',list(d['assets']))"
	@echo
	@echo "--- stage 4b: fuzzy rank (stubbed via bin/llm) ---"
	@echo "    backend=$${BB_INFERENCE_BACKEND:-claude}"; printf '    llm stub -> '; bin/llm "rank these findings" 2>/dev/null
	@echo
	@echo "--- stages 5-6: analyze / report ---"
	@echo "    [stubbed] not wired yet (next review step). No report is ever submitted (G3)."
	@echo
	@echo "### dry-run complete — deterministic core proven on example.com ###"

passive probe recon rank analyze report: _todo
_todo:
	@echo "stage '$(MAKECMDGOALS)' is not wired yet — it's the next reviewable step."
	@echo "it will enforce scope_filter + gate G2 + rate_limit_rps before any traffic."
	@exit 2
