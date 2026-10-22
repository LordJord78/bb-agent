# shellcheck shell=bash
# Shared helpers for every pipeline stage. Source this at the top of a stage:
#   source "$(dirname "$0")/../lib/common.sh"
#
# Provides: repo paths, the BB_HALT kill-switch check, timestamped logging,
# polite rate-limit / jitter helpers, an identifying User-Agent, and a bridge
# to the Python Scope Guard so every stage filters hosts the same way.
#
# Nothing here sends traffic. Stages that do must call bb_require_scope_pass
# on their host lists and honor bb_rate_limit_rps before invoking any tool.

set -euo pipefail

BB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export BB_ROOT
export BB_LOG_DIR="$BB_ROOT/logs"
export BB_PY="${BB_PY:-python3}"

# Identify this as security research where a tool lets us set a UA.
export BB_USER_AGENT="${BB_USER_AGENT:-bb-agent/0.1 (authorized security research; human-reviewed)}"

# Default backend for the fuzzy stage; never auto-pulls a model.
export BB_INFERENCE_BACKEND="${BB_INFERENCE_BACKEND:-claude}"

# Dry-run stubs all network tools. On by default during the build so nothing
# can accidentally touch a host; real runs set BB_DRY_RUN=0 explicitly.
export BB_DRY_RUN="${BB_DRY_RUN:-1}"

mkdir -p "$BB_LOG_DIR"

bb_now() { date '+%Y-%m-%dT%H:%M:%S%z'; }

# bb_log <stage> <message...>  -> stderr + logs/<stage>.log
bb_log() {
  local stage="$1"; shift
  local line="[$(bb_now)] [$stage] $*"
  echo "$line" >&2
  echo "$line" >>"$BB_LOG_DIR/$stage.log"
}

# The kill switch. Every stage calls this at entry and between items.
bb_check_halt() {
  if [[ "${BB_HALT:-0}" == "1" ]]; then
    bb_log "${1:-halt}" "BB_HALT=1 — aborting."
    exit 42
  fi
}

# Small random jitter (0.0–0.5s) so we never hammer in lockstep.
bb_jitter() {
  "$BB_PY" -c 'import random,time; time.sleep(random.uniform(0,0.5))'
}

# Read one field out of a program's parsed scope (via the Scope Guard).
# usage: bb_scope_field <program> <field>
bb_scope_field() {
  local program="$1" field="$2"
  "$BB_PY" - "$program" "$field" <<'PY'
import sys
sys.path.insert(0, __import__("os").environ["BB_ROOT"])
from lib.scope_guard import load_scope
scope = load_scope(sys.argv[1])
val = scope.get(sys.argv[2], "")
print(val if not isinstance(val, list) else " ".join(val))
PY
}

bb_rate_limit_rps() { bb_scope_field "$1" rate_limit_rps; }

# Filter a newline-delimited host list on stdin through the Scope Guard.
# usage: some_source | bb_require_scope_pass <program>   > in_scope_hosts.txt
# No tool should ever receive hosts that have not passed through here.
bb_require_scope_pass() {
  local program="$1"
  "$BB_PY" - "$program" <<'PY'
import sys
sys.path.insert(0, __import__("os").environ["BB_ROOT"])
from lib.scope_guard import load_scope, scope_filter
scope = load_scope(sys.argv[1])
hosts = [l.strip() for l in sys.stdin if l.strip()]
for h in scope_filter(hosts, scope):
    print(h)
PY
}

# Hard-refuse active tooling unless the program's RoE allows it. Stages that
# send crafted traffic call this (the code half of gate G2); the per-run human
# "yes" is handled by the orchestrator.
bb_require_active_allowed() {
  local program="$1"
  "$BB_PY" - "$program" <<'PY'
import sys
sys.path.insert(0, __import__("os").environ["BB_ROOT"])
from lib.scope_guard import load_scope, assert_automation_allowed, assert_active_testing_allowed, ScopeRefusal
try:
    scope = load_scope(sys.argv[1])
    assert_automation_allowed(scope)
    assert_active_testing_allowed(scope)
except ScopeRefusal as exc:
    print(f"REFUSED: {exc}", file=sys.stderr)
    sys.exit(3)
PY
}
