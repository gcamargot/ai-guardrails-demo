#!/bin/sh
set -eu

root_dir=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)

assert_mode() {
  mode=$1
  shift
  output=$(cd "$root_dir" && "$@" ./scripts/talk-demo.sh run --mode "$mode")
  lines=$(printf '%s\n' "$output" | wc -l | tr -d ' ')
  test "$lines" -eq 4
  for scenario in exploit meeting outlook codex; do
    count=$(printf '%s\n' "$output" | grep -c "\"scenario\":\"$scenario\"" || true)
    test "$count" -eq 1
  done
  printf '%s\n' "$output" | grep -Fq '"scenario":"exploit","outcome":"insecure_effect_then_enforced_deny","effect_count":1'
  printf '%s\n' "$output" | grep -Fq '"scenario":"meeting","outcome":"exact_approval","effect_count":1'
  printf '%s\n' "$output" | grep -Fq '"scenario":"outlook","outcome":"untrusted_content_ignored","effect_count":0'
  printf '%s\n' "$output" | grep -Fq '"scenario":"codex","outcome":"server_denied","effect_count":0'
  printf '%s\n' "$output" | grep -Fq '"failed_condition":"smart_lock_owner_subject_required","protected_effect_count":0'
  printf '%s\n' "$output" | grep -Fq '"proposal_state":"pending_then_approved","approval_binding":"exact_single_use"'
  printf '%s\n' "$output" | grep -Fq '"content_trust":"untrusted","derived_effect_count":0'
  printf '%s\n' "$output" | grep -Fq '"allowed_tool":"dev.read_repository","smart_lock_discovered":false'
  if printf '%s\n' "$output" | grep -Eq 'owner-subject-id|credential|password|approval":"'; then
    echo "talk demo leaked a sensitive fixture value" >&2
    exit 1
  fi
}

assert_mode preloaded env
assert_mode evidence env
assert_mode live env TALK_SMOKE_COMMAND=./scripts/testdata/talk-smoke-pass.sh
