#!/bin/sh
set -eu

root_dir=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
fixture_dir=$(mktemp -d)
trap 'rm -rf "$fixture_dir"' EXIT INT TERM

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
  case "$mode" in
    preloaded)
      test "$(printf '%s\n' "$output" | grep -c '"model_response":' || true)" -eq 4
      ;;
    evidence)
      test "$(printf '%s\n' "$output" | grep -c '"screenshot":"' || true)" -eq 4
      printf '%s\n' "$output" | grep -Fq '"correlation_id":"fallback-exploit-correlation-01"'
      printf '%s\n' "$output" | grep -Fq '"decision_id":"fallback-exploit-decision-01"'
      ;;
  esac
  if printf '%s\n' "$output" | grep -Eq 'owner-subject-id|credential|password|approval":"'; then
    echo "talk demo leaked a sensitive fixture value" >&2
    exit 1
  fi
}

assert_mode preloaded env
assert_mode evidence env
assert_mode live env TALK_TEST_MODE=1 TALK_SMOKE_COMMAND=./scripts/testdata/talk-smoke-pass.sh

cp -R "$root_dir/docs/talk/fallback/." "$fixture_dir/"
printf '{}\n{}\n{}\n{}\n' > "$fixture_dir/preloaded-model-responses.jsonl"
if cd "$root_dir" && TALK_TEST_MODE=1 TALK_FALLBACK_DIR="$fixture_dir" ./scripts/talk-demo.sh run --mode preloaded >/dev/null 2>&1; then
  echo "arbitrary preloaded responses unexpectedly passed" >&2
  exit 1
fi

cp "$root_dir/docs/talk/fallback/preloaded-model-responses.jsonl" "$fixture_dir/preloaded-model-responses.jsonl"
sed 's/fallback-exploit-correlation-01/uncorrelated-decision/' "$fixture_dir/01-exploit.svg" > "$fixture_dir/01-exploit.tmp"
mv "$fixture_dir/01-exploit.tmp" "$fixture_dir/01-exploit.svg"
if cd "$root_dir" && TALK_TEST_MODE=1 TALK_FALLBACK_DIR="$fixture_dir" ./scripts/talk-demo.sh run --mode evidence >/dev/null 2>&1; then
  echo "uncorrelated evidence unexpectedly passed" >&2
  exit 1
fi

if cd "$root_dir" && TALK_TEST_MODE=1 TALK_SMOKE_COMMAND=./scripts/testdata/talk-smoke-substrings.sh ./scripts/talk-demo.sh run --mode live >/dev/null 2>&1; then
  echo "unstructured smoke substrings unexpectedly passed" >&2
  exit 1
fi

if cd "$root_dir" && TALK_SMOKE_COMMAND=./scripts/testdata/talk-smoke-pass.sh ./scripts/talk-demo.sh run --mode live >/dev/null 2>&1; then
  echo "smoke override without TALK_TEST_MODE unexpectedly passed" >&2
  exit 1
fi
