#!/bin/sh
set -eu

usage() {
  echo "usage: $0 run --mode live|preloaded|evidence" >&2
  exit 2
}

test "${1:-}" = run || usage
test "${2:-}" = --mode || usage
mode=${3:-}
test "$#" -eq 3 || usage

root_dir=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
results="$root_dir/docs/talk/fallback/results.jsonl"
responses="$root_dir/docs/talk/fallback/preloaded-model-responses.jsonl"
evidence="$root_dir/docs/talk/fallback/evidence.md"

emit_results() {
  selected_mode=$1
  verification=$2
  sed -e "s/\"mode\":\"recorded\"/\"mode\":\"$selected_mode\"/" \
    -e "s/\"verification\":\"recorded\"/\"verification\":\"$verification\"/" "$results"
}

case "$mode" in
  preloaded)
    test -s "$responses" || { echo "preloaded model responses are unavailable" >&2; exit 1; }
    test "$(wc -l < "$responses" | tr -d ' ')" -eq 4 || { echo "preloaded response set is incomplete" >&2; exit 1; }
    emit_results preloaded preloaded-responses
    ;;
  evidence)
    test -s "$evidence" || { echo "trace-correlated evidence is unavailable" >&2; exit 1; }
    for screenshot in 01-exploit 02-meeting 03-outlook 04-codex; do
      test -s "$root_dir/docs/talk/fallback/$screenshot.svg" || {
        echo "evidence screenshot is unavailable: $screenshot" >&2
        exit 1
      }
    done
    emit_results evidence screenshot-sequence
    ;;
  live)
    smoke_command=${TALK_SMOKE_COMMAND:-./scripts/smoke.sh}
    echo "Running the isolated end-to-end verification; presentation records follow on stdout." >&2
    if ! smoke_output=$(cd "$root_dir" && "$smoke_command" 2>&1); then
      printf '%s\n' "$smoke_output" >&2
      exit 1
    fi
    for proof in 'repository=CONTEXT.md' 'outlook_effect_count=0' 'event_count=1' 'policy_revision=ticket-10' 'fail_closed=identity effect_count=0'; do
      if ! printf '%s\n' "$smoke_output" | grep -Fq "$proof"; then
        echo "live verification is missing proof: $proof" >&2
        exit 1
      fi
    done
    emit_results live full-smoke
    ;;
  *) usage ;;
esac
