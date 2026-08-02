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
fallback_dir=${TALK_FALLBACK_DIR:-"$root_dir/docs/talk/fallback"}
if test -n "${TALK_FALLBACK_DIR:-}" && test "${TALK_TEST_MODE:-}" != 1; then
  echo "TALK_FALLBACK_DIR is available only with TALK_TEST_MODE=1" >&2
  exit 2
fi
artifact_tool="$root_dir/scripts/talk-demo-artifacts.py"

case "$mode" in
  preloaded)
    python3 "$artifact_tool" preloaded "$fallback_dir"
    ;;
  evidence)
    python3 "$artifact_tool" evidence "$fallback_dir"
    ;;
  live)
    if test -n "${TALK_SMOKE_COMMAND:-}"; then
      if test "${TALK_TEST_MODE:-}" != 1; then
        echo "TALK_SMOKE_COMMAND is available only with TALK_TEST_MODE=1" >&2
        exit 2
      fi
      smoke_output=$(cd "$root_dir" && "$TALK_SMOKE_COMMAND")
      printf '%s\n' "$smoke_output" | python3 "$artifact_tool" contract
      exit 0
    fi
    echo "Running the isolated end-to-end verification; presentation records follow on stdout." >&2
    if ! smoke_output=$(cd "$root_dir" && ./scripts/smoke.sh 2>&1); then
      printf '%s\n' "$smoke_output" >&2
      exit 1
    fi
    for proof in 'repository=CONTEXT.md' 'outlook_effect_count=0' 'event_count=1' 'policy_revision=ticket-10' 'fail_closed=identity effect_count=0'; do
      if ! printf '%s\n' "$smoke_output" | grep -Fq "$proof"; then
        echo "live verification is missing proof: $proof" >&2
        exit 1
      fi
    done
    python3 "$artifact_tool" recorded "$fallback_dir" live full-smoke
    ;;
  *) usage ;;
esac
