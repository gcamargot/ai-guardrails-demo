#!/bin/sh
set -eu

root_dir=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)

pass_output=$(cd "$root_dir" && ./scripts/rehearse-talk.sh verify scripts/testdata/rehearsal-pass.json)
test "$pass_output" = 'PASS human_rehearsal segments=6 actual=28:30 target=30:00 questions=7'

if cd "$root_dir" && ./scripts/rehearse-talk.sh verify scripts/testdata/rehearsal-over-budget.json >/dev/null 2>&1; then
  echo "over-budget rehearsal unexpectedly passed" >&2
  exit 1
fi

set +e
pending_output=$(cd "$root_dir" && ./scripts/rehearse-talk.sh verify docs/talk/rehearsal.json 2>&1)
pending_status=$?
set -e
test "$pending_status" -eq 3
test "$pending_output" = 'PENDING human_rehearsal segments=6 target=30:00 questions=5-10'
