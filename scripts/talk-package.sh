#!/bin/sh
set -eu

usage() {
  echo "usage: $0 validate" >&2
  exit 2
}

test "${1:-}" = validate || usage
test "$#" -eq 1 || usage

root_dir=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
slides="$root_dir/docs/talk/slides.md"
notes="$root_dir/docs/talk/speaker-notes.md"
runbook="$root_dir/docs/talk/runbook.md"

for required_file in "$slides" "$notes" "$runbook"; do
  if test ! -s "$required_file"; then
    echo "talk package is missing ${required_file#"$root_dir/"}" >&2
    exit 1
  fi
done

actual_segments=$(sed -n 's/^<!-- segment:\([^ ]*\) minutes:\([0-9][0-9]*\) -->$/\1 \2/p' "$slides")
expected_segments='compromise 3
definition 5
architecture 8
demo 8
operations 4
conclusion 2'
if test "$actual_segments" != "$expected_segments"; then
  echo "talk segments must be compromise/definition/architecture/demo/operations/conclusion at 3/5/8/8/4/2 minutes" >&2
  exit 1
fi

minutes=$(printf '%s\n' "$actual_segments" | awk '{total += $2} END {print total + 0}')
visible_code=$(grep -c '^<!-- visible-code:[a-z-]* -->$' "$slides" || true)
code_fences=$(grep -c '^```' "$slides" || true)
if test "$minutes" -ne 30 || test "$visible_code" -ne 3 || test "$code_fences" -ne 6; then
  echo "talk package requires 30 minutes and exactly three visible code fragments" >&2
  exit 1
fi

for required_text in \
  'MCP mental model' \
  'Enforcement Boundary' \
  'Security Context' \
  'Model Interpretation' \
  'Subject + Actor + Channel + Turn Capability + Tool + arguments' \
  'Platform/Security' \
  'Protected Resource owner' \
  'Prompt Rule exploit' \
  'Meeting Proposal' \
  'Outlook prompt injection' \
  'Codex denial' \
  "If the model can grant itself permission, it isn't a guardrail."; do
  if ! grep -Fq "$required_text" "$slides"; then
    echo "slides are missing required content: $required_text" >&2
    exit 1
  fi
done

checklist_items=$(sed -n '/<!-- closing-checklist:start -->/,/<!-- closing-checklist:end -->/p' "$slides" | grep -c '^[0-9][0-9]*\.' || true)
if test "$checklist_items" -ne 5; then
  echo "closing checklist must contain exactly five questions" >&2
  exit 1
fi

for scenario in exploit meeting outlook codex; do
  if ! grep -Fq "<!-- demo-scenario:$scenario -->" "$slides"; then
    echo "slides are missing demo scenario: $scenario" >&2
    exit 1
  fi
done

echo "PASS talk_package segments=6 minutes=30 visible_code=3 scenarios=4"
