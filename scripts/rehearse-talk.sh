#!/bin/sh
set -eu

if test "${1:-}" != verify || test "$#" -ne 2; then
  echo "usage: $0 verify <timings.json>" >&2
  exit 2
fi

python3 - "$2" <<'PY'
import json
import sys
from pathlib import Path

expected = [
    ("compromise", 3),
    ("definition", 5),
    ("architecture", 8),
    ("demo", 8),
    ("operations", 4),
    ("conclusion", 2),
]


def fail(reason):
    print(f"FAIL human_rehearsal reason={reason}", file=sys.stderr)
    raise SystemExit(1)


path = Path(sys.argv[1])
try:
    document = json.loads(path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as error:
    fail(f"unreadable_timings:{error}")

if not isinstance(document, dict) or set(document) != {"status", "question_minutes", "segments"}:
    fail("invalid_document_shape")
segments = document["segments"]
if not isinstance(segments, list) or len(segments) != len(expected):
    fail("six_segments_required")

for index, ((expected_id, expected_budget), segment) in enumerate(zip(expected, segments)):
    if not isinstance(segment, dict) or set(segment) != {"id", "budget_minutes", "actual_seconds"}:
        fail(f"invalid_segment_shape:{index}")
    if segment["id"] != expected_id or segment["budget_minutes"] != expected_budget:
        fail(f"segment_order_or_budget:{index}")

status = document["status"]
if status == "pending":
    if document["question_minutes"] is not None or any(segment["actual_seconds"] is not None for segment in segments):
        fail("pending_record_contains_observations")
    print("PENDING human_rehearsal segments=6 target=30:00 questions=5-10")
    raise SystemExit(3)
if status != "observed":
    fail("status_must_be_pending_or_observed")

questions = document["question_minutes"]
if type(questions) is not int or not 5 <= questions <= 10:
    fail("questions_must_be_5_to_10_minutes")

total = 0
for segment, (segment_id, budget) in zip(segments, expected):
    actual = segment["actual_seconds"]
    if type(actual) is not int or actual < 0:
        fail(f"invalid_actual_seconds:{segment_id}")
    if actual > budget * 60:
        fail(f"segment_over_budget:{segment_id}")
    total += actual
if total > 30 * 60:
    fail("talk_over_30_minutes")

print(
    f"PASS human_rehearsal segments=6 actual={total // 60}:{total % 60:02d} "
    f"target=30:00 questions={questions}"
)
PY
