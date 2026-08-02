#!/bin/sh
set -eu

root_dir=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
output=$(cd "$root_dir" && ./scripts/talk-package.sh validate)

expected='PASS talk_package segments=6 minutes=30 visible_code=3 scenarios=4'
if test "$output" != "$expected"; then
  echo "unexpected talk package result: $output" >&2
  exit 1
fi
