#!/bin/sh
set -eu

root_dir=$(CDPATH='' cd -- "$(dirname "$0")/../.." && pwd)
cat "$root_dir/docs/talk/fallback/results.jsonl"
