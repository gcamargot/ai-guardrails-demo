#!/bin/sh
set -eu

repository_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT INT TERM

run_rejected() {
  fixture="$1"
  expected_stage="$2"
  output="$test_root/$fixture-output"
  log="$test_root/$fixture.log"

  if POLICY_SOURCE="$repository_root/testdata/policy-ci/$fixture" \
    POLICY_OUTPUT="$output" \
    POLICY_SIGNING_KEY="$repository_root/policies/keys/demo-signing-private.pem" \
    POLICY_VERIFYING_KEY="$repository_root/policies/keys/demo-signing-public.pem" \
    "$repository_root/scripts/policy-ci.sh" >"$log" 2>&1; then
    echo "$fixture unexpectedly passed" >&2
    exit 1
  fi
  if ! grep -Fq "$expected_stage" "$log"; then
    echo "$fixture did not fail at $expected_stage" >&2
    exit 1
  fi
  if test -e "$output/agent-tools-bundle.tar.gz"; then
    echo "$fixture published an artifact after failure" >&2
    exit 1
  fi
}

run_rejected bad-format "policy-ci: format"
run_rejected bad-compile "policy-ci: compile"
run_rejected bad-tests "policy-ci: tests"
run_rejected bad-owners "policy-ci: ownership"

valid_output="$test_root/valid-output"
POLICY_SOURCE="$repository_root/policies" \
  POLICY_OUTPUT="$valid_output" \
  POLICY_SIGNING_KEY="$repository_root/policies/keys/demo-signing-private.pem" \
  POLICY_VERIFYING_KEY="$repository_root/policies/keys/demo-signing-public.pem" \
  "$repository_root/scripts/policy-ci.sh"

test -s "$valid_output/agent-tools-bundle.tar.gz"
tar -tzf "$valid_output/agent-tools-bundle.tar.gz" | grep -Fq '.signatures.json'

custom_output="$test_root/custom-revision-output"
POLICY_SOURCE="$repository_root/policies" \
  POLICY_OUTPUT="$custom_output" \
  POLICY_REVISION="review-42" \
  POLICY_SIGNING_KEY="$repository_root/policies/keys/demo-signing-private.pem" \
  POLICY_VERIFYING_KEY="$repository_root/policies/keys/demo-signing-public.pem" \
  "$repository_root/scripts/policy-ci.sh"
reported_revision="$(docker run --rm \
  -v "$custom_output/agent-tools-bundle.tar.gz:/bundle.tar.gz:ro" \
  openpolicyagent/opa:1.17.0-static eval --bundle /bundle.tar.gz --format raw data.policy_metadata.revision)"
if test "$reported_revision" != "review-42"; then
  echo "decision revision $reported_revision diverges from manifest revision review-42" >&2
  exit 1
fi
echo "PASS policy pipeline rejects every quality-gate failure and publishes only a signed artifact"
