#!/bin/sh
set -eu

repository_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
policy_source="${POLICY_SOURCE:-$repository_root/policies}"
policy_output="${POLICY_OUTPUT:-$repository_root/.artifacts/policy}"
policy_revision="${POLICY_REVISION:-ticket-08}"
policy_signing_key="${POLICY_SIGNING_KEY:-$repository_root/policies/keys/demo-signing-private.pem}"
policy_verifying_key="${POLICY_VERIFYING_KEY:-$repository_root/policies/keys/demo-signing-public.pem}"
policy_untrusted_key="${POLICY_UNTRUSTED_KEY:-$repository_root/policies/keys/demo-untrusted-private.pem}"
policy_opa_image="${POLICY_OPA_IMAGE:-openpolicyagent/opa:1.17.0-static}"
policy_workspace="$(mktemp -d)"
trap 'rm -rf "$policy_workspace"' EXIT INT TERM

run_opa_source() {
  docker run --rm \
    -v "$policy_source:/source:ro" \
    "$policy_opa_image" "$@"
}

echo "policy-ci: format"
run_opa_source fmt --fail --list /source

echo "policy-ci: compile"
run_opa_source check --strict /source

echo "policy-ci: tests"
run_opa_source test /source --fail-on-empty

echo "policy-ci: ownership"
grep -Fqx 'Platform/Security approval: required' "$policy_source/OWNERS.md"
grep -Fqx 'Resource owner approval: required' "$policy_source/OWNERS.md"

test -f "$policy_source/agent_tools.rego"
test -f "$policy_source/data.json"
test -f "$policy_signing_key"
test -f "$policy_verifying_key"
test -f "$policy_untrusted_key"

mkdir -p "$policy_workspace/bundle" "$policy_workspace/output"
cp "$policy_source/agent_tools.rego" "$policy_source/data.json" "$policy_workspace/bundle/"

echo "policy-ci: bundle"
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$policy_workspace/bundle:/bundle:ro" \
  -v "$policy_workspace/output:/output" \
  -v "$policy_signing_key:/keys/signing.pem:ro" \
  "$policy_opa_image" build --bundle /bundle \
    --revision "$policy_revision" \
    --signing-alg ES256 \
    --signing-key /keys/signing.pem \
    --output /output/agent-tools-bundle.tar.gz

docker run --rm --user "$(id -u):$(id -g)" \
  -v "$policy_workspace/bundle:/bundle:ro" \
  -v "$policy_workspace/output:/output" \
  -v "$policy_untrusted_key:/keys/untrusted.pem:ro" \
  "$policy_opa_image" build --bundle /bundle \
    --revision "${policy_revision}-untrusted-update" \
    --signing-alg ES256 \
    --signing-key /keys/untrusted.pem \
    --output /output/invalid-signature-fixture.tar.gz

mkdir -p "$policy_output"
rm -f "$policy_output/agent-tools-bundle.tar.gz" "$policy_output/invalid-signature-fixture.tar.gz"
cp "$policy_workspace/output/agent-tools-bundle.tar.gz" "$policy_workspace/output/invalid-signature-fixture.tar.gz" "$policy_output/"
echo "policy-ci: published revision=$policy_revision"
