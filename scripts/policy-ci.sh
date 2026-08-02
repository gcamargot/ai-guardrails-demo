#!/bin/sh
set -eu

repository_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
policy_source="${POLICY_SOURCE:-$repository_root/policies}"
policy_output="${POLICY_OUTPUT:-$repository_root/.artifacts/policy}"
policy_revision="${POLICY_REVISION:-}"
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

build_bundle() {
  signing_key="$1"
  revision="$2"
  output_name="$3"
  docker run --rm --user "$(id -u):$(id -g)" \
    -v "$policy_workspace/bundle:/bundle:ro" \
    -v "$policy_workspace/output:/output" \
    -v "$signing_key:/keys/signing.pem:ro" \
    "$policy_opa_image" build --bundle /bundle \
      --revision "$revision" \
      --signing-alg ES256 \
      --signing-key /keys/signing.pem \
      --output "/output/$output_name"
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

if test -z "$policy_revision"; then
  policy_revision="$(awk -F '"' '/"revision"/ {print $4; exit}' "$policy_source/data.json")"
fi
case "$policy_revision" in
  ''|*[!A-Za-z0-9._-]*)
    echo "policy-ci: revision must use only letters, digits, dot, underscore or hyphen" >&2
    exit 1
    ;;
esac

test -f "$policy_source/agent_tools.rego"
test -f "$policy_source/log_mask.rego"
test -f "$policy_signing_key"
test -f "$policy_verifying_key"
test -f "$policy_untrusted_key"

mkdir -p "$policy_workspace/bundle" "$policy_workspace/output" "$policy_workspace/verified"
cp "$policy_source/agent_tools.rego" "$policy_source/log_mask.rego" "$policy_workspace/bundle/"
printf '{"policy_metadata":{"revision":"%s"}}\n' "$policy_revision" >"$policy_workspace/bundle/data.json"

echo "policy-ci: bundle"
build_bundle "$policy_signing_key" "$policy_revision" agent-tools-bundle.tar.gz

echo "policy-ci: verify"
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$policy_workspace/output/agent-tools-bundle.tar.gz:/bundle.tar.gz:ro" \
  -v "$policy_verifying_key:/keys/verifying.pem:ro" \
  -v "$policy_workspace/verified:/verified" \
  "$policy_opa_image" build --bundle /bundle.tar.gz \
    --verification-key /keys/verifying.pem \
    --verification-key-id demo-policy-key \
    --signing-alg ES256 \
    --output /verified/verified.tar.gz

build_bundle "$policy_untrusted_key" "${policy_revision}-untrusted-update" invalid-signature-fixture.tar.gz

mkdir -p "$policy_output"
rm -f "$policy_output/agent-tools-bundle.tar.gz" "$policy_output/invalid-signature-fixture.tar.gz"
cp "$policy_workspace/output/agent-tools-bundle.tar.gz" "$policy_workspace/output/invalid-signature-fixture.tar.gz" "$policy_output/"
echo "policy-ci: published revision=$policy_revision"
