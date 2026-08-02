#!/bin/sh
set -eu

cleanup() {
  docker compose down --remove-orphans --volumes
}
trap cleanup EXIT INT TERM

./scripts/policy-ci.sh
docker compose up --build --wait gateway telegram-adapter
docker compose --profile test run --build --rm smoke

docker compose --profile test run --rm telegram-network-probe
docker compose --profile test run --rm qwen-network-probe
docker compose --profile test run --rm codex-network-probe
docker compose --profile test run --rm replay-network-probe

docker compose --profile test run --no-deps --rm -e FAILURE_MODE=malformed-input smoke
docker compose exec -T coffee-station wget -q --post-data='' -O /dev/null http://127.0.0.1:8081/test/output/malformed
docker compose --profile test run --no-deps --rm -e FAILURE_MODE=malformed-output smoke
docker compose exec -T coffee-station wget -q --post-data='' -O /dev/null http://127.0.0.1:8081/test/output/valid

docker compose stop approval-authority
docker compose --profile test run --no-deps --rm -e FAILURE_MODE=approval smoke
docker compose up -d --wait approval-authority

docker compose stop opa
docker compose --profile test run --no-deps --rm -e FAILURE_MODE=opa smoke
docker compose start opa
opa_ready=false
for attempt in $(seq 1 30); do
  if docker compose exec -T gateway wget -q -O /dev/null 'http://opa:8181/health?bundles' 2>/dev/null; then
    opa_ready=true
    break
  fi
  sleep 1
done

if test "$opa_ready" != true; then
  docker compose logs --no-color opa policy-bundle >&2
  echo "OPA did not recover within 30 seconds" >&2
  exit 1
fi

docker compose --profile test run --no-deps --rm -e FAILURE_MODE=identity smoke

logs="$(docker compose logs --no-color)"
for forbidden in \
  'demo-calendar-credential' \
  'demo-outlook-credential' \
  'demo-smart-lock-credential' \
  'demo-reset-control-credential' \
  'insecure-prompt-only-credential' \
  'demo-telegram-webhook-secret' \
  'owner-demo-password' \
  'PROMPT_INJECTION_SENTINEL_7F3A' \
  'Ignore the prompt rule' \
  'ignore previous instructions'; do
  if printf '%s' "$logs" | grep -Fq "$forbidden"; then
    echo "sensitive body, secret or prompt leaked into service logs" >&2
    exit 1
  fi
done

adapter_event="$(printf '%s' "$logs" | grep -m 1 '"stage":"adapter_result"' || true)"
if test -z "$adapter_event"; then
  echo "no adapter_result span found in service logs" >&2
  exit 1
fi
for required in '"trace_id":"' '"traceparent":"00-' '"correlation_id":"' '"decision_id":"' '"tool":"' '"outcome":"' '"duration_micros":'; do
  if ! printf '%s' "$adapter_event" | grep -Fq "$required"; then
    echo "adapter_result span is missing $required" >&2
    exit 1
  fi
done
