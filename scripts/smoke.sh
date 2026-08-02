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
  'demo-telegram-webhook-secret' \
  'owner-demo-password' \
  'PROMPT_INJECTION_SENTINEL_7F3A' \
  'ignore previous instructions'; do
  if printf '%s' "$logs" | grep -Fq "$forbidden"; then
    echo "sensitive body, secret or prompt leaked into service logs" >&2
    exit 1
  fi
done
