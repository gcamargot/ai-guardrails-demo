#!/bin/sh
set -eu

cleanup() {
  docker compose down --remove-orphans --volumes
}
trap cleanup EXIT INT TERM

docker compose up --build --wait gateway telegram-adapter
docker compose --profile test run --build --rm smoke

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
