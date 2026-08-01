#!/bin/sh
set -eu

cleanup() {
  docker compose down --remove-orphans
}
trap cleanup EXIT INT TERM

docker compose up --build --wait gateway telegram-adapter
docker compose --profile test run --build --rm smoke

if docker compose logs --no-color | grep -Fq 'demo-calendar-credential'; then
  echo "calendar credential leaked into service logs" >&2
  exit 1
fi
