#!/bin/sh
set -eu

cleanup() {
  docker compose down --remove-orphans
}
trap cleanup EXIT INT TERM

docker compose up --build --wait gateway
docker compose --profile test run --build --rm smoke
