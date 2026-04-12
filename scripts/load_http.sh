#!/usr/bin/env bash
set -euo pipefail

TARGET_URL="${1:-http://127.0.0.1:8080/}"
CONCURRENCY="${CONCURRENCY:-64}"
REQUESTS="${REQUESTS:-20000}"
DURATION="${DURATION:-30s}"
TIMEOUT="${TIMEOUT:-5s}"

echo "Target: ${TARGET_URL}"
echo "Concurrency: ${CONCURRENCY}"
echo "Requests: ${REQUESTS}"
echo "Duration: ${DURATION}"

if command -v wrk >/dev/null 2>&1; then
  exec wrk \
    --latency \
    --timeout "${TIMEOUT}" \
    -t "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)" \
    -c "${CONCURRENCY}" \
    -d "${DURATION}" \
    "${TARGET_URL}"
fi

if command -v hey >/dev/null 2>&1; then
  exec hey \
    -z "${DURATION}" \
    -c "${CONCURRENCY}" \
    -q 0 \
    "${TARGET_URL}"
fi

if command -v ab >/dev/null 2>&1; then
  exec ab \
    -k \
    -c "${CONCURRENCY}" \
    -n "${REQUESTS}" \
    "${TARGET_URL}"
fi

echo "Need one of: wrk, hey, ab" >&2
exit 1
