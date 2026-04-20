#!/usr/bin/env bash
set -euo pipefail

ARTIFACT_DIR="$1"
SCENARIO="$2"
MODE="$3"
THREADS="$4"
DURATION_SECONDS="$5"
DRIVER="${6:-closed}"
TARGET_RPS="${7:-0}"

mkdir -p "$ARTIFACT_DIR/raw"

wait_metrics() {
  for _ in $(seq 1 45); do
    if curl -fsS http://127.0.0.1:13740/metrics >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

docker restart rust_waf_2c512m >/dev/null
wait_metrics

SINCE_TS=$(date --iso-8601=seconds)
curl -fsS http://127.0.0.1:13740/metrics > "$ARTIFACT_DIR/raw/${SCENARIO}-before.json"
SAMPLE="$ARTIFACT_DIR/raw/${SCENARIO}-samples.jsonl"
: > "$SAMPLE"

(
  while true; do
    ts=$(date +%s)
    stat=$(docker stats --no-stream --format '{{.CPUPerc}}|{{.MemUsage}}' rust_waf_2c512m 2>/dev/null || echo '|')
    state=$(docker inspect rust_waf_2c512m --format '{{.State.Status}}|{{.State.OOMKilled}}|{{.State.ExitCode}}' 2>/dev/null || echo 'gone|unknown|')
    metrics=$(curl -m 1 -fsS http://127.0.0.1:13740/metrics 2>/dev/null || echo '{}')
    python3 - "$SCENARIO" "$ts" "$stat" "$state" "$metrics" >> "$SAMPLE" <<'PY'
import json
import sys

scenario, ts, stat, state, metrics = sys.argv[1:6]
item = {"scenario": scenario, "ts": int(ts)}
cpu, mem = (stat.split("|", 1) + [""])[:2]
st, oom, code = (state.split("|") + ["", ""])[:3]
item.update({"cpu": cpu, "mem": mem, "status": st, "oom": oom, "exit": code})
try:
    j = json.loads(metrics)
except Exception:
    j = {}
keys = [
    "total_packets",
    "blocked_packets",
    "blocked_l4",
    "blocked_l7",
    "proxied_requests",
    "proxy_successes",
    "proxy_failures",
    "l7_cc_challenges",
    "l7_cc_blocks",
    "l7_cc_delays",
    "l7_cc_fast_path_requests",
    "l7_cc_fast_path_blocks",
    "l7_cc_fast_path_challenges",
    "l7_cc_fast_path_no_decisions",
    "l7_cc_hot_cache_hits",
    "l7_cc_hot_cache_misses",
    "l7_cc_hot_cache_expired",
    "trusted_proxy_l4_degrade_actions",
    "trusted_proxy_permit_drops",
    "sqlite_queue_depth",
    "sqlite_dropped_security_events",
    "persisted_security_events",
    "runtime_pressure_level",
    "runtime_defense_depth",
    "runtime_pressure_cpu_percent",
    "runtime_pressure_cpu_score",
    "runtime_pressure_cpu_sample_available",
]
for key in keys:
    item[key] = j.get(key)
print(json.dumps(item, ensure_ascii=False))
PY
    sleep 1
  done
) &
SPID=$!

if [ "$DRIVER" = "open" ]; then
  if [ "$TARGET_RPS" = "0" ]; then
    echo "open driver requires TARGET_RPS" >&2
    exit 2
  fi
  python3 /root/rust_waf_test/cdn_cc_openloop.py --mode "$MODE" --threads "$THREADS" --seconds "$DURATION_SECONDS" --target-rps "$TARGET_RPS" > "$ARTIFACT_DIR/raw/${SCENARIO}.out"
elif [ "$DRIVER" = "tunable" ]; then
  TIMEOUT="${TARGET_RPS:-0.5}"
  python3 /root/rust_waf_test/cdn_cc_stress_tunable.py --mode "$MODE" --threads "$THREADS" --seconds "$DURATION_SECONDS" --timeout "$TIMEOUT" > "$ARTIFACT_DIR/raw/${SCENARIO}.out"
elif [ "$DRIVER" = "multi" ]; then
  PROCS="${TARGET_RPS:-2}"
  PIDS=""
  for idx in $(seq 1 "$PROCS"); do
    python3 /root/rust_waf_test/cdn_cc_stress.py --mode "$MODE" --threads "$THREADS" --seconds "$DURATION_SECONDS" > "$ARTIFACT_DIR/raw/${SCENARIO}.part${idx}.out" &
    PIDS="$PIDS $!"
  done
  for pid in $PIDS; do
    wait "$pid"
  done
  python3 - "$ARTIFACT_DIR/raw/${SCENARIO}.out" "$ARTIFACT_DIR/raw/${SCENARIO}".part*.out <<'PY'
import collections
import json
import sys

target = sys.argv[1]
items = [json.load(open(path)) for path in sys.argv[2:]]
counts = collections.Counter()
seconds = 0.0
threads = 0
responses = 0
p95_values = []
p99_values = []
max_values = []
for item in items:
    counts.update(item.get("counts", {}))
    seconds = max(seconds, float(item.get("seconds", 0)))
    threads += int(item.get("threads", 0))
    responses += int(item.get("responses", 0))
    lat = item.get("lat_ms", {})
    p95_values.append(float(lat.get("p95", 0)))
    p99_values.append(float(lat.get("p99", 0)))
    max_values.append(float(lat.get("max", 0)))
summary = {
    "mode": items[0].get("mode") if items else "unknown",
    "seconds": round(seconds, 2),
    "threads": threads,
    "processes": len(items),
    "responses": responses,
    "rps": round(responses / seconds, 2) if seconds else 0,
    "counts": dict(sorted(counts.items())),
    "lat_ms": {
        "p50": 0,
        "p95": round(max(p95_values or [0]), 2),
        "p99": round(max(p99_values or [0]), 2),
        "max": round(max(max_values or [0]), 2),
    },
}
json.dump(summary, open(target, "w"), ensure_ascii=False)
PY
else
  python3 /root/rust_waf_test/cdn_cc_stress.py --mode "$MODE" --threads "$THREADS" --seconds "$DURATION_SECONDS" > "$ARTIFACT_DIR/raw/${SCENARIO}.out"
fi
kill "$SPID" >/dev/null 2>&1 || true
wait "$SPID" >/dev/null 2>&1 || true

curl -fsS http://127.0.0.1:13740/metrics > "$ARTIFACT_DIR/raw/${SCENARIO}-after.json"
docker logs --since "$SINCE_TS" rust_waf_2c512m > "$ARTIFACT_DIR/raw/${SCENARIO}-logs.log" 2>&1 || true

python3 - "$SAMPLE" "$ARTIFACT_DIR/raw/${SCENARIO}-before.json" "$ARTIFACT_DIR/raw/${SCENARIO}-after.json" "$ARTIFACT_DIR/raw/${SCENARIO}.out" "$MODE" "$THREADS" "$DURATION_SECONDS" "$DRIVER" "$TARGET_RPS" > "$ARTIFACT_DIR/raw/${SCENARIO}-summary.json" <<'PY'
import json
import re
import statistics
import sys

sample, before, after, result, mode, threads, seconds, driver, target_rps = sys.argv[1:10]
rows = [json.loads(line) for line in open(sample) if line.strip()]
b = json.load(open(before))
a = json.load(open(after))
r = json.load(open(result))

def cpu_value(value):
    try:
        return float(str(value).replace("%", ""))
    except Exception:
        return 0.0

def mem_value(value):
    match = re.search(r"([0-9.]+)(MiB|GiB)", str(value))
    if not match:
        return 0.0
    return float(match.group(1)) * (1024 if match.group(2) == "GiB" else 1)

keys = [
    "total_packets",
    "blocked_packets",
    "blocked_l4",
    "blocked_l7",
    "proxied_requests",
    "proxy_successes",
    "proxy_failures",
    "l7_cc_challenges",
    "l7_cc_blocks",
    "l7_cc_delays",
    "l7_cc_fast_path_requests",
    "l7_cc_fast_path_blocks",
    "l7_cc_fast_path_challenges",
    "l7_cc_fast_path_no_decisions",
    "l7_cc_hot_cache_hits",
    "l7_cc_hot_cache_misses",
    "l7_cc_hot_cache_expired",
    "trusted_proxy_l4_degrade_actions",
    "trusted_proxy_permit_drops",
    "sqlite_queue_depth",
    "sqlite_dropped_security_events",
    "persisted_security_events",
]
delta = {}
for key in keys:
    if isinstance(a.get(key), (int, float)) and isinstance(b.get(key), (int, float)):
        delta[key] = a[key] - b[key]

effective = delta.get("blocked_l7", 0) + delta.get("proxied_requests", 0)
duration = float(r.get("duration", r.get("seconds", seconds)))
fast_requests = delta.get("l7_cc_fast_path_requests", 0)
blocked_l7 = delta.get("blocked_l7", 0)
proxied = delta.get("proxied_requests", 0)

summary = {
    "mode": mode,
    "threads": int(threads),
    "target_seconds": float(seconds),
    "driver": driver,
    "target_rps": float(target_rps),
    "result": r,
    "client_sent": r.get("sent"),
    "client_actual_send_rps": r.get("actual_send_rps"),
    "client_send_errors": r.get("send_errors"),
    "client_responses": r.get("responses"),
    "client_response_rps": r.get("rps"),
    "client_counts": r.get("counts"),
    "samples": len(rows),
    "avg_cpu_pct": round(statistics.fmean([cpu_value(row.get("cpu")) for row in rows]), 2) if rows else 0,
    "max_cpu_pct": max([cpu_value(row.get("cpu")) for row in rows] or [0]),
    "max_mem_mib": round(max([mem_value(row.get("mem")) for row in rows] or [0]), 1),
    "last_sample": rows[-1] if rows else {},
    "delta": delta,
    "effective_requests": effective,
    "effective_tps": round(effective / duration, 2) if duration else 0,
    "waf_verdict_rps": round(delta.get("blocked_packets", 0) / duration, 2) if duration else 0,
    "waf_proxy_rps": round(delta.get("proxied_requests", 0) / duration, 2) if duration else 0,
    "backend_success_rate": round(delta.get("proxy_successes", 0) / proxied * 100, 2) if proxied else None,
    "hot_cache_effective_ratio_pct": round(delta.get("l7_cc_hot_cache_hits", 0) / effective * 100, 2) if effective else 0,
    "fast_block_l7_ratio_pct": round(delta.get("l7_cc_fast_path_blocks", 0) / blocked_l7 * 100, 2) if blocked_l7 else 0,
    "fast_no_decision_ratio_pct": round(delta.get("l7_cc_fast_path_no_decisions", 0) / fast_requests * 100, 2) if fast_requests else 0,
    "container_state": rows[-1].get("status") if rows else None,
    "oom": rows[-1].get("oom") if rows else None,
}
print(json.dumps(summary, ensure_ascii=False, indent=2))
PY

cat "$ARTIFACT_DIR/raw/${SCENARIO}-summary.json"
