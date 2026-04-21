#!/usr/bin/env bash
set -u

ART="$(cat /root/rust_waf_test/stage11-latest-artifact.txt)"
mkdir -p "$ART/raw"
LOG="$ART/stage11-commands.log"
: > "$LOG"

run_cmd() {
  echo "[$(date --iso-8601=seconds)] $*" | tee -a "$LOG"
  "$@" 2>&1 | tee -a "$LOG"
}

run_stage9() {
  local name="$1" mode="$2" threads="$3" seconds="$4" driver="$5" target="$6"
  run_cmd /root/rust_waf_test/run_stage9_case.sh \
    "$ART" "$name" "$mode" "$threads" "$seconds" "$driver" "$target"
}

run_mixed() {
  local name="$1" target="$2" normal_ratio="$3" seconds="$4" real_ips="$5" threads="${6:-512}"
  echo "[$(date --iso-8601=seconds)] mixed $name target=$target normal=$normal_ratio seconds=$seconds real_ips=$real_ips" | tee -a "$LOG"

  docker restart rust_waf_2c512m >/dev/null
  for _ in $(seq 1 45); do
    curl -fsS http://127.0.0.1:13740/metrics >/dev/null 2>&1 && break
    sleep 1
  done

  local since_ts
  since_ts=$(date --iso-8601=seconds)
  curl -fsS http://127.0.0.1:13740/metrics > "$ART/raw/${name}-before.json"
  local sample="$ART/raw/${name}-samples.jsonl"
  : > "$sample"

  (
    while true; do
      ts=$(date +%s)
      stat=$(docker stats --no-stream --format '{{.CPUPerc}}|{{.MemUsage}}' rust_waf_2c512m 2>/dev/null || echo '|')
      state=$(docker inspect rust_waf_2c512m --format '{{.State.Status}}|{{.State.OOMKilled}}|{{.State.ExitCode}}' 2>/dev/null || echo 'gone|unknown|')
      metrics=$(curl -m 1 -fsS http://127.0.0.1:13740/metrics 2>/dev/null || echo '{}')
      python3 - "$name" "$ts" "$stat" "$state" "$metrics" >> "$sample" <<'PY'
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
for key in [
    "total_packets",
    "blocked_packets",
    "blocked_l7",
    "proxied_requests",
    "proxy_successes",
    "proxy_failures",
    "l7_cc_fast_path_requests",
    "l7_cc_fast_path_blocks",
    "l7_cc_fast_path_no_decisions",
    "l7_cc_hot_cache_hits",
    "l7_cc_hot_cache_misses",
    "l7_cc_hot_cache_expired",
    "sqlite_queue_depth",
    "sqlite_dropped_security_events",
    "runtime_pressure_level",
    "runtime_defense_depth",
    "runtime_pressure_cpu_percent",
    "runtime_pressure_cpu_score",
]:
    item[key] = j.get(key)
print(json.dumps(item, ensure_ascii=False))
PY
      sleep 1
    done
  ) &
  spid=$!

  python3 /root/rust_waf_test/cdn_cc_mixed_openloop.py \
    --threads "$threads" \
    --seconds "$seconds" \
    --target-rps "$target" \
    --host-header cdn.local \
    --normal-ratio "$normal_ratio" \
    --source-count 4096 \
    --real-ip-count "$real_ips" \
    --normal-ip-count 512 \
    --timeout 0.5 > "$ART/raw/${name}.out"

  kill "$spid" >/dev/null 2>&1 || true
  wait "$spid" >/dev/null 2>&1 || true
  curl -fsS http://127.0.0.1:13740/metrics > "$ART/raw/${name}-after.json"
  docker logs --since "$since_ts" rust_waf_2c512m > "$ART/raw/${name}-logs.log" 2>&1 || true

  python3 - "$sample" "$ART/raw/${name}-before.json" "$ART/raw/${name}-after.json" "$ART/raw/${name}.out" "$name" "$target" "$normal_ratio" "$seconds" "$real_ips" > "$ART/raw/${name}-summary.json" <<'PY'
import json
import re
import statistics
import sys

sample, before, after, result, name, target, normal_ratio, seconds, real_ips = sys.argv[1:10]
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
    "blocked_l7",
    "proxied_requests",
    "proxy_successes",
    "proxy_failures",
    "l7_cc_fast_path_requests",
    "l7_cc_fast_path_blocks",
    "l7_cc_fast_path_no_decisions",
    "l7_cc_hot_cache_hits",
    "l7_cc_hot_cache_misses",
    "l7_cc_hot_cache_expired",
    "sqlite_queue_depth",
    "sqlite_dropped_security_events",
]
delta = {
    key: a.get(key, 0) - b.get(key, 0)
    for key in keys
    if isinstance(a.get(key), (int, float)) and isinstance(b.get(key), (int, float))
}
duration = float(r.get("duration", seconds))
effective = delta.get("blocked_l7", 0) + delta.get("proxied_requests", 0)
fast = delta.get("l7_cc_fast_path_requests", 0)
summary = {
    "scenario": name,
    "target_rps": float(target),
    "normal_ratio": float(normal_ratio),
    "real_ip_count": int(real_ips),
    "client": r,
    "samples": len(rows),
    "avg_cpu_pct": round(statistics.fmean([cpu_value(row.get("cpu")) for row in rows]), 2) if rows else 0,
    "max_cpu_pct": max([cpu_value(row.get("cpu")) for row in rows] or [0]),
    "max_mem_mib": round(max([mem_value(row.get("mem")) for row in rows] or [0]), 1),
    "delta": delta,
    "effective_requests": effective,
    "effective_tps": round(effective / duration, 2) if duration else 0,
    "waf_verdict_rps": round(delta.get("blocked_packets", 0) / duration, 2) if duration else 0,
    "waf_proxy_rps": round(delta.get("proxied_requests", 0) / duration, 2) if duration else 0,
    "backend_success_rate": round(delta.get("proxy_successes", 0) / max(delta.get("proxied_requests", 0), 1) * 100, 2) if delta.get("proxied_requests", 0) else None,
    "hot_cache_effective_ratio_pct": round(delta.get("l7_cc_hot_cache_hits", 0) / max(effective, 1) * 100, 2),
    "fast_no_decision_ratio_pct": round(delta.get("l7_cc_fast_path_no_decisions", 0) / max(fast, 1) * 100, 2),
    "last_sample": rows[-1] if rows else {},
}
print(json.dumps(summary, ensure_ascii=False, indent=2))
PY
  cat "$ART/raw/${name}-summary.json" | tee -a "$LOG"
}

run_stage9 advanced-open-2000-120 advanced 512 120 open 2000
run_stage9 advanced-open-2200-120 advanced 512 120 open 2200
run_stage9 advanced-open-2500-120 advanced 768 120 open 2500
run_stage9 advanced-open-2100-600 advanced 768 600 open 2100
run_mixed mixed-95-5-2200-180 2200 0.05 180 10000 768
run_mixed mixed-90-10-2200-180 2200 0.10 180 10000 768
run_mixed high-card-10000ip-2200-180 2200 0.00 180 10000 768

echo "$ART" > /root/rust_waf_test/stage11-latest-artifact.txt
