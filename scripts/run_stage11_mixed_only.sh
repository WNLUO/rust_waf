#!/usr/bin/env bash
set -euo pipefail

ART="$(cat /root/rust_waf_test/stage11-latest-artifact.txt)"
mkdir -p "$ART/raw"

run_one() {
  local name="$1" target="$2" normal_ratio="$3" seconds="$4" real_ips="$5" threads="$6"
  echo "[$(date --iso-8601=seconds)] rerun mixed $name"
  docker restart rust_waf_2c512m >/dev/null
  for _ in $(seq 1 45); do
    curl -fsS http://127.0.0.1:13740/metrics >/dev/null 2>&1 && break
    sleep 1
  done
  curl -fsS http://127.0.0.1:13740/metrics > "$ART/raw/${name}-before.json"
  sample="$ART/raw/${name}-samples.jsonl"
  : > "$sample"
  (
    while true; do
      ts=$(date +%s)
      stat=$(docker stats --no-stream --format '{{.CPUPerc}}|{{.MemUsage}}' rust_waf_2c512m 2>/dev/null || echo '|')
      metrics=$(curl -m 1 -fsS http://127.0.0.1:13740/metrics 2>/dev/null || echo '{}')
      python3 - "$name" "$ts" "$stat" "$metrics" >> "$sample" <<'PY'
import json, sys
scenario, ts, stat, metrics = sys.argv[1:5]
cpu, mem = (stat.split("|", 1) + [""])[:2]
try:
    j = json.loads(metrics)
except Exception:
    j = {}
item = {"scenario": scenario, "ts": int(ts), "cpu": cpu, "mem": mem}
for key in ["blocked_packets","blocked_l7","proxied_requests","proxy_successes","proxy_failures","l7_cc_fast_path_requests","l7_cc_fast_path_blocks","l7_cc_fast_path_no_decisions","l7_cc_hot_cache_hits","l7_cc_hot_cache_misses","sqlite_queue_depth","sqlite_dropped_security_events","runtime_pressure_level","runtime_defense_depth","runtime_pressure_cpu_percent","runtime_pressure_cpu_score"]:
    item[key] = j.get(key)
print(json.dumps(item, ensure_ascii=False))
PY
      sleep 1
    done
  ) &
  spid=$!
  python3 /root/rust_waf_test/cdn_cc_mixed_openloop.py \
    --host-header cdn.local \
    --threads "$threads" \
    --seconds "$seconds" \
    --target-rps "$target" \
    --normal-ratio "$normal_ratio" \
    --source-count 4096 \
    --real-ip-count "$real_ips" \
    --normal-ip-count 512 \
    --timeout 0.5 > "$ART/raw/${name}.out"
  kill "$spid" >/dev/null 2>&1 || true
  wait "$spid" >/dev/null 2>&1 || true
  curl -fsS http://127.0.0.1:13740/metrics > "$ART/raw/${name}-after.json"
  python3 - "$sample" "$ART/raw/${name}-before.json" "$ART/raw/${name}-after.json" "$ART/raw/${name}.out" "$name" "$seconds" > "$ART/raw/${name}-summary.json" <<'PY'
import json, re, statistics, sys
sample, before, after, result, name, seconds = sys.argv[1:7]
rows = [json.loads(line) for line in open(sample) if line.strip()]
b = json.load(open(before)); a = json.load(open(after)); r = json.load(open(result))
def cpu(v):
    try: return float(str(v).replace("%", ""))
    except Exception: return 0.0
def mem(v):
    m = re.search(r"([0-9.]+)(MiB|GiB)", str(v))
    return 0.0 if not m else float(m.group(1)) * (1024 if m.group(2) == "GiB" else 1)
keys = ["blocked_packets","blocked_l7","proxied_requests","proxy_successes","proxy_failures","l7_cc_fast_path_requests","l7_cc_fast_path_blocks","l7_cc_fast_path_no_decisions","l7_cc_hot_cache_hits","l7_cc_hot_cache_misses","sqlite_queue_depth","sqlite_dropped_security_events"]
delta = {k: a.get(k,0)-b.get(k,0) for k in keys if isinstance(a.get(k), (int,float)) and isinstance(b.get(k), (int,float))}
duration = float(r.get("duration", seconds))
effective = delta.get("blocked_l7", 0) + delta.get("proxied_requests", 0)
summary = {
    "scenario": name,
    "client": r,
    "samples": len(rows),
    "avg_cpu_pct": round(statistics.fmean([cpu(x.get("cpu")) for x in rows]), 2) if rows else 0,
    "max_cpu_pct": max([cpu(x.get("cpu")) for x in rows] or [0]),
    "max_mem_mib": round(max([mem(x.get("mem")) for x in rows] or [0]), 1),
    "delta": delta,
    "effective_requests": effective,
    "effective_tps": round(effective / duration, 2) if duration else 0,
    "backend_success_rate": round(delta.get("proxy_successes",0) / max(delta.get("proxied_requests",0),1) * 100, 2) if delta.get("proxied_requests",0) else None,
    "hot_cache_effective_ratio_pct": round(delta.get("l7_cc_hot_cache_hits",0) / max(effective,1) * 100, 2),
    "last_sample": rows[-1] if rows else {},
}
print(json.dumps(summary, ensure_ascii=False, indent=2))
PY
  cat "$ART/raw/${name}-summary.json"
}

run_one mixed-cdnlocal-95-5-2200-180 2200 0.05 180 10000 768
run_one mixed-cdnlocal-90-10-2200-180 2200 0.10 180 10000 768
