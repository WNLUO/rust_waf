#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
import time
import urllib.request


COUNTERS = [
    "blocked_packets",
    "blocked_l4",
    "blocked_l7",
    "l7_cc_blocks",
    "l7_cc_fast_path_requests",
    "l7_cc_fast_path_blocks",
    "l7_cc_fast_path_no_decisions",
    "l7_cc_hot_cache_hits",
    "l7_cc_hot_cache_misses",
    "l7_behavior_challenges",
    "l7_behavior_blocks",
    "proxied_requests",
    "proxy_successes",
    "proxy_failures",
    "proxy_fail_close_rejections",
    "l4_bucket_budget_rejections",
    "trusted_proxy_permit_drops",
    "trusted_proxy_l4_degrade_actions",
    "tls_handshake_failures",
    "slow_attack_blocks",
    "sqlite_queue_depth",
    "sqlite_dropped_security_events",
]


def fetch_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as response:
        return json.loads(response.read().decode())


def delta(before: dict, after: dict) -> dict:
    out = {}
    for key in COUNTERS:
        left = before.get(key)
        right = after.get(key)
        if isinstance(left, (int, float)) and isinstance(right, (int, float)):
            out[key] = right - left
    return out


def run_client(args) -> dict:
    cmd = [
        sys.executable,
        args.client_script,
        "--host",
        args.host,
        "--port",
        str(args.port),
        "--host-header",
        args.host_header,
        "--threads",
        str(args.threads),
        "--seconds",
        str(args.seconds),
        "--target-rps",
        str(args.target_rps),
        "--normal-ratio",
        str(args.normal_ratio),
        "--source-count",
        str(args.source_count),
        "--real-ip-count",
        str(args.real_ip_count),
        "--normal-ip-count",
        str(args.normal_ip_count),
        "--timeout",
        str(args.timeout),
    ]
    output = subprocess.check_output(cmd, text=True)
    return json.loads(output)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--metrics-url", default="http://127.0.0.1:13740/metrics")
    parser.add_argument("--client-script", default="scripts/cdn_cc_mixed_openloop.py")
    parser.add_argument("--scenario", default="normal-probe")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--host-header", default="cdn.local")
    parser.add_argument("--threads", type=int, default=64)
    parser.add_argument("--seconds", type=float, default=30)
    parser.add_argument("--target-rps", type=float, default=100)
    parser.add_argument("--normal-ratio", type=float, default=1.0)
    parser.add_argument("--source-count", type=int, default=128)
    parser.add_argument("--real-ip-count", type=int, default=10000)
    parser.add_argument("--normal-ip-count", type=int, default=512)
    parser.add_argument("--timeout", type=float, default=1.0)
    args = parser.parse_args()

    before = fetch_json(args.metrics_url)
    started = time.time()
    client = run_client(args)
    after = fetch_json(args.metrics_url)
    duration = max(time.time() - started, 0.001)
    counters = delta(before, after)
    proxied = counters.get("proxied_requests", 0)
    proxy_successes = counters.get("proxy_successes", 0)

    summary = {
        "scenario": args.scenario,
        "duration": round(duration, 2),
        "client": client,
        "delta": counters,
        "proxy_success_rate": round(proxy_successes / max(proxied, 1) * 100, 2)
        if proxied
        else None,
        "normal_success_rate": client.get("normal_success_rate"),
        "normal_zero_count": client.get("normal_counts", {}).get("0", 0),
        "normal_403_count": client.get("normal_counts", {}).get("403", 0),
        "normal_429_count": client.get("normal_counts", {}).get("429", 0),
        "normal_200_count": client.get("normal_counts", {}).get("200", 0),
        "runtime_before": {
            "pressure": before.get("runtime_pressure_level"),
            "depth": before.get("runtime_defense_depth"),
            "l4_overload": before.get("l4_overload_level"),
        },
        "runtime_after": {
            "pressure": after.get("runtime_pressure_level"),
            "depth": after.get("runtime_defense_depth"),
            "l4_overload": after.get("l4_overload_level"),
        },
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
