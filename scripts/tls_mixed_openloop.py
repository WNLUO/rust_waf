#!/usr/bin/env python3
import argparse
import json
import random
import socket
import ssl
import threading
import time
import urllib.request
from collections import Counter


parser = argparse.ArgumentParser()
parser.add_argument("--connect-host", default="127.0.0.1")
parser.add_argument("--port", type=int, default=8443)
parser.add_argument("--server-name", default="waf_test.uxu.me")
parser.add_argument("--metrics-url", default="http://127.0.0.1:3740/metrics")
parser.add_argument("--seconds", type=float, default=30)
parser.add_argument("--threads", type=int, default=64)
parser.add_argument("--target-rps", type=float, default=500)
parser.add_argument("--normal-ratio", type=float, default=0.1)
parser.add_argument("--attack-ips", type=int, default=12)
parser.add_argument("--normal-ips", type=int, default=128)
parser.add_argument("--source-ips", type=int, default=1)
parser.add_argument("--timeout", type=float, default=1.5)
args = parser.parse_args()

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(["http/1.1"])

lock = threading.Lock()
stop = threading.Event()
counts = Counter()
latencies = []

attack_ips = [f"198.51.100.{i % 250 + 1}" for i in range(args.attack_ips)]
normal_ips = [f"203.0.113.{i % 250 + 1}" for i in range(args.normal_ips)]
source_ips = [f"127.10.{i // 250}.{i % 250 + 1}" for i in range(args.source_ips)]
ua_normal = ["Mozilla/5.0 Chrome/122.0 Safari/537.36", "Mozilla/5.0 Firefox/123.0"]
ua_attack = ["curl/8.0", "python-requests/2.31", "Go-http-client/1.1"]


def fetch_metrics():
    with urllib.request.urlopen(args.metrics_url, timeout=3) as response:
        return json.loads(response.read().decode())


def one_request(kind, seq):
    real_ip = random.choice(normal_ips if kind == "normal" else attack_ips)
    if kind == "normal":
        path = random.choice(
            ["/", "/index.php", "/wp-content/themes/twentytwentyfour/style.css"]
        )
        path = f"{path}?n={seq}"
        ua = random.choice(ua_normal)
        cookie = f"rwaf_fp=normal-{real_ip.replace('.', '-')}; sessionid={seq % 1000}"
        extra = (
            "Sec-Fetch-Site: same-origin\r\n"
            "Sec-Fetch-Dest: document\r\n"
            "Accept: text/html,application/xhtml+xml\r\n"
        )
    else:
        path = random.choice(["/api/search", "/wp-login.php", "/xmlrpc.php", "/?s=test"])
        path = f"{path}?q={seq}&r={random.randint(1, 1000000)}"
        ua = random.choice(ua_attack)
        cookie = ""
        extra = "Accept: */*\r\n"

    cookie_header = f"Cookie: {cookie}\r\n" if cookie else ""
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {args.server_name}\r\n"
        f"User-Agent: {ua}\r\n"
        f"CF-Connecting-IP: {real_ip}\r\n"
        f"X-Forwarded-For: {real_ip}\r\n"
        f"X-Real-IP: {real_ip}\r\n"
        f"{extra}"
        f"{cookie_header}"
        "Connection: close\r\n\r\n"
    ).encode()

    started_at = time.time()
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(args.timeout)
        source_ip = random.choice(source_ips)
        if source_ip != "127.10.0.1" or args.source_ips > 1:
            raw.bind((source_ip, 0))
        raw.connect((args.connect_host, args.port))
        with ctx.wrap_socket(raw, server_hostname=args.server_name) as sock:
            sock.sendall(request)
            data = sock.recv(512)
        status = 0
        if data.startswith(b"HTTP/"):
            parts = data.split(None, 2)
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])
        elapsed = time.time() - started_at
        with lock:
            counts[f"{kind}_sent"] += 1
            counts[f"{kind}_status_{status}"] += 1
            if 200 <= status < 400:
                counts[f"{kind}_ok"] += 1
            elif status in (403, 429, 503):
                counts[f"{kind}_blocked"] += 1
            latencies.append(elapsed)
    except Exception as exc:
        with lock:
            counts[f"{kind}_sent"] += 1
            counts[f"{kind}_error"] += 1
            counts[f"err_{type(exc).__name__}"] += 1


def worker(thread_id):
    interval = args.threads / args.target_rps if args.target_rps > 0 else 0
    seq = thread_id
    next_at = time.time()
    while not stop.is_set():
        kind = "normal" if random.random() < args.normal_ratio else "attack"
        one_request(kind, seq)
        seq += args.threads
        next_at += interval
        delay = next_at - time.time()
        if delay > 0:
            time.sleep(delay)
        else:
            next_at = time.time()


def delta(before, after, key):
    return after.get(key, 0) - before.get(key, 0)


before = fetch_metrics()
started_at = time.time()
threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(args.threads)]
for thread in threads:
    thread.start()
time.sleep(args.seconds)
stop.set()
for thread in threads:
    thread.join(timeout=2)
after = fetch_metrics()

with lock:
    sorted_latencies = sorted(latencies)
    p50 = sorted_latencies[int(len(sorted_latencies) * 0.50)] if sorted_latencies else None
    p95 = sorted_latencies[int(len(sorted_latencies) * 0.95)] if sorted_latencies else None
    result = {
        "duration": round(time.time() - started_at, 3),
        "target_rps": args.target_rps,
        "normal_ratio": args.normal_ratio,
        "client_counts": dict(counts),
        "latency_p50_ms": round(p50 * 1000, 1) if p50 else None,
        "latency_p95_ms": round(p95 * 1000, 1) if p95 else None,
        "metric_deltas": {
            key: delta(before, after, key)
            for key in [
                "total_packets",
                "blocked_packets",
                "blocked_l4",
                "blocked_l7",
                "early_defense_drops_total",
                "early_defense_trusted_cdn_unresolved_drops",
                "early_defense_l4_request_budget_drops",
                "l7_drop_reason_cc_fast_block",
                "l7_drop_reason_cc_hard_block",
                "l7_cc_challenges",
                "l7_cc_blocks",
                "l7_cc_fast_path_requests",
                "l7_cc_fast_path_blocks",
                "l7_cc_fast_path_challenges",
                "proxied_requests",
                "proxy_successes",
                "proxy_failures",
                "trusted_proxy_permit_drops",
                "tls_handshake_timeouts",
                "tls_handshake_failures",
            ]
        },
        "runtime_after": {
            key: after.get(key)
            for key in [
                "runtime_pressure_level",
                "runtime_capacity_class",
                "runtime_defense_depth",
                "runtime_server_mode",
                "runtime_pressure_storage_queue_percent",
                "runtime_pressure_cpu_score",
                "runtime_pressure_cpu_percent",
                "resource_sentinel_mode",
                "resource_sentinel_cpu_pressure_score",
                "system_cpu_usage_percent",
                "system_memory_usage_percent",
            ]
            if key in after
        },
    }

print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
