#!/usr/bin/env python3
import argparse
import collections
import json
import random
import socket
import statistics
import struct
import threading
import time


def cdn_sources(count: int) -> list[str]:
    return [
        f"127.10.{(idx // 250) % 200}.{1 + idx % 250}"
        for idx in range(max(1, count))
    ]


def client_ip(index: int, real_ip_count: int) -> str:
    value = index % max(1, real_ip_count)
    return f"203.{value // 65536 % 250}.{value // 256 % 256}.{1 + value % 250}"


def attack_request(seq: int, real_ip_count: int, host_header: str) -> bytes:
    ip = client_ip(seq, real_ip_count)
    route = random.choice(
        ["/api/search", "/api/login", "/api/profile", "/api/cart", "/api/order"]
    )
    path = f"{route}?q={seq % 100000}&r={random.randrange(1_000_000)}"
    ua = f"Mozilla/5.0 MixedOpenLoop/{seq % 8192}.{random.randrange(8192)}"
    headers = [
        f"GET {path} HTTP/1.1",
        f"Host: {host_header}",
        f"User-Agent: {ua}",
        "Accept: application/json,*/*;q=0.8",
        f"X-Forwarded-For: {ip}, 127.10.0.1",
        f"X-Real-IP: {ip}",
        "CDN-Loop: test-cdn",
        "Connection: close",
        "",
        "",
    ]
    return "\r\n".join(headers).encode()


def normal_request(seq: int, normal_ip_count: int, host_header: str) -> bytes:
    ip = client_ip(seq, normal_ip_count)
    route = random.choice(["/", "/dashboard", "/health", "/static/app.js"])
    path = f"{route}?n={seq % 256}"
    fp = f"normal-{seq % max(1, normal_ip_count)}"
    headers = [
        f"GET {path} HTTP/1.1",
        f"Host: {host_header}",
        "User-Agent: Mozilla/5.0 LegitBrowser/1.0",
        "Accept: text/html,application/xhtml+xml,application/json,*/*;q=0.8",
        "Accept-Language: zh-CN,zh;q=0.9,en;q=0.7",
        "Sec-Fetch-Site: same-origin",
        "Sec-Fetch-Mode: navigate",
        "Sec-Fetch-Dest: document",
        f"X-Browser-Fingerprint-Id: {fp}",
        f"Cookie: rwaf_fp={fp}; session=legit-{seq % 4096}",
        f"X-Forwarded-For: {ip}, 127.10.0.1",
        f"X-Real-IP: {ip}",
        "CDN-Loop: test-cdn",
        "Connection: close",
        "",
        "",
    ]
    return "\r\n".join(headers).encode()


def read_status(sock: socket.socket) -> int:
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 131072:
        chunk = sock.recv(8192)
        if not chunk:
            return 0
        data += chunk
    try:
        head, rest = data.split(b"\r\n\r\n", 1)
        status = int(head.split(b" ", 2)[1])
    except Exception:
        return -1

    content_length = 0
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            try:
                content_length = int(line.split(b":", 1)[1].strip())
            except Exception:
                content_length = 0
    need = max(0, content_length - len(rest))
    while need > 0:
        chunk = sock.recv(min(8192, need))
        if not chunk:
            break
        need -= len(chunk)
    return status


def worker(args, worker_id, start_at, stop_at, stats, lock):
    interval = args.threads / args.target_rps
    next_send = start_at + worker_id * interval / max(args.threads, 1)
    sources = cdn_sources(args.source_count)
    rng = random.Random(worker_id * 104729 + int(start_at))
    local = {
        "attempted": 0,
        "sent": 0,
        "attack_attempted": 0,
        "attack_sent": 0,
        "normal_attempted": 0,
        "normal_sent": 0,
        "errors": 0,
        "error_counts": collections.Counter(),
        "late_sends": 0,
        "max_lag_ms": 0.0,
        "normal_counts": collections.Counter(),
        "normal_latencies": [],
    }

    while True:
        now = time.perf_counter()
        if now >= stop_at:
            break
        if now < next_send:
            time.sleep(min(next_send - now, 0.002))
            continue

        lag_ms = max(0.0, (now - next_send) * 1000.0)
        if lag_ms > 5.0:
            local["late_sends"] += 1
            local["max_lag_ms"] = max(local["max_lag_ms"], lag_ms)

        seq = local["attempted"] * args.threads + worker_id
        is_normal = rng.random() < args.normal_ratio
        req = (
            normal_request(seq, args.normal_ip_count, args.host_header)
            if is_normal
            else attack_request(seq, args.real_ip_count, args.host_header)
        )
        local["attempted"] += 1
        local["normal_attempted" if is_normal else "attack_attempted"] += 1
        started = time.perf_counter()
        try:
            source = rng.choice(sources)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if args.linger_rst and not is_normal:
                    sock.setsockopt(
                        socket.SOL_SOCKET,
                        socket.SO_LINGER,
                        struct.pack("ii", 1, 0),
                    )
                sock.settimeout(args.timeout)
                sock.bind((source, 0))
                sock.connect((args.host, args.port))
                sock.sendall(req)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                if is_normal:
                    status = read_status(sock)
                    local["normal_counts"][str(status)] += 1
                    local["normal_latencies"].append(
                        (time.perf_counter() - started) * 1000
                    )
                elif args.read_attack:
                    _ = read_status(sock)
            local["sent"] += 1
            local["normal_sent" if is_normal else "attack_sent"] += 1
        except OSError as exc:
            local["errors"] += 1
            key = f"{exc.__class__.__name__}:{getattr(exc, 'errno', 'na')}"
            local["error_counts"][key] += 1
        next_send += interval
        if next_send < time.perf_counter() - 1:
            next_send = time.perf_counter()

    with lock:
        for key in [
            "attempted",
            "sent",
            "attack_attempted",
            "attack_sent",
            "normal_attempted",
            "normal_sent",
            "errors",
            "late_sends",
        ]:
            stats[key] += local[key]
        stats["max_lag_ms"] = max(stats["max_lag_ms"], local["max_lag_ms"])
        stats["error_counts"].update(local["error_counts"])
        stats["normal_counts"].update(local["normal_counts"])
        stats["normal_latencies"].extend(local["normal_latencies"])


def percentile(values, pct):
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(len(ordered) * pct / 100))
    return ordered[idx]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--host-header", default="cdn.local")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--threads", type=int, default=512)
    parser.add_argument("--seconds", type=float, default=120)
    parser.add_argument("--target-rps", type=float, required=True)
    parser.add_argument("--normal-ratio", type=float, default=0.05)
    parser.add_argument("--timeout", type=float, default=0.5)
    parser.add_argument("--source-count", type=int, default=2048)
    parser.add_argument("--real-ip-count", type=int, default=10000)
    parser.add_argument("--normal-ip-count", type=int, default=256)
    parser.add_argument("--linger-rst", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--read-attack", action="store_true")
    args = parser.parse_args()

    start = time.perf_counter() + 1.0
    stop = start + args.seconds
    stats = {
        "attempted": 0,
        "sent": 0,
        "attack_attempted": 0,
        "attack_sent": 0,
        "normal_attempted": 0,
        "normal_sent": 0,
        "errors": 0,
        "late_sends": 0,
        "max_lag_ms": 0.0,
        "error_counts": collections.Counter(),
        "normal_counts": collections.Counter(),
        "normal_latencies": [],
    }
    lock = threading.Lock()
    threads = [
        threading.Thread(target=worker, args=(args, idx, start, stop, stats, lock), daemon=True)
        for idx in range(args.threads)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    duration = max(time.perf_counter() - start, 0.001)
    normal_latencies = stats["normal_latencies"]
    normal_success = sum(
        count
        for status, count in stats["normal_counts"].items()
        if status.isdigit() and 200 <= int(status) < 400
    )
    print(
        json.dumps(
            {
                "duration": round(duration, 2),
                "target_rps": args.target_rps,
                "threads": args.threads,
                "normal_ratio": args.normal_ratio,
                "source_count": args.source_count,
                "real_ip_count": args.real_ip_count,
                "normal_ip_count": args.normal_ip_count,
                "attempted": stats["attempted"],
                "sent": stats["sent"],
                "attack_attempted": stats["attack_attempted"],
                "attack_sent": stats["attack_sent"],
                "normal_attempted": stats["normal_attempted"],
                "normal_sent": stats["normal_sent"],
                "send_errors": stats["errors"],
                "error_counts": dict(sorted(stats["error_counts"].items())),
                "actual_send_rps": round(stats["sent"] / duration, 2),
                "attempted_rps": round(stats["attempted"] / duration, 2),
                "normal_counts": dict(sorted(stats["normal_counts"].items())),
                "normal_success": normal_success,
                "normal_success_rate": round(
                    normal_success / max(stats["normal_sent"], 1) * 100, 2
                ),
                "late_sends": stats["late_sends"],
                "max_schedule_lag_ms": round(stats["max_lag_ms"], 2),
                "normal_lat_ms": {
                    "p50": round(statistics.median(normal_latencies), 2)
                    if normal_latencies
                    else 0,
                    "p95": round(percentile(normal_latencies, 95), 2),
                    "p99": round(percentile(normal_latencies, 99), 2),
                    "max": round(max(normal_latencies), 2) if normal_latencies else 0,
                },
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
