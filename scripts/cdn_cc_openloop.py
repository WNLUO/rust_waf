#!/usr/bin/env python3
import argparse
import json
import random
import socket
import statistics
import struct
import threading
import time


HOST = "127.0.0.1"
PORT = 18080


def cdn_sources(count: int) -> list[str]:
    return [
        f"127.10.{(idx // 250) % 200}.{1 + idx % 250}"
        for idx in range(max(1, count))
    ]


def make_request(mode: str, worker_id: int, seq: int) -> bytes:
    if mode == "advanced":
        client_octet = (worker_id * 131 + seq) % 240 + 10
        client_ip = f"203.0.{(worker_id + seq) % 255}.{client_octet}"
        path = f"/api/search?q={seq % 100000}&_={random.randrange(1_000_000)}"
        ua = f"Mozilla/5.0 Stage9OpenLoop/{worker_id}.{seq % 8192}"
        headers = [
            f"GET {path} HTTP/1.1",
            "Host: example.com",
            f"User-Agent: {ua}",
            "Accept: */*",
            f"X-Forwarded-For: {client_ip}, 127.10.0.1",
            f"X-Real-IP: {client_ip}",
            "Connection: close",
            "",
            "",
        ]
    else:
        client_ip = f"198.51.100.{(worker_id * 17 + seq) % 240 + 10}"
        headers = [
            "GET /api/search HTTP/1.1",
            "Host: example.com",
            "User-Agent: Stage9OpenLoop",
            "Accept: */*",
            f"X-Forwarded-For: {client_ip}",
            "Connection: close",
            "",
            "",
        ]
    return "\r\n".join(headers).encode()


def worker(args, worker_id, start_at, stop_at, stats, lock):
    interval = args.threads / args.target_rps
    next_send = start_at + worker_id * interval / max(args.threads, 1)
    sources = cdn_sources(args.source_count)
    sent = 0
    attempted = 0
    errors = 0
    error_counts = {}
    late_sends = 0
    max_lag_ms = 0.0
    latencies = []
    rng = random.Random(worker_id * 104729 + int(start_at))

    while True:
        now = time.perf_counter()
        if now >= stop_at:
            break
        if now < next_send:
            time.sleep(min(next_send - now, 0.002))
            continue

        lag_ms = max(0.0, (now - next_send) * 1000.0)
        if lag_ms > 5.0:
            late_sends += 1
            max_lag_ms = max(max_lag_ms, lag_ms)
        attempted += 1
        started = time.perf_counter()
        try:
            source = rng.choice(sources)
            req = make_request(args.mode, worker_id, sent)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if args.linger_rst:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                sock.settimeout(args.timeout)
                sock.bind((source, 0))
                sock.connect((HOST, PORT))
                sock.sendall(req)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                if args.read:
                    try:
                        sock.recv(128)
                    except OSError:
                        pass
            sent += 1
            latencies.append((time.perf_counter() - started) * 1000)
        except OSError as exc:
            errors += 1
            key = f"{exc.__class__.__name__}:{getattr(exc, 'errno', 'na')}"
            error_counts[key] = error_counts.get(key, 0) + 1
        next_send += interval
        if next_send < time.perf_counter() - 1:
            next_send = time.perf_counter()

    with lock:
        stats["attempted"] += attempted
        stats["sent"] += sent
        stats["errors"] += errors
        for key, value in error_counts.items():
            stats["error_counts"][key] = stats["error_counts"].get(key, 0) + value
        stats["late_sends"] += late_sends
        stats["max_lag_ms"] = max(stats["max_lag_ms"], max_lag_ms)
        stats["latencies"].extend(latencies)


def percentile(values, pct):
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(len(ordered) * pct / 100))
    return ordered[idx]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["regular", "advanced"], default="advanced")
    parser.add_argument("--threads", type=int, default=256)
    parser.add_argument("--seconds", type=float, default=120)
    parser.add_argument("--target-rps", type=float, required=True)
    parser.add_argument("--timeout", type=float, default=0.25)
    parser.add_argument("--source-count", type=int, default=2048)
    parser.add_argument("--linger-rst", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--read", action="store_true")
    args = parser.parse_args()

    start = time.perf_counter() + 1.0
    stop = start + args.seconds
    stats = {
        "attempted": 0,
        "sent": 0,
        "errors": 0,
        "error_counts": {},
        "late_sends": 0,
        "max_lag_ms": 0.0,
        "latencies": [],
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
    latencies = stats["latencies"]
    print(
        json.dumps(
            {
                "mode": args.mode,
                "duration": duration,
                "target_rps": args.target_rps,
                "threads": args.threads,
                "attempted": stats["attempted"],
                "sent": stats["sent"],
                "send_errors": stats["errors"],
                "error_counts": dict(sorted(stats["error_counts"].items())),
                "actual_send_rps": round(stats["sent"] / duration, 2),
                "attempted_rps": round(stats["attempted"] / duration, 2),
                "send_success_rate": round(stats["sent"] / max(stats["attempted"], 1) * 100, 2),
                "late_sends": stats["late_sends"],
                "max_schedule_lag_ms": round(stats["max_lag_ms"], 2),
                "p50": round(statistics.median(latencies), 2) if latencies else 0,
                "p95": round(percentile(latencies, 95), 2),
                "p99": round(percentile(latencies, 99), 2),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
