#!/usr/bin/env python3
import argparse
import collections
import json
import random
import socket
import string
import threading
import time


HOST = "127.0.0.1"
PORT = 18080
UA_POOL = [
    "Mozilla/5.0 Chrome/121",
    "Mozilla/5.0 Safari/605",
    "Mozilla/5.0 Firefox/122",
    "okhttp/4.10",
    "curl/8.0",
]
lock = threading.Lock()
counts = collections.Counter()
latencies = []


def cdn_ip(index):
    return f"127.10.{(index // 250) % 200}.{1 + index % 250}"


def user_ip(index, seq, mode):
    if mode == "normal":
        return f"198.51.{(index // 250) % 80}.{1 + (index + seq) % 250}"
    return f"10.{(index // 600) % 220}.{(index // 250) % 250}.{1 + (index * 17 + seq) % 250}"


def read_resp(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(8192)
        if not chunk:
            return None
        data += chunk
        if len(data) > 131072:
            break
    try:
        head, rest = data.split(b"\r\n\r\n", 1)
    except ValueError:
        return -1
    try:
        status = int(head.split(b" ", 2)[1])
    except Exception:
        status = -1
    content_length = 0
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            try:
                content_length = int(line.split(b":", 1)[1].strip())
            except Exception:
                pass
    need = max(0, content_length - len(rest))
    while need:
        chunk = sock.recv(min(8192, need))
        if not chunk:
            break
        need -= len(chunk)
    return status


def make_request(index, seq, mode):
    ip = user_ip(index, seq, mode)
    if mode == "normal":
        path = f"/api/login?cc=1&n={seq % 8}"
        user_agent = "cc-bot/1.0"
        extra = "Accept: */*\r\n"
    else:
        route = random.choice(
            ["/api/search", "/api/login", "/api/profile", "/api/cart", "/api/order", "/asset/app.js"]
        )
        query = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(6, 22)))
        path = f"{route}?q={query}&p={seq % 50}&r={random.randint(1, 999999)}"
        user_agent = random.choice(UA_POOL) + " " + "".join(random.choices(string.ascii_letters, k=6))
        cookie = "sid=" + "".join(random.choices(string.ascii_letters + string.digits, k=24))
        extra = (
            "Accept: text/html,application/json,*/*;q=0.8\r\n"
            "Accept-Language: zh-CN,zh;q=0.9,en;q=0.7\r\n"
            f"Referer: https://www.example.com/{random.randint(1, 999)}\r\n"
            f"Cookie: {cookie}\r\n"
        )
    return (
        f"GET {path} HTTP/1.1\r\n"
        "Host: cdn.local\r\n"
        f"User-Agent: {user_agent}\r\n"
        f"X-Forwarded-For: {ip}\r\n"
        f"X-Real-IP: {ip}\r\n"
        "CDN-Loop: test-cdn\r\n"
        f"{extra}"
        "Connection: keep-alive\r\n\r\n"
    ).encode()


def worker(index, seconds, mode, timeout):
    local_counts = collections.Counter()
    local_latencies = []
    seq = 0
    sock = None
    end = time.time() + seconds
    while time.time() < end:
        try:
            if sock is None:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((cdn_ip(index), 0))
                sock.settimeout(timeout)
                sock.connect((HOST, PORT))
            request = make_request(index, seq, mode)
            started = time.time()
            sock.sendall(request)
            status = read_resp(sock)
            local_latencies.append((time.time() - started) * 1000)
            local_counts[str(status)] += 1
            seq += 1
            if status is None:
                try:
                    sock.close()
                except Exception:
                    pass
                sock = None
        except Exception as exc:
            local_counts["err:" + exc.__class__.__name__] += 1
            try:
                if sock:
                    sock.close()
            except Exception:
                pass
            sock = None
    if sock:
        try:
            sock.close()
        except Exception:
            pass
    with lock:
        counts.update(local_counts)
        latencies.extend(local_latencies)


def percentile(values, pct):
    if not values:
        return 0
    return values[min(len(values) - 1, int(len(values) * pct / 100))]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["normal", "advanced"], required=True)
    parser.add_argument("--threads", type=int, default=512)
    parser.add_argument("--seconds", type=int, default=90)
    parser.add_argument("--timeout", type=float, default=0.5)
    args = parser.parse_args()

    start = time.time()
    threads = []
    for index in range(args.threads):
        thread = threading.Thread(target=worker, args=(index, args.seconds, args.mode, args.timeout), daemon=True)
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()

    elapsed = time.time() - start
    total = sum(value for key, value in counts.items() if key.isdigit())
    sorted_latencies = sorted(latencies)
    print(
        json.dumps(
            {
                "mode": args.mode,
                "seconds": round(elapsed, 2),
                "threads": args.threads,
                "timeout": args.timeout,
                "responses": total,
                "rps": round(total / elapsed, 2),
                "counts": dict(sorted(counts.items())),
                "lat_ms": {
                    "p50": round(percentile(sorted_latencies, 50), 2),
                    "p95": round(percentile(sorted_latencies, 95), 2),
                    "p99": round(percentile(sorted_latencies, 99), 2),
                    "max": round(max(sorted_latencies) if sorted_latencies else 0, 2),
                },
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
