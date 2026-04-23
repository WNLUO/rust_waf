#!/usr/bin/env bash
set -euo pipefail

REMOTE_HOST="${REMOTE_HOST:-85.149.219.14}"
REMOTE_USER="${REMOTE_USER:-root}"
REMOTE_PASSWORD="${REMOTE_PASSWORD:-}"
OPTIMIZED_DIR="${OPTIMIZED_DIR:-/root/waf-test}"
OPTIMIZED_PORT="${OPTIMIZED_PORT:-18080}"
OPTIMIZED_METRICS_URL="${OPTIMIZED_METRICS_URL:-http://127.0.0.1:13740/metrics}"
HOST_HEADER="${HOST_HEADER:-test.local}"
PATH_TO_BLOCK="${PATH_TO_BLOCK:-/__block__}"
CONNECTIONS="${CONNECTIONS:-128}"
DURATION_SECONDS="${DURATION_SECONDS:-30}"

if [[ -z "${REMOTE_PASSWORD}" ]]; then
  echo "请先通过环境变量提供 REMOTE_PASSWORD" >&2
  exit 1
fi

if ! command -v sshpass >/dev/null 2>&1; then
  echo "缺少 sshpass，请先安装 sshpass" >&2
  exit 1
fi

export SSHPASS="${REMOTE_PASSWORD}"

REMOTE_ENV=(
  "REMOTE_HOST=${REMOTE_HOST}"
  "OPTIMIZED_DIR=${OPTIMIZED_DIR}"
  "OPTIMIZED_PORT=${OPTIMIZED_PORT}"
  "OPTIMIZED_METRICS_URL=${OPTIMIZED_METRICS_URL}"
  "HOST_HEADER=${HOST_HEADER}"
  "PATH_TO_BLOCK=${PATH_TO_BLOCK}"
  "CONNECTIONS=${CONNECTIONS}"
  "DURATION_SECONDS=${DURATION_SECONDS}"
)

sshpass -e ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  "${REMOTE_USER}@${REMOTE_HOST}" \
  "$(printf '%q ' "${REMOTE_ENV[@]}")python3 -" <<'PY'
import asyncio
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import time
import urllib.request

optimized_dir = os.environ["OPTIMIZED_DIR"]
optimized_port = int(os.environ["OPTIMIZED_PORT"])
optimized_metrics_url = os.environ["OPTIMIZED_METRICS_URL"]
host_header = os.environ["HOST_HEADER"]
path_to_block = os.environ["PATH_TO_BLOCK"]
connections = int(os.environ["CONNECTIONS"])
duration_seconds = int(os.environ["DURATION_SECONDS"])


def waf_processes():
    output = subprocess.run(["pgrep", "-af", "waf"], capture_output=True, text=True)
    for line in output.stdout.strip().splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2:
            continue
        pid, cmdline = parts
        try:
            cwd = os.readlink(f"/proc/{pid}/cwd")
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            continue
        yield int(pid), cmdline, cwd, exe


def stop_optimized():
    expected_exe = f"{optimized_dir}/target/release/waf"
    for pid, cmdline, cwd, exe in waf_processes():
        if exe == expected_exe or (cwd == optimized_dir and cmdline.startswith("./target/release/waf")):
            os.kill(pid, signal.SIGTERM)
    time.sleep(1)


def start_optimized():
    log = open("/tmp/waf-intercept-stress.log", "w", encoding="utf-8")
    subprocess.Popen(
        ["./target/release/waf"],
        cwd=optimized_dir,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    time.sleep(2)


def optimized_pid():
    expected_exe = f"{optimized_dir}/target/release/waf"
    for pid, cmdline, cwd, exe in waf_processes():
        if exe == expected_exe or (cwd == optimized_dir and cmdline.startswith("./target/release/waf")):
            return pid
    raise RuntimeError("未找到优化版 waf 进程")


def rss_kb(pid):
    with open(f"/proc/{pid}/status", encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    raise RuntimeError("未找到 VmRSS")


def cpu_jiffies(pid):
    with open(f"/proc/{pid}/stat", encoding="utf-8") as handle:
        fields = handle.read().split()
    return int(fields[13]) + int(fields[14])


def configure_db():
    db_path = os.path.join(optimized_dir, "data", "waf.db")
    for suffix in ("-wal", "-shm"):
        path = f"{db_path}{suffix}"
        if os.path.exists(path):
            os.remove(path)
    backup = f"{db_path}.intercept-stress.bak.{int(time.time())}"
    shutil.copy2(db_path, backup)
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("SELECT config_json FROM app_config WHERE id = 1").fetchone()
        config = json.loads(row[0])
        config["listen_addrs"] = [f"127.0.0.1:{optimized_port}"]
        config["api_enabled"] = True
        config["api_bind"] = optimized_metrics_url.replace("http://", "").rsplit("/", 1)[0]
        config.setdefault("gateway_config", {})["https_listen_addr"] = ""
        config.setdefault("http3_config", {})["enabled"] = False
        config.setdefault("http3_config", {})["listen_addr"] = "127.0.0.1:0"
        config.setdefault("l4_config", {})["ddos_protection_enabled"] = False
        config.setdefault("l4_config", {})["advanced_ddos_enabled"] = False
        config.setdefault("l7_config", {}).setdefault("cc_defense", {})["enabled"] = False
        config.setdefault("l7_config", {}).setdefault("slow_attack_defense", {})["enabled"] = False
        conn.execute(
            "UPDATE app_config SET config_json = ?, updated_at = ? WHERE id = 1",
            (json.dumps(config, separators=(",", ":")), int(time.time())),
        )
        conn.execute("DELETE FROM blocked_ips")
        conn.execute("DELETE FROM ai_temp_policies")
        conn.execute("DELETE FROM behavior_events")
        conn.execute("DELETE FROM behavior_sessions")
        conn.execute("DELETE FROM local_sites WHERE primary_hostname = ?", (host_header,))
        now = int(time.time())
        conn.execute(
            """INSERT INTO local_sites (
                name, primary_hostname, hostnames_json, listen_ports_json, upstreams_json,
                safeline_intercept_json, priority, overload_policy, reserved_concurrency,
                reserved_rps, enabled, tls_enabled, local_certificate_id,
                source, sync_mode, notes, last_synced_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "intercept_stress_site",
                host_header,
                json.dumps([host_header]),
                json.dumps([str(optimized_port)]),
                json.dumps(["127.0.0.1:18081"]),
                json.dumps({"enabled": False}),
                "normal",
                "inherit",
                0,
                0,
                1,
                0,
                None,
                "manual",
                "manual",
                "",
                None,
                now,
                now,
            ),
        )
        template = {
            "status_code": 403,
            "content_type": "text/plain; charset=utf-8",
            "body_source": "inline_text",
            "gzip": False,
            "body_text": "blocked\n",
            "body_file_path": "",
            "headers": [{"key": "cache-control", "value": "no-store"}],
        }
        conn.execute("DELETE FROM rules WHERE id = ?", ("intercept-stress-respond",))
        conn.execute(
            """INSERT INTO rules (
                id, name, enabled, layer, pattern, action, severity,
                plugin_template_id, response_template_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "intercept-stress-respond",
                "Intercept stress respond",
                1,
                "l7",
                "__block__",
                "respond",
                "high",
                None,
                json.dumps(template, separators=(",", ":")),
                now,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return backup


def fetch_metrics():
    return json.load(urllib.request.urlopen(optimized_metrics_url, timeout=3))


def wait_ready():
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            urllib.request.urlopen(optimized_metrics_url, timeout=2).read()
            return
        except Exception:
            time.sleep(0.2)
    raise RuntimeError("优化版 API 未就绪")


async def worker(stop_at, counters):
    request = (
        f"GET {path_to_block} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "User-Agent: intercept-stress\r\n"
        "Accept: */*\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    ).encode()
    while time.time() < stop_at:
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", optimized_port)
            while time.time() < stop_at:
                writer.write(request)
                await writer.drain()
                header = await reader.readuntil(b"\r\n\r\n")
                first = header.split(b"\r\n", 1)[0]
                length = 0
                for line in header.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        length = int(line.split(b":", 1)[1].strip())
                        break
                if length:
                    await reader.readexactly(length)
                if b" 403 " in first:
                    counters["blocked"] += 1
                else:
                    counters["other"] += 1
        except Exception:
            counters["errors"] += 1
            await asyncio.sleep(0)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


async def run_load(pid):
    counters = {"blocked": 0, "other": 0, "errors": 0}
    stop_at = time.time() + duration_seconds
    samples = []
    start_cpu = cpu_jiffies(pid)
    start = time.time()

    async def sampler():
        while time.time() < stop_at:
            metrics = fetch_metrics()
            samples.append(
                {
                    "ts": round(time.time() - start, 3),
                    "rss_kb": rss_kb(pid),
                    "blocked_packets": metrics.get("blocked_packets"),
                    "blocked_l7": metrics.get("blocked_l7"),
                    "sqlite_queue_depth": metrics.get("sqlite_queue_depth"),
                    "sqlite_dropped_security_events": metrics.get("sqlite_dropped_security_events"),
                    "persisted_security_events": metrics.get("persisted_security_events"),
                }
            )
            await asyncio.sleep(1)

    tasks = [asyncio.create_task(worker(stop_at, counters)) for _ in range(connections)]
    tasks.append(asyncio.create_task(sampler()))
    await asyncio.gather(*tasks, return_exceptions=True)
    elapsed = time.time() - start
    end_cpu = cpu_jiffies(pid)
    hz = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
    metrics = fetch_metrics()
    return {
        "duration_seconds": round(elapsed, 3),
        "connections": connections,
        "client_counters": counters,
        "client_rps": round(counters["blocked"] / elapsed, 2) if elapsed else 0,
        "peak_rss_kb": max([item["rss_kb"] for item in samples] or [rss_kb(pid)]),
        "final_rss_kb": rss_kb(pid),
        "process_cpu_seconds": round((end_cpu - start_cpu) / hz, 3),
        "samples": samples,
        "final_metrics": {
            "blocked_packets": metrics.get("blocked_packets"),
            "blocked_l7": metrics.get("blocked_l7"),
            "sqlite_queue_depth": metrics.get("sqlite_queue_depth"),
            "sqlite_dropped_security_events": metrics.get("sqlite_dropped_security_events"),
            "persisted_security_events": metrics.get("persisted_security_events"),
            "runtime_pressure_level": metrics.get("runtime_pressure_level"),
            "system_memory_used_bytes": metrics.get("system", {}).get("memory_used_bytes"),
        },
    }


backup_path = configure_db()
stop_optimized()
start_optimized()
wait_ready()
pid = optimized_pid()
before = fetch_metrics()
result = asyncio.run(run_load(pid))
after = fetch_metrics()
print(json.dumps({
    "config": {
        "remote_host": os.environ["REMOTE_HOST"],
        "optimized_dir": optimized_dir,
        "port": optimized_port,
        "host": host_header,
        "path": path_to_block,
        "duration_seconds": duration_seconds,
        "connections": connections,
        "db_backup": backup_path,
    },
    "before": {
        "blocked_packets": before.get("blocked_packets"),
        "blocked_l7": before.get("blocked_l7"),
        "rss_kb": rss_kb(pid),
    },
    "result": result,
    "after": {
        "blocked_packets": after.get("blocked_packets"),
        "blocked_l7": after.get("blocked_l7"),
        "sqlite_queue_depth": after.get("sqlite_queue_depth"),
        "sqlite_dropped_security_events": after.get("sqlite_dropped_security_events"),
        "persisted_security_events": after.get("persisted_security_events"),
        "rss_kb": rss_kb(pid),
    },
}, ensure_ascii=False, indent=2))
PY
