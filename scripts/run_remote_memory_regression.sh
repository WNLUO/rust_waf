#!/usr/bin/env bash
set -euo pipefail

REMOTE_HOST="${REMOTE_HOST:-85.149.219.14}"
REMOTE_USER="${REMOTE_USER:-root}"
REMOTE_PASSWORD="${REMOTE_PASSWORD:-}"

BASELINE_DIR="${BASELINE_DIR:-/root/waf}"
OPTIMIZED_DIR="${OPTIMIZED_DIR:-/root/waf-test}"
UPSTREAM_FILE_URL="${UPSTREAM_FILE_URL:-http://127.0.0.1:18081/large.bin}"
BASELINE_PORT="${BASELINE_PORT:-18082}"
OPTIMIZED_PORT="${OPTIMIZED_PORT:-18080}"
OPTIMIZED_METRICS_URL="${OPTIMIZED_METRICS_URL:-http://127.0.0.1:13740/metrics}"
HOST_HEADER="${HOST_HEADER:-test.local}"
CONCURRENCY="${CONCURRENCY:-12}"
RUNS="${RUNS:-1}"
PREPARE_TEST="${PREPARE_TEST:-1}"
BASELINE_DB_PATH="${BASELINE_DB_PATH:-/root/waf/data/baseline-test.db}"
OPTIMIZED_DB_PATH="${OPTIMIZED_DB_PATH:-/root/waf-test/data/waf.db}"
BASELINE_LOG_PATH="${BASELINE_LOG_PATH:-/tmp/waf-baseline.log}"
OPTIMIZED_LOG_PATH="${OPTIMIZED_LOG_PATH:-/tmp/waf-optimized.log}"

if [[ -z "${REMOTE_PASSWORD}" ]]; then
  echo "请先通过环境变量提供 REMOTE_PASSWORD" >&2
  exit 1
fi

if ! command -v sshpass >/dev/null 2>&1; then
  echo "缺少 sshpass，请先安装 sshpass" >&2
  exit 1
fi

SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
)

export SSHPASS="${REMOTE_PASSWORD}"

REMOTE_ENV=(
  "REMOTE_HOST=${REMOTE_HOST}"
  "BASELINE_DIR=${BASELINE_DIR}"
  "OPTIMIZED_DIR=${OPTIMIZED_DIR}"
  "UPSTREAM_FILE_URL=${UPSTREAM_FILE_URL}"
  "BASELINE_PORT=${BASELINE_PORT}"
  "OPTIMIZED_PORT=${OPTIMIZED_PORT}"
  "OPTIMIZED_METRICS_URL=${OPTIMIZED_METRICS_URL}"
  "HOST_HEADER=${HOST_HEADER}"
  "CONCURRENCY=${CONCURRENCY}"
  "RUNS=${RUNS}"
  "PREPARE_TEST=${PREPARE_TEST}"
  "BASELINE_DB_PATH=${BASELINE_DB_PATH}"
  "OPTIMIZED_DB_PATH=${OPTIMIZED_DB_PATH}"
  "BASELINE_LOG_PATH=${BASELINE_LOG_PATH}"
  "OPTIMIZED_LOG_PATH=${OPTIMIZED_LOG_PATH}"
)

sshpass -e ssh "${SSH_OPTS[@]}" "${REMOTE_USER}@${REMOTE_HOST}" \
  "$(printf '%q ' "${REMOTE_ENV[@]}")python3 -" <<'PY'
import json
import os
import shutil
import sqlite3
import subprocess
import time
import urllib.request

baseline_dir = os.environ['BASELINE_DIR']
optimized_dir = os.environ['OPTIMIZED_DIR']
upstream_file_url = os.environ['UPSTREAM_FILE_URL']
baseline_port = int(os.environ['BASELINE_PORT'])
optimized_port = int(os.environ['OPTIMIZED_PORT'])
optimized_metrics_url = os.environ['OPTIMIZED_METRICS_URL']
host_header = os.environ['HOST_HEADER']
concurrency = int(os.environ['CONCURRENCY'])
runs = int(os.environ['RUNS'])
prepare_test = os.environ['PREPARE_TEST'] == '1'
baseline_db_path = os.environ['BASELINE_DB_PATH']
optimized_db_path = os.environ['OPTIMIZED_DB_PATH']
baseline_log_path = os.environ['BASELINE_LOG_PATH']
optimized_log_path = os.environ['OPTIMIZED_LOG_PATH']


def get_pid_by_prefix(prefix: str) -> int:
    output = subprocess.run(['pgrep', '-af', 'waf'], capture_output=True, text=True)
    lines = output.stdout.strip().splitlines()
    matches = []
    expected_cwd = os.path.dirname(os.path.dirname(os.path.dirname(prefix)))
    expected_exe = prefix
    for line in lines:
        parts = line.strip().split(None, 1)
        if len(parts) != 2:
            continue
        pid, cmdline = parts
        proc_cwd = ''
        proc_exe = ''
        try:
            proc_cwd = os.readlink(f'/proc/{pid}/cwd')
        except OSError:
            pass
        try:
            proc_exe = os.readlink(f'/proc/{pid}/exe')
        except OSError:
            pass
        if proc_exe == expected_exe or (
            cmdline.startswith('./target/release/waf') and proc_cwd == expected_cwd
        ):
            matches.append(pid)
    if not matches:
        raise RuntimeError(f'未找到进程: {prefix}')
    return int(matches[0])


def try_sql(conn: sqlite3.Connection, sql: str, params=()) -> None:
    try:
        conn.execute(sql, params)
    except sqlite3.Error:
        pass


def reset_db_state(db_path: str) -> None:
    if not os.path.exists(db_path):
        return
    conn = sqlite3.connect(db_path)
    try:
        try_sql(conn, "DELETE FROM blocked_ips WHERE ip = ?", ('127.0.0.1',))
        try_sql(conn, "DELETE FROM ai_temp_policies")
        try_sql(conn, "DELETE FROM ai_visitor_decisions WHERE source_ip = ?", ('127.0.0.1',))
        try_sql(conn, "DELETE FROM ai_visitor_profiles WHERE source_ip = ?", ('127.0.0.1',))
        try_sql(conn, "DELETE FROM behavior_events WHERE source_ip = ?", ('127.0.0.1',))
        try_sql(conn, "DELETE FROM behavior_sessions WHERE source_ip = ?", ('127.0.0.1',))
        conn.commit()
    finally:
        conn.close()


def prepare_runtime_db(source_db_path: str, workdir: str) -> None:
    runtime_db_path = os.path.join(workdir, 'data', 'waf.db')
    if os.path.abspath(source_db_path) == os.path.abspath(runtime_db_path):
        return
    for suffix in ('', '-wal', '-shm'):
        path = f'{runtime_db_path}{suffix}'
        if os.path.exists(path):
            os.remove(path)
    shutil.copy2(source_db_path, runtime_db_path)


def configure_runtime_db(
    workdir: str,
    listen_port: int,
    api_enabled: bool,
    api_bind: str,
    safeline_enabled: bool,
    site_name: str,
) -> None:
    db_path = os.path.join(workdir, 'data', 'waf.db')
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute('SELECT config_json FROM app_config WHERE id = 1').fetchone()
        config = json.loads(row[0])
        config['listen_addrs'] = [f'127.0.0.1:{listen_port}']
        config['api_enabled'] = api_enabled
        config['api_bind'] = api_bind
        config.setdefault('gateway_config', {})['https_listen_addr'] = ''
        config.setdefault('http3_config', {})['enabled'] = False
        config.setdefault('http3_config', {})['listen_addr'] = '127.0.0.1:0'
        conn.execute(
            'UPDATE app_config SET config_json = ?, updated_at = ? WHERE id = 1',
            (json.dumps(config, separators=(',', ':')), int(time.time())),
        )
        conn.execute('DELETE FROM local_sites WHERE primary_hostname = ?', (host_header,))
        now = int(time.time())
        conn.execute(
            '''INSERT INTO local_sites (
                name, primary_hostname, hostnames_json, listen_ports_json, upstreams_json,
                safeline_intercept_json, priority, overload_policy, reserved_concurrency,
                reserved_rps, enabled, tls_enabled, local_certificate_id,
                source, sync_mode, notes, last_synced_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (
                site_name,
                host_header,
                json.dumps([host_header]),
                json.dumps([str(listen_port)]),
                json.dumps(['127.0.0.1:18081']),
                json.dumps({'enabled': safeline_enabled}, separators=(',', ':')),
                'normal',
                'inherit',
                0,
                0,
                1,
                0,
                None,
                'manual',
                'manual',
                '',
                None,
                now,
                now,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def stop_instance(prefix: str) -> None:
    output = subprocess.run(['pgrep', '-af', 'waf'], capture_output=True, text=True)
    for line in output.stdout.strip().splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2:
            continue
        pid, cmdline = parts
        proc_cwd = ''
        proc_exe = ''
        try:
            proc_cwd = os.readlink(f'/proc/{pid}/cwd')
        except OSError:
            pass
        try:
            proc_exe = os.readlink(f'/proc/{pid}/exe')
        except OSError:
            pass
        expected_cwd = os.path.dirname(os.path.dirname(os.path.dirname(prefix)))
        if proc_exe == prefix or (
            cmdline.startswith('./target/release/waf') and proc_cwd == expected_cwd
        ):
            try:
                os.kill(int(pid), 15)
            except ProcessLookupError:
                pass
    time.sleep(1.0)


def start_instance(workdir: str, log_path: str) -> None:
    log_handle = open(log_path, 'w', encoding='utf-8')
    subprocess.Popen(
        ['./target/release/waf'],
        cwd=workdir,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    time.sleep(2.0)


def get_rss_kb(pid: int) -> int:
    with open(f'/proc/{pid}/status', 'r', encoding='utf-8') as handle:
        for line in handle:
            if line.startswith('VmRSS:'):
                return int(line.split()[1])
    raise RuntimeError(f'未找到 VmRSS: pid={pid}')


def wait_http_ok(url: str, headers=None, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    request_headers = headers or {}
    while time.time() < deadline:
        try:
            request = urllib.request.Request(url, headers=request_headers)
            with urllib.request.urlopen(request, timeout=2) as response:
                if response.status == 200:
                    return
        except Exception:
            time.sleep(0.2)
    raise RuntimeError(f'服务未就绪: {url}')


def wait_site_ok(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = subprocess.run(
            [
                'curl',
                '--resolve',
                f'{host_header}:{port}:127.0.0.1',
                f'http://{host_header}:{port}/large.bin',
                '-o',
                '/dev/null',
                '-s',
                '-w',
                '%{http_code}',
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and result.stdout.strip() == '200':
            return
        time.sleep(0.2)
    raise RuntimeError(f'站点未就绪: {host_header}:{port}')


def curl_download(port: int) -> subprocess.Popen:
    return subprocess.Popen(
        [
            'curl',
            '--resolve',
            f'{host_header}:{port}:127.0.0.1',
            f'http://{host_header}:{port}/large.bin',
            '-o',
            '/dev/null',
            '-s',
        ]
    )


def measure_case(name: str, pid: int, port: int) -> dict:
    before = get_rss_kb(pid)
    workers = [curl_download(port) for _ in range(concurrency)]
    peak = before
    while True:
        alive = any(worker.poll() is None for worker in workers)
        peak = max(peak, get_rss_kb(pid))
        if not alive:
            break
        time.sleep(0.05)
    for worker in workers:
        worker.wait()
    after = get_rss_kb(pid)
    return {
        'name': name,
        'before_kb': before,
        'peak_kb': peak,
        'after_kb': after,
        'delta_kb': peak - before,
    }


if prepare_test:
    reset_db_state(baseline_db_path)
    reset_db_state(optimized_db_path)
    prepare_runtime_db(baseline_db_path, baseline_dir)
    prepare_runtime_db(optimized_db_path, optimized_dir)
    configure_runtime_db(
        baseline_dir,
        baseline_port,
        False,
        '127.0.0.1:13741',
        True,
        'baseline_proxy',
    )
    configure_runtime_db(
        optimized_dir,
        optimized_port,
        True,
        optimized_metrics_url.replace('http://', '').rsplit('/', 1)[0],
        False,
        'optimized_proxy',
    )
    stop_instance(f'{baseline_dir}/target/release/waf')
    stop_instance(f'{optimized_dir}/target/release/waf')
    start_instance(baseline_dir, baseline_log_path)
    start_instance(optimized_dir, optimized_log_path)
    baseline_pid = get_pid_by_prefix(f'{baseline_dir}/target/release/waf')
    optimized_pid = get_pid_by_prefix(f'{optimized_dir}/target/release/waf')
else:
    baseline_pid = get_pid_by_prefix(f'{baseline_dir}/target/release/waf')
    optimized_pid = get_pid_by_prefix(f'{optimized_dir}/target/release/waf')

wait_http_ok(upstream_file_url)
wait_site_ok(baseline_port)
wait_site_ok(optimized_port)
wait_http_ok(optimized_metrics_url)

results = []
for index in range(runs):
    baseline = measure_case('baseline', baseline_pid, baseline_port)
    optimized = measure_case('optimized', optimized_pid, optimized_port)
    metrics = json.load(urllib.request.urlopen(optimized_metrics_url, timeout=3))
    results.append(
        {
            'run': index + 1,
            'baseline': baseline,
            'optimized': optimized,
            'optimized_metrics': {
                'proxied_requests': metrics.get('proxied_requests'),
                'proxy_successes': metrics.get('proxy_successes'),
                'streamed_proxy_responses': metrics.get('streamed_proxy_responses'),
                'http2_pool_evictions': metrics.get('http2_pool_evictions'),
                'proxy_body_preview_truncations': metrics.get(
                    'proxy_body_preview_truncations'
                ),
            },
        }
    )

latest = results[-1]
baseline_peak = latest['baseline']['peak_kb']
optimized_peak = latest['optimized']['peak_kb']
reduction_kb = baseline_peak - optimized_peak
reduction_pct = (
    round(reduction_kb * 100.0 / baseline_peak, 2) if baseline_peak else 0.0
)

summary = {
    'config': {
        'remote_host': os.environ['REMOTE_HOST'],
        'baseline_dir': baseline_dir,
        'optimized_dir': optimized_dir,
        'baseline_port': baseline_port,
        'optimized_port': optimized_port,
        'concurrency': concurrency,
        'runs': runs,
    },
    'results': results,
    'latest_comparison': {
        'baseline_peak_kb': baseline_peak,
        'optimized_peak_kb': optimized_peak,
        'peak_reduction_kb': reduction_kb,
        'peak_reduction_pct': reduction_pct,
    },
}

print(json.dumps(summary, ensure_ascii=False, indent=2))
PY
