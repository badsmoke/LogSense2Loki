import argparse
import importlib
import json
import os
import queue
import re
import resource
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ID_RE = re.compile(r"id=(\d+)")


def run_case(code_dir: str, log_count: int, workers: int, timeout_s: float, loki_delay_ms: float):
    sys.path.insert(0, code_dir)

    syslog_server = importlib.import_module("syslog_server")
    setattr(syslog_server, "start_http_server", lambda *_args, **_kwargs: None)

    sent_at = {}
    sent_lock = threading.Lock()
    latencies = []
    lat_lock = threading.Lock()
    post_count = 0
    post_lock = threading.Lock()
    worker_errors = []
    worker_err_lock = threading.Lock()
    recv_error = None
    process_log_calls = 0
    process_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_POST(self):
            nonlocal post_count
            with post_lock:
                post_count += 1
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            if loki_delay_ms > 0:
                time.sleep(loki_delay_ms / 1000.0)

            try:
                payload = json.loads(body.decode("utf-8"))
                now = time.perf_counter()
                for stream in payload.get("streams", []):
                    for entry in stream.get("entries", []):
                        line = json.loads(entry.get("line", "{}"))
                        msg = line.get("message", "")
                        m = ID_RE.search(msg)
                        if not m:
                            continue
                        log_id = int(m.group(1))
                        with sent_lock:
                            t0 = sent_at.get(log_id)
                        if t0 is not None:
                            with lat_lock:
                                latencies.append(now - t0)
            except Exception:
                pass

            self.send_response(204)
            self.end_headers()

    loki = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    loki_port = loki.server_address[1]
    loki_thread = threading.Thread(target=loki.serve_forever, daemon=True)
    loki_thread.start()

    os.environ["LOKI_URL"] = f"http://127.0.0.1:{loki_port}/loki/api/v1/push"

    server = syslog_server.SyslogServer("127.0.0.1", 0, False, "", max_queue_size=200000, thread_multiplier=1, log_batch_size=200)
    server_port = server.sock.getsockname()[1]
    original_process_log = server.process_log

    def wrapped_process_log(msg):
        nonlocal process_log_calls
        with process_lock:
            process_log_calls += 1
        return original_process_log(msg)

    server.process_log = wrapped_process_log

    def worker_runner():
        try:
            server.process_log_queue()
        except Exception as exc:
            with worker_err_lock:
                worker_errors.append(repr(exc))

    worker_threads = []
    for _ in range(workers):
        t = threading.Thread(target=worker_runner, daemon=True)
        t.start()
        worker_threads.append(t)

    def recv_runner():
        nonlocal recv_error
        try:
            server.run()
        except Exception as exc:
            recv_error = repr(exc)

    recv_thread = threading.Thread(target=recv_runner, daemon=True)
    recv_thread.start()

    producer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Give receiver moment to start
    time.sleep(0.1)

    ru0 = resource.getrusage(resource.RUSAGE_SELF)
    t_start = time.perf_counter()

    for i in range(log_count):
        log = f'<134>1 2024-05-28T16:39:59+02:00 fw api 123 - [meta sequenceId="1"] id={i} action=test\n'
        with sent_lock:
            sent_at[i] = time.perf_counter()
        producer.sendto(log.encode("utf-8"), ("127.0.0.1", server_port))

    producer.close()

    deadline = time.perf_counter() + timeout_s
    stall_deadline = time.perf_counter() + 2.0
    last_done = -1
    while time.perf_counter() < deadline:
        with lat_lock:
            done = len(latencies)
        if done >= log_count:
            break
        if done != last_done:
            last_done = done
            stall_deadline = time.perf_counter() + 2.0
        elif done > 0 and server.queue.qsize() == 0 and time.perf_counter() >= stall_deadline:
            break
        time.sleep(0.05)

    t_end = time.perf_counter()
    ru1 = resource.getrusage(resource.RUSAGE_SELF)

    # Shutdown network loop best-effort
    try:
        server.sock.close()
    except Exception:
        pass
    loki.shutdown()

    cpu_time = (ru1.ru_utime + ru1.ru_stime) - (ru0.ru_utime + ru0.ru_stime)
    wall = max(t_end - t_start, 1e-9)

    with lat_lock:
        got = len(latencies)
        lat_sorted = sorted(latencies)

    def percentile(arr, p):
        if not arr:
            return None
        idx = int((len(arr) - 1) * p)
        return arr[idx] * 1000.0

    result = {
        "code_dir": code_dir,
        "log_count": log_count,
        "received_at_loki": got,
        "drop_rate_pct": ((log_count - got) / log_count) * 100.0,
        "throughput_logs_per_s": got / wall,
        "wall_s": wall,
        "cpu_time_s": cpu_time,
        "cpu_pct_of_1_core": (cpu_time / wall) * 100.0,
        "latency_p50_ms": percentile(lat_sorted, 0.50),
        "latency_p95_ms": percentile(lat_sorted, 0.95),
        "latency_p99_ms": percentile(lat_sorted, 0.99),
        "mock_post_count": post_count,
        "metric_received_logs_total": float(server.RECEIVED_LOGS._value.get()),
        "metric_successful_logs_total": float(server.SUCCESSFUL_LOGS._value.get()),
        "metric_failed_logs_total": float(server.FAILED_LOGS._value.get()),
        "metric_sended_logs_total": float(server.SENDED_LOGS._value.get()),
        "final_queue_size": server.queue.qsize(),
        "worker_error_count": len(worker_errors),
        "recv_error": recv_error,
        "process_log_calls": process_log_calls,
    }
    print(json.dumps(result, sort_keys=True))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--code-dir", required=True)
    ap.add_argument("--log-count", type=int, default=40000)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--timeout-s", type=float, default=20.0)
    ap.add_argument("--loki-delay-ms", type=float, default=0.2)
    args = ap.parse_args()

    run_case(args.code_dir, args.log_count, args.workers, args.timeout_s, args.loki_delay_ms)


if __name__ == "__main__":
    main()
