import cProfile
import io
import os
import pstats
import signal
import sys
import threading

import config
import syslog_server


pr = None


def main():
    syslog_host = os.getenv('SYSLOG_HOST', config.SYSLOG_HOST)
    syslog_port = int(os.getenv('SYSLOG_PORT', config.SYSLOG_PORT))
    geoip = os.getenv('ENABLE_GEOIP', str(config.ENABLE_GEOIP)).lower() != 'false'
    geoip_db_path = os.getenv('GEOIP_DB_PATH', config.GEOIP_DB_PATH)
    max_queue_size = int(os.getenv('QUEUE_SIZE', config.QUEUE_SIZE))
    thread_multiplier = int(os.getenv('THREAD_MULTIPLIER', config.THREAD_MULTIPLIER))
    queue_thread_multiplier = int(os.getenv('QUEUE_THREAD_MULTIPLIER', config.QUEUE_THREAD_MULTIPLIER))
    log_batch_size = int(os.getenv('LOG_BATCH_SIZE', config.LOG_BATCH_SIZE))

    server = syslog_server.SyslogServer(
        syslog_host,
        syslog_port,
        geoip,
        geoip_db_path,
        max_queue_size,
        thread_multiplier,
        log_batch_size,
    )

    worker_threads = max(1, (os.cpu_count() or 1) * queue_thread_multiplier)
    for _ in range(worker_threads):
        t = threading.Thread(target=server.process_log_queue, daemon=True)
        t.start()

    server.run()


def signal_handler(_sig, _frame):
    global pr
    if pr is None:
        sys.exit(0)

    pr.disable()
    s = io.StringIO()
    pstats.Stats(pr, stream=s).sort_stats('cumulative').print_stats()
    with open('profiling_results.txt', 'w') as f:
        f.write(s.getvalue())
    print('Profiling data written to profiling_results.txt.')
    sys.exit(0)


if __name__ == '__main__':
    enable_profiling = os.getenv('ENABLE_PROFILING', 'false').lower() == 'true'

    if enable_profiling:
        pr = cProfile.Profile()
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        try:
            pr.enable()
            main()
        except KeyboardInterrupt:
            pass
        finally:
            signal_handler(None, None)
    else:
        try:
            main()
        except KeyboardInterrupt:
            pass
