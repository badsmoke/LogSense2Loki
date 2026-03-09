import socket
from parsers import (
    dhcpd_parser,
    filterlog_parser,
    unbound_parser,
    configd_parser,
    devd_parser,
    syslogng_parser,
    lighttpd_parser,
    cron_parser,
    audit_parser,
    kernel_parser,
    dhclient_parser,
    dpinger_parser,
    api_parser,
    config_parser,
    configctl_parser,
    opnsense_parser,
    rule_updater_parser,
)
import loki_client
from prometheus_client import start_http_server, Counter, Gauge, Summary
import concurrent.futures
import geoip_helper
import ipaddress
import logging
import os
import queue
import re
import threading


LOGGER = logging.getLogger(__name__)
SYSLOG_APP_PATTERN = re.compile(
    r'^<\d+>1\s+\S+\s+\S+\s+(?P<app>[^\s]+)\s+'
)


class SyslogServer:
    SUCCESSFUL_LOGS = Counter(
        'logsense2loki_successful_logs_total',
        'Total number of successfully parsed and sent logs',
    )
    SENDED_LOGS = Counter(
        'logsense2loki_sended_logs_total',
        'Total number of sent parsed logs',
    )
    FAILED_LOGS = Counter(
        'logsense2loki_failed_logs_total',
        'Total number of logs that failed to parse or send',
    )
    RECEIVED_LOGS = Counter(
        'logsense2loki_received_logs_total',
        'Total number of received logs',
    )
    QUEUE_SIZE = Gauge('logsense2loki_queue_size', 'Current size of the processing queue')
    QUEUE_MAX_SIZE = Gauge('logsense2loki_queue_max_size', 'Maximum size of the processing queue')

    PARSER_PROCESSING_TIME = Summary(
        'logsense2loki_parser_processing_seconds',
        'Time spent processing logs',
        ['parser'],
    )

    def __init__(self, host, port, geoip, geoip_db_path, max_queue_size, thread_multiplier, log_batch_size):
        self.host = host
        self.port = port
        self.geoip = geoip
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**24)
        self.sock.bind((self.host, self.port))
        self.partial_line = ""

        cpu_count = os.cpu_count() or 1
        parser_workers = max(1, min(32, cpu_count * thread_multiplier))
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=parser_workers)

        self.geoip_backlog_limit = parser_workers * 100
        self.geoip_pending = 0
        self.geoip_lock = threading.Lock()

        if geoip:
            self.geoip_helper = geoip_helper.GeoIPHelper(geoip_db_path)

        self.queue = queue.Queue(maxsize=max_queue_size)
        self.log_batch_size = log_batch_size
        self.QUEUE_MAX_SIZE.set(max_queue_size)

        self.parser_dispatch = (
            (' dhcpd ', 'dhcpd', lambda msg: dhcpd_parser.parse(msg)),
            (' filterlog ', 'filterlog', lambda msg: filterlog_parser.parse(msg)),
            (' unbound ', 'unbound', lambda msg: unbound_parser.parse(msg)),
            (' configd.py ', 'configd.py', lambda msg: configd_parser.parse(msg)),
            (' devd ', 'devd', lambda msg: devd_parser.parse(msg)),
            (' syslog-ng ', 'syslog-ng', lambda msg: syslogng_parser.parse(msg)),
            (' lighttpd ', 'lighttpd', lambda msg: lighttpd_parser.parse(msg)),
            (' /usr/sbin/cron ', 'cron', lambda msg: cron_parser.parse(msg)),
            (' audit ', 'audit', lambda msg: audit_parser.parse(msg)),
            (' kernel ', 'kernel', lambda msg: kernel_parser.parse(msg)),
            (' dhclient ', 'dhclient', lambda msg: dhclient_parser.parse(msg)),
            (' dpinger ', 'dpinger', lambda msg: dpinger_parser.parse(msg)),
            (' api ', 'api', lambda msg: api_parser.parse(msg)),
            (' configctl ', 'configctl', lambda msg: configctl_parser.parse(msg)),
            (' config ', 'config', lambda msg: config_parser.parse(msg)),
            (' opnsense ', 'opnsense', lambda msg: opnsense_parser.parse(msg)),
            (' rule-updater.py ', 'rule_updater', lambda msg: rule_updater_parser.parse(msg)),
        )
        self.parser_by_app = {
            'dhcpd': ('dhcpd', lambda msg: dhcpd_parser.parse(msg)),
            'filterlog': ('filterlog', lambda msg: filterlog_parser.parse(msg)),
            'unbound': ('unbound', lambda msg: unbound_parser.parse(msg)),
            'configd.py': ('configd.py', lambda msg: configd_parser.parse(msg)),
            'devd': ('devd', lambda msg: devd_parser.parse(msg)),
            'syslog-ng': ('syslog-ng', lambda msg: syslogng_parser.parse(msg)),
            'lighttpd': ('lighttpd', lambda msg: lighttpd_parser.parse(msg)),
            '/usr/sbin/cron': ('cron', lambda msg: cron_parser.parse(msg)),
            'audit': ('audit', lambda msg: audit_parser.parse(msg)),
            'kernel': ('kernel', lambda msg: kernel_parser.parse(msg)),
            'dhclient': ('dhclient', lambda msg: dhclient_parser.parse(msg)),
            'dpinger': ('dpinger', lambda msg: dpinger_parser.parse(msg)),
            'api': ('api', lambda msg: api_parser.parse(msg)),
            'configctl': ('configctl', lambda msg: configctl_parser.parse(msg)),
            'config': ('config', lambda msg: config_parser.parse(msg)),
            'opnsense': ('opnsense', lambda msg: opnsense_parser.parse(msg)),
            'rule-updater.py': ('rule_updater', lambda msg: rule_updater_parser.parse(msg)),
        }
        self.parser_timers = {
            label: self.PARSER_PROCESSING_TIME.labels(label)
            for _, label, _ in self.parser_dispatch
        }
        self.no_parser_counter = 0
        self.queue_drop_counter = 0

    def run(self):
        LOGGER.info("Syslog server is running on %s:%s", self.host, self.port)
        start_http_server(8100)

        try:
            while True:
                data, _ = self.sock.recvfrom(8192)
                self.RECEIVED_LOGS.inc()

                decoded_data = (self.partial_line + data.decode('utf-8', errors='replace'))
                lines = decoded_data.split('\n')
                self.partial_line = lines.pop() if lines else ""

                for log_message in lines:
                    if not log_message:
                        continue
                    try:
                        self.queue.put_nowait(log_message)
                    except queue.Full:
                        self.FAILED_LOGS.inc()
                        self.queue_drop_counter += 1
                        if self.queue_drop_counter % 1000 == 1:
                            LOGGER.warning(
                                "Queue full, dropping log messages. total_dropped=%s",
                                self.queue_drop_counter,
                            )

                self.QUEUE_SIZE.set(self.queue.qsize())

        except Exception:
            LOGGER.exception("An error occurred in syslog receive loop")
        finally:
            self.sock.close()

    def process_log_queue(self):
        while True:
            try:
                first_log = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue

            logs_to_process = [first_log]
            while len(logs_to_process) < self.log_batch_size:
                try:
                    logs_to_process.append(self.queue.get_nowait())
                except queue.Empty:
                    break

            self.process_logs_batch(logs_to_process)
            for _ in logs_to_process:
                self.queue.task_done()
            self.QUEUE_SIZE.set(self.queue.qsize())

    def process_logs_batch(self, logs):
        if not logs:
            return

        parsed_logs = []
        for log_message in logs:
            parsed_log = self.process_log(log_message)
            if parsed_log:
                parsed_logs.append(parsed_log)

        if not parsed_logs:
            return

        try:
            sent_count = loki_client.send_to_loki(parsed_logs)
            if sent_count:
                self.SENDED_LOGS.inc(sent_count)
        except Exception:
            LOGGER.exception("Failed to send logs to Loki")
            self.FAILED_LOGS.inc(len(parsed_logs))

    def process_log(self, log_message):
        try:
            parsed_log = None
            matched_label = None

            app_match = SYSLOG_APP_PATTERN.match(log_message)
            if app_match:
                app_name = app_match.group('app')
                parser_entry = self.parser_by_app.get(app_name)
                if parser_entry:
                    matched_label, parser_func = parser_entry
                    with self.parser_timers[matched_label].time():
                        parsed_log = parser_func(log_message)

            if matched_label is None:
                for needle, label, parser_func in self.parser_dispatch:
                    if needle in log_message:
                        matched_label = label
                        with self.parser_timers[label].time():
                            parsed_log = parser_func(log_message)
                        break

            if parsed_log and matched_label == 'filterlog' and self.geoip:
                ip_address = parsed_log.get('src_ip')
                if ip_address and self.is_public_ip(ip_address):
                    self.submit_geoip(ip_address, parsed_log)

            if parsed_log and isinstance(parsed_log, dict):
                self.SUCCESSFUL_LOGS.inc()
                return parsed_log

            if matched_label and parsed_log is not None and not isinstance(parsed_log, dict):
                LOGGER.warning("Parsed log is not a dictionary: %r", parsed_log)
            else:
                self.no_parser_counter += 1
                if self.no_parser_counter % 1000 == 1:
                    LOGGER.warning("No parser matched for logs. Total unmatched=%s", self.no_parser_counter)
            self.FAILED_LOGS.inc()
            return None
        except Exception:
            LOGGER.exception("Failed to process log")
            self.FAILED_LOGS.inc()
            return None

    def is_public_ip(self, ip):
        try:
            return ipaddress.ip_address(ip).is_global
        except ValueError:
            return False

    def submit_geoip(self, ip_address, parsed_log):
        with self.geoip_lock:
            if self.geoip_pending >= self.geoip_backlog_limit:
                return
            self.geoip_pending += 1

        future = self.executor.submit(self.process_geoip, ip_address, parsed_log)
        future.add_done_callback(self._on_geoip_done)

    def _on_geoip_done(self, _future):
        with self.geoip_lock:
            self.geoip_pending -= 1

    def process_geoip(self, ip_address, parsed_log):
        try:
            geo_info = self.geoip_helper.get_city(ip_address)
            geo_log = {
                'service': 'geoip',
                'hostname': parsed_log.get('hostname'),
                'ip': ip_address,
                'city': geo_info['city'],
                'country': geo_info['country'],
                'latitude': geo_info['latitude'],
                'longitude': geo_info['longitude'],
                'country_code': geo_info['country_code'],
                'geohash': geo_info['geohash'],
                'organization': geo_info['organization'],
                'action': parsed_log.get('action'),
                'direction': parsed_log.get('direction'),
                'dst_port': parsed_log.get('dst_port'),
                'proto': parsed_log.get('proto'),
                'rulenumber': parsed_log.get('rulenumber'),
                'interface': parsed_log.get('interface'),
            }
            loki_client.send_to_loki([geo_log])
        except Exception:
            LOGGER.exception('An error occurred in process_geoip')
