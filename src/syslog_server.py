import time
import socket
from parsers import dhcpd_parser, filterlog_parser, unbound_parser, configd_parser, devd_parser, syslogng_parser, lighttpd_parser, cron_parser, audit_parser, kernel_parser, dhclient_parser, dpinger_parser, api_parser, config_parser,configctl_parser,opnsense_parser,rule_updater_parser
import loki_client
from prometheus_client import start_http_server, Counter, Gauge, Summary
import concurrent.futures
import geoip_helper
import ipaddress
import io
import os
import queue

class SyslogServer:
    
    # Create metrics
    SUCCESSFUL_LOGS = Counter('logsense2loki_successful_logs_total', 'Total number of successfully parsed and sent logs')
    SENDED_LOGS = Counter('logsense2loki_sended_logs_total', 'Total number of sended parsed and sent logs')
    FAILED_LOGS = Counter('logsense2loki_failed_logs_total', 'Total number of logs that failed to parse or send')
    RECEIVED_LOGS = Counter('logsense2loki_received_logs_total', 'Total number of received logs')
    QUEUE_SIZE = Gauge('logsense2loki_queue_size', 'Current size of the processing queue')
    QUEUE_MAX_SIZE = Gauge('logsense2loki_queue_max_size', 'Maximum size of the processing queue')

    # Summary metrics for parser processing time
    PARSER_PROCESSING_TIME = Summary('logsense2loki_parser_processing_seconds', 'Time spent processing logs', ['parser'])

    def __init__(self, host, port, geoip, geoip_db_path, max_queue_size, thread_multiplier, log_batch_size):
        self.host = host
        self.port = port
        self.geoip = geoip
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Set up the socket for UDP
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**24)
        self.sock.bind((self.host, self.port))
        self.buffer = io.BytesIO()
        # check if geoip enabled
        if geoip:
            self.geoip_helper = geoip_helper.GeoIPHelper(geoip_db_path)

        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=min(32, os.cpu_count() * thread_multiplier))
        self.queue = queue.Queue(maxsize=max_queue_size)  # Setting the queue size
        self.log_batch_size = log_batch_size
        self.QUEUE_MAX_SIZE.set(max_queue_size)
    
    def run(self):
        print("Syslog server is running...")

        # Start prometheus server
        start_http_server(8100)

        try:
            while True:
                data, addr = self.sock.recvfrom(8192)
                self.RECEIVED_LOGS.inc()
                # Write the received data to the buffer
                self.buffer.write(data)

                # Set the read pointer to the beginning of the buffer
                self.buffer.seek(0)

                # Attempts to decode the contents of the buffer
                try:
                    decoded_data = self.buffer.read().decode('utf-8')
                except UnicodeDecodeError:
                    # If a decoding error occurs, reset the read pointer and wait for more data
                    print("UnicodeDecodeError: Invalid data received")
                    self.buffer.seek(0, io.SEEK_END)
                    continue

                # Process complete lines
                lines = decoded_data.split('\n')

                # The last incomplete line remains in the buffer
                self.buffer = io.BytesIO()
                self.buffer.write(lines.pop().encode('utf-8'))

                for log_message in lines:
                    try:
                        self.queue.put_nowait(log_message)
                    except queue.Full:
                        print("Queue full, dropping log message")
                        self.FAILED_LOGS.inc()
                
                # Update queue size metric
                self.QUEUE_SIZE.set(self.queue.qsize())

        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            self.sock.close()

    def process_log_queue(self):
        while True:
            logs_to_process = []
            while not self.queue.empty():
                logs_to_process.append(self.queue.get())
                self.queue.task_done()
                if len(logs_to_process) >= self.log_batch_size:  
                    break
            # 
            self.process_logs_batch(logs_to_process)
            self.QUEUE_SIZE.set(self.queue.qsize())

    def process_logs_batch(self, logs):
        parsed_logs = []
        for log_message in logs:
            parsed_log = self.process_log(log_message)
            if parsed_log:
                parsed_logs.append(parsed_log)
        
        # Send only if there are parsed logs
        try:
            loki_client.send_to_loki(parsed_logs)
            self.SENDED_LOGS.inc(len(parsed_logs))
        except Exception as e:
            print(f"Failed to send logs to Loki: {e}")
            self.FAILED_LOGS.inc(len(parsed_logs))
        
    def process_log(self, log_message):
        try:
            # Look for the right parser
            parsed_log = None

            if ' dhcpd ' in log_message:
                with self.PARSER_PROCESSING_TIME.labels('dhcpd').time():
                    parsed_log = dhcpd_parser.parse(log_message)
            elif ' filterlog ' in log_message:
                with self.PARSER_PROCESSING_TIME.labels('filterlog').time():
                    parsed_log = filterlog_parser.parse(log_message)
                    if self.geoip and parsed_log:
                        ip_address = parsed_log.get('src_ip')


                        if ip_address and self.is_public_ip(ip_address):
                            # Start a new thread to process the geolocation
                            self.executor.submit(self.process_geoip, ip_address, parsed_log)
            elif ' unbound ' in log_message:
                with self.PARSER_PROCESSING_TIME.labels('unbound').time():
                    parsed_log = unbound_parser.parse(log_message)
            elif ' configd.py ' in log_message:
                with self.PARSER_PROCESSING_TIME.labels('configd.py').time():
                    parsed_log = configd_parser.parse(log_message)
            elif ' devd ' in log_message:
                with self.PARSER_PROCESSING_TIME.labels('devd').time():
                    parsed_log = devd_parser.parse(log_message)
            elif ' syslog-ng ' in log_message:
                with self.PARSER_PROCESSING_TIME.labels('syslog-ng').time():
                    parsed_log = syslogng_parser.parse(log_message)
            elif ' lighttpd ' in log_message:
                with self.PARSER_PROCESSING_TIME.labels('lighttpd').time():
                    parsed_log = lighttpd_parser.parse(log_message)
            elif ' /usr/sbin/cron ' in log_message:
                with self.PARSER_PROCESSING_TIME.labels('cron').time():
                    parsed_log = cron_parser.parse(log_message)
            elif ' audit ' in log_message:
                with self.PARSER_PROCESSING_TIME.labels('audit').time():
                    parsed_log = audit_parser.parse(log_message)
            elif ' kernel ' in log_message:
                with self.PARSER_PROCESSING_TIME.labels('kernel').time():
                    parsed_log = kernel_parser.parse(log_message)        
            elif ' dhclient ' in log_message:
                with self.PARSER_PROCESSING_TIME.labels('dhclient').time():
                    parsed_log = dhclient_parser.parse(log_message) 
            elif ' dpinger ' in log_message:
                with self.PARSER_PROCESSING_TIME.labels('dpinger').time():
                    parsed_log = dpinger_parser.parse(log_message) 
            elif ' api ' in log_message:
                with self.PARSER_PROCESSING_TIME.labels('api').time():
                    parsed_log = api_parser.parse(log_message) 
            elif ' config ' in log_message:
                with self.PARSER_PROCESSING_TIME.labels('config').time():
                    parsed_log = config_parser.parse(log_message)        
            elif ' configctl ' in log_message:
                with self.PARSER_PROCESSING_TIME.labels('configctl').time():
                    parsed_log = configctl_parser.parse(log_message) 
            elif ' opnsense ' in log_message:
                with self.PARSER_PROCESSING_TIME.labels('opnsense').time():
                    parsed_log = opnsense_parser.parse(log_message) 
            elif ' rule-updater.py  ' in log_message:
                with self.PARSER_PROCESSING_TIME.labels('rule_updater').time():
                    parsed_log = rule_updater_parser.parse(log_message) 

            if parsed_log:
                if not isinstance(parsed_log, dict):
                    print(f"Parsed log is not a dictionary: {parsed_log}")
                self.SUCCESSFUL_LOGS.inc()
                return parsed_log
            else:
                print(f"Received log no parser: {log_message}")
                self.FAILED_LOGS.inc()
                return None

        except Exception as e:
            print(f"Failed to process log: {e}",log_message)
            self.FAILED_LOGS.inc()
            return None

    def is_public_ip(self, ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_global
        except ValueError as e:
            print(f"Invalid IP address: {ip} - {e}")
            return False

    def process_geoip(self, ip_address, parsed_log):


        #or all? some values are greate for creating dashboard filter
        hostname = parsed_log.get('hostname')
        action = parsed_log.get('action')
        direction = parsed_log.get('direction')
        dst_port = parsed_log.get('dst_port')
        proto = parsed_log.get('proto')
        rulenumber = parsed_log.get('rulenumber')
        interface = parsed_log.get('interface')
        try:
            geo_info = self.geoip_helper.get_city(ip_address)
            geo_log = {
                "service": "geoip",
                "hostname": hostname,
                "ip": ip_address,
                "city": geo_info["city"],
                "country": geo_info["country"],
                "latitude": geo_info["latitude"],
                "longitude": geo_info["longitude"],
                "country_code": geo_info["country_code"],
                "geohash": geo_info["geohash"],
                "organization": geo_info["organization"],
                "action": action,
                "direction": direction,
                "dst_port": dst_port,
                "proto":proto,
                "rulenumber":rulenumber,
                "interface":interface

            }
            loki_client.send_to_loki([geo_log])
        except Exception as e:
            print(f"An error occurred in process_geoip: {e}")
