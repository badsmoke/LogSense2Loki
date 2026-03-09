import time
import statistics

from syslog_server import SyslogServer
import loki_client

LOGS = [
    '<134>1 2024-05-28T16:39:59+02:00 fw filterlog 1 - [meta sequenceId="1"] 201,,,0a40f86c186bf24db3d173b50ef28a54,vtnet2_vlan99,match,pass,in,4,0x0,,64,35287,0,DF,17,udp,69,10.0.99.244,10.0.99.1,45730,53,49',
    '<134>1 2024-05-28T16:39:59+02:00 fw unbound 123 - [meta sequenceId="1"] [1234:abcd] query: 1.2.3.4 example.com A IN',
    '<134>1 2024-05-28T16:39:59+02:00 fw configd.py 123 - [meta sequenceId="1"] [123e4567-e89b-12d3-a456-426614174000] apply template',
    '<134>1 2024-05-28T16:39:59+02:00 fw devd 123 - [meta sequenceId="1"] link up',
    '<134>1 2024-05-28T16:39:59+02:00 fw syslog-ng 1 - [meta sequenceId="1"] normal message',
    '<134>1 2024-05-28T16:39:59+02:00 fw lighttpd 1 - [meta sequenceId="1"] 1.2.3.4 host - [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 200 123 "-" "ua"',
    '<134>1 2024-05-28T16:39:59+02:00 fw /usr/sbin/cron 123 - [meta sequenceId="1"] (root) CMD (php /usr/local/opnsense/scripts/cron.php)',
    '<134>1 2024-05-28T16:39:59+02:00 fw audit 1 - [meta sequenceId="1"] unrelated event',
    '<134>1 2024-05-28T16:39:59+02:00 fw kernel - - [meta sequenceId="1"] arp: 10.0.0.2 moved from aa:bb:cc:dd:ee:ff to 11:22:33:44:55:66 on em0',
    '<134>1 2024-05-28T16:39:59+02:00 fw dhclient 123 - [meta sequenceId="1"] bound to 10.0.0.2',
    '<134>1 2024-05-28T16:39:59+02:00 fw dpinger 123 - ALERT: WAN_DHCP (Addr: 8.8.8.8 Alarm: 0 -> 1 RTT: 12.3 ms RTTd: 1.1 ms Loss: 0.0 %)',
    '<134>1 2024-05-28T16:39:59+02:00 fw api 123 - [meta sequenceId="1"] endpoint called',
    '<134>1 2024-05-28T16:39:59+02:00 fw config 123 - [meta sequenceId="1"] config-event: changed setting',
    '<134>1 2024-05-28T16:39:59+02:00 fw configctl 123 - [meta sequenceId="1"] reconfigure done',
    '<134>1 2024-05-28T16:39:59+02:00 fw opnsense 123 - [meta sequenceId="1"] system started',
    '<134>1 2024-05-28T16:39:59+02:00 fw rule-updater.py 1 - [meta sequenceId="1"] download completed now',
    '<134>1 2024-05-28T16:39:59+02:00 fw dhcpd 1 - [meta sequenceId="1"] DHCPDISCOVER from aa:bb:cc:dd:ee:ff via em0',
]


def run_once(n=40000):
    server = SyslogServer('127.0.0.1', 0, False, '', 10000, 1, 100)
    loki_client.send_to_loki = lambda logs: None

    t0 = time.perf_counter()
    for i in range(n):
        server.process_log(LOGS[i % len(LOGS)])
    t1 = time.perf_counter()
    return n / (t1 - t0)


if __name__ == '__main__':
    runs = [run_once() for _ in range(5)]
    print(f"MEAN_MSGS_PER_SEC={statistics.mean(runs):.2f}")
    print(f"STDEV_MSGS_PER_SEC={statistics.pstdev(runs):.2f}")
    print("RUNS_MSGS_PER_SEC=" + ",".join(f"{x:.2f}" for x in runs))
