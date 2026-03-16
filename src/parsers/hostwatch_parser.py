import re

HOSTWATCH_CHANGED_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) hostwatch \d+ - \[meta sequenceId="\d+"\]\s+'
    r'(?P<hostwatch_timestamp>[\d\-T:\.]+Z)\s+INFO hostwatch: changed ethernet address host '
    r'(?P<host_mac>[0-9a-f:]+) moved from (?P<old_mac>[0-9a-f:]+) to (?P<ip>\d+\.\d+\.\d+\.\d+) at (?P<interface>\S+)'
)
HOSTWATCH_NEW_STATION_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) hostwatch \d+ - \[meta sequenceId="\d+"\]\s+'
    r'(?P<hostwatch_timestamp>[\d\-T:\.]+Z)\s+INFO hostwatch: new station host '
    r'(?P<host_mac>[0-9a-f:]+) using (?P<ip>\d+\.\d+\.\d+\.\d+) at (?P<interface>\S+)'
)


def parse(log):
    match = HOSTWATCH_CHANGED_PATTERN.match(log)
    if match:
        return {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'hostwatch',
            'log_type': 'changed_ethernet_address',
            'hostwatch_timestamp': match.group('hostwatch_timestamp'),
            'host_mac': match.group('host_mac'),
            'old_mac': match.group('old_mac'),
            'ip': match.group('ip'),
            'interface': match.group('interface'),
        }

    match = HOSTWATCH_NEW_STATION_PATTERN.match(log)
    if match:
        return {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'hostwatch',
            'log_type': 'new_station',
            'hostwatch_timestamp': match.group('hostwatch_timestamp'),
            'host_mac': match.group('host_mac'),
            'ip': match.group('ip'),
            'interface': match.group('interface'),
        }

    return None
