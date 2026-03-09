import re

UNBOUND_STANDARD_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) unbound \d+ - \[.*?\] '
    r'\[(?P<identifier_1>\d+):(?P<identifier_2>[^\]]+)\] query: (?P<src_ip>\d+\.\d+\.\d+\.\d+) '
    r'(?P<query>[^\s]+) (?P<record_type>[A-Z]+) IN'
)
UNBOUND_INFO_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) unbound \d+ - \[.*?\] '
    r'\[\d+:[0-9a-f]+\] info: (?P<message>.+)$'
)
UNBOUND_ERROR_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) unbound \d+ - \[.*?\] '
    r'\[\d+:[^\]]+\] error: read \(in tcp s\): (?P<error>.+) for (?P<src_ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)'
)


def parse(log):
    if ' info: ' in log:
        return parse_unbound_info_log(log)
    if ' error: ' in log:
        return parse_unbound_error_log(log)
    return parse_standard_unbound_log(log)


def parse_standard_unbound_log(log):
    match = UNBOUND_STANDARD_PATTERN.match(log)
    if not match:
        return None
    return {
        'timestamp': match.group('timestamp'),
        'hostname': match.group('hostname'),
        'service': 'resolver',
        'src_ip': match.group('src_ip'),
        'query': match.group('query'),
        'record_type': match.group('record_type'),
    }


def parse_unbound_info_log(log):
    match = UNBOUND_INFO_PATTERN.match(log)
    if not match:
        return None
    return {
        'timestamp': match.group('timestamp'),
        'hostname': match.group('hostname'),
        'service': 'resolver',
        'log_type': 'info',
        'message': match.group('message'),
    }


def parse_unbound_error_log(log):
    match = UNBOUND_ERROR_PATTERN.match(log)
    if not match:
        return None
    return {
        'timestamp': match.group('timestamp'),
        'hostname': match.group('hostname'),
        'service': 'resolver',
        'log_type': 'error',
        'error_message': match.group('error'),
        'src_ip': match.group('src_ip'),
        'port': match.group('port'),
    }
