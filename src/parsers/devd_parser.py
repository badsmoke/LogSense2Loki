import re

DEVD_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) devd \d+ - \[[^\]]+\] (?P<message>.+)'
)


def parse(log):
    match = DEVD_PATTERN.match(log)
    if not match:
        return None
    return {
        'timestamp': match.group('timestamp'),
        'hostname': match.group('hostname'),
        'service': 'devd',
        'message': match.group('message'),
    }
