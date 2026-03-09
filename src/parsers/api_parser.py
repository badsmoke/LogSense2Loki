import re

API_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) api \d+ - \[[^\]]+\] (?P<message>.+)'
)


def parse(log):
    match = API_PATTERN.match(log)
    if not match:
        return None
    return {
        'timestamp': match.group('timestamp'),
        'hostname': match.group('hostname'),
        'service': 'api',
        'message': match.group('message'),
    }
