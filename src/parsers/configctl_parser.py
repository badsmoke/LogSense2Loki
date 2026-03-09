import re

CONFIGCTL_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) configctl \d+ - \[[^\]]+\] (?P<message>.+)'
)


def parse(log):
    match = CONFIGCTL_PATTERN.match(log)
    if not match:
        return None
    return {
        'timestamp': match.group('timestamp'),
        'hostname': match.group('hostname'),
        'service': 'configctl',
        'message': match.group('message'),
    }
