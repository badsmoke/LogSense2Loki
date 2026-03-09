import re

DHCLIENT_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) dhclient \d+ - \[[^\]]+\] (?P<message>.+)'
)


def parse(log):
    match = DHCLIENT_PATTERN.match(log)
    if not match:
        return None
    return {
        'timestamp': match.group('timestamp'),
        'hostname': match.group('hostname'),
        'service': 'dhclient',
        'message': match.group('message'),
    }
