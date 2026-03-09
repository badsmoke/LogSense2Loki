import re

CONFIGD_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) configd\.py \d+ - \[[^\]]+\] (\[(?P<uuid>[\da-fA-F-]+)\] )?(?P<message>.+)'
)


def parse(log):
    match = CONFIGD_PATTERN.match(log)
    if not match:
        return None

    parsed = {
        'timestamp': match.group('timestamp'),
        'hostname': match.group('hostname'),
        'service': 'configd',
        'message': match.group('message'),
    }
    if match.group('uuid'):
        parsed['uuid'] = match.group('uuid')
    return parsed
