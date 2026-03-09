import re

CONFIG_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) config \d+ - \[meta sequenceId="(?P<sequence_id>\d+)"\] config-event: (?P<message>.+)'
)


def parse(log):
    match = CONFIG_PATTERN.match(log)
    if not match:
        return None
    return {
        'timestamp': match.group('timestamp'),
        'hostname': match.group('hostname'),
        'service': 'config',
        'message': match.group('message'),
    }
