import re

OPNSENSE_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) opnsense \d+ - \[meta sequenceId="(?P<sequence_id>\d+)"\] (?P<message>.+)'
)


def parse(log):
    match = OPNSENSE_PATTERN.match(log)
    if not match:
        return None
    return {
        'timestamp': match.group('timestamp'),
        'hostname': match.group('hostname'),
        'service': 'opnsense',
        'message': match.group('message'),
    }
