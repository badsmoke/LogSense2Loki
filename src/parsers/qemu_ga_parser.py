import re

QEMU_GA_INFO_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) qemu-ga \d+ - '
    r'\[meta sequenceId="\d+"\] (?P<level>\w+): (?P<message>.+)$'
)


def parse(log):
    match = QEMU_GA_INFO_PATTERN.match(log)
    if not match:
        return None
    return {
        'timestamp': match.group('timestamp'),
        'hostname': match.group('hostname'),
        'service': 'qemu-ga',
        'log_type': match.group('level').lower(),
        'message': match.group('message'),
    }
