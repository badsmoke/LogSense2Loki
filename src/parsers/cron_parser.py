import re

CRON_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) /usr/sbin/cron \d+ - \[[^\]]+\] \((?P<user>\S+)\) CMD \((?P<command>.+?)\)'
)


def parse(log):
    match = CRON_PATTERN.match(log)
    if not match:
        return None
    return {
        'timestamp': match.group('timestamp'),
        'hostname': match.group('hostname'),
        'service': 'cron',
        'user': match.group('user'),
        'command': match.group('command'),
    }
