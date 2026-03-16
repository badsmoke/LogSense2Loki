import re

CRON_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) /usr/sbin/cron \d+ - \[[^\]]+\] \((?P<user>\S+)\) CMD \((?P<command>.+?)\)'
)
CRON_MAIL_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) /usr/sbin/cron \d+ - \[[^\]]+\] '
    r'\((?P<user>\S+)\) MAIL \((?P<message>.+)'
)


def parse(log):
    match = CRON_PATTERN.match(log)
    if match:
        return {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'cron',
            'log_type': 'cmd',
            'user': match.group('user'),
            'command': match.group('command'),
        }

    match = CRON_MAIL_PATTERN.match(log)
    if match:
        return {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'cron',
            'log_type': 'mail',
            'user': match.group('user'),
            'message': match.group('message'),
        }

    return None
