import re

RULE_UPDATER_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) rule-updater.py \d+ - \[meta sequenceId="(?P<sequence_id>\d+)"\] (?P<message>.+)'
)


def parse_rule_updater(log):
    match = RULE_UPDATER_PATTERN.match(log)
    if not match:
        return None
    return {
        'timestamp': match.group('timestamp'),
        'hostname': match.group('hostname'),
        'service': 'rule-updater',
        'message': match.group('message'),
        'category': categorize_message(match.group('message')),
    }


def parse(log):
    return parse_rule_updater(log)


def categorize_message(message):
    if 'download completed' in message:
        return 'download completed'
    if 'download skipped' in message:
        return 'download skipped'
    if 'version response' in message:
        return 'version response'
    return 'general'
