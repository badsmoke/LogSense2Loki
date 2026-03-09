import re

KERNEL_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) kernel - - \[meta sequenceId="\d+"\] (?P<message>.+)'
)
ARP_PATTERN = re.compile(
    r'arp: (?P<ip>\d+\.\d+\.\d+\.\d+) moved from (?P<old_mac>[0-9a-f:]+) to (?P<new_mac>[0-9a-f:]+) on (?P<interface>\S+)'
)


def parse(log):
    match = KERNEL_PATTERN.match(log)
    if not match:
        return None

    message = match.group('message')
    parsed_log = {
        'timestamp': match.group('timestamp'),
        'hostname': match.group('hostname'),
        'service': 'kernel',
        'message': message,
    }

    if message.startswith('arp:'):
        parsed_log['log_type'] = 'arp'
        parsed_log.update(parse_arp_message(message))
    else:
        parsed_log['log_type'] = 'generic'

    return parsed_log


def parse_arp_message(message):
    match = ARP_PATTERN.search(message)
    if not match:
        return {}
    return {
        'ip': match.group('ip'),
        'old_mac': match.group('old_mac'),
        'new_mac': match.group('new_mac'),
        'interface': match.group('interface'),
    }
