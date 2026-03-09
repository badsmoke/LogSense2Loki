import re

FIREWALL_DNS_NOT_EXIST_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) firewall \d+ - \[meta sequenceId="\d+"\] '
    r'The DNS query name does not exist: (?P<query>\S+)\. \[for (?P<alias>[^\]]+)\]'
)
FIREWALL_RESOLVING_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) firewall \d+ - \[meta sequenceId="\d+"\] '
    r'resolving (?P<hostnames>\d+) hostnames \((?P<addresses>\d+) addresses\) for (?P<alias>\S+) took (?P<seconds>[\d\.]+) seconds'
)


def parse(log):
    match = FIREWALL_DNS_NOT_EXIST_PATTERN.match(log)
    if match:
        return {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'firewall',
            'log_type': 'dns_query_name_not_exists',
            'query': match.group('query'),
            'alias': match.group('alias'),
        }

    match = FIREWALL_RESOLVING_PATTERN.match(log)
    if match:
        return {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'firewall',
            'log_type': 'alias_resolving',
            'alias': match.group('alias'),
            'hostnames': match.group('hostnames'),
            'addresses': match.group('addresses'),
            'duration_seconds': match.group('seconds'),
        }

    return None
