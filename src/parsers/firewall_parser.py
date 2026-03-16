import re

FIREWALL_DNS_NOT_EXIST_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) firewall \d+ - \[meta sequenceId="\d+"\] '
    r'The DNS query name does not exist: (?P<query>\S+)\. \[for (?P<alias>[^\]]+)\]'
)
FIREWALL_RESOLVING_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) firewall \d+ - \[meta sequenceId="\d+"\] '
    r'resolving (?P<hostnames>\d+) hostnames \((?P<addresses>\d+) addresses\) for (?P<alias>\S+) took (?P<seconds>[\d\.]+) seconds'
)
FIREWALL_FETCH_ALIAS_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) firewall \d+ - \[meta sequenceId="\d+"\] '
    r'fetch alias url (?P<url>\S+) \(lines: (?P<lines>\d+)\)'
)
FIREWALL_PROCESSING_ALIAS_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) firewall \d+ - \[meta sequenceId="\d+"\] '
    r'processing alias url (?P<url>\S+) took (?P<seconds>[\d\.]+)s'
)
FIREWALL_FETCH_ALIAS_ERROR_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) firewall \d+ - \[meta sequenceId="\d+"\] '
    r'error fetching alias url (?P<url>\S+) (?:\[(?P<details_bracket>[^\]]+)\]|\((?P<details_paren>[^\)]+)\))'
)
FIREWALL_ALIAS_RESOLVE_ERROR_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) firewall \d+ - \[meta sequenceId="\d+"\] '
    r'alias resolve error (?P<alias>\S+) \((?P<details>[^\)]+)\)'
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

    match = FIREWALL_FETCH_ALIAS_PATTERN.match(log)
    if match:
        return {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'firewall',
            'log_type': 'alias_fetch',
            'url': match.group('url'),
            'lines': match.group('lines'),
        }

    match = FIREWALL_PROCESSING_ALIAS_PATTERN.match(log)
    if match:
        return {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'firewall',
            'log_type': 'alias_processing',
            'url': match.group('url'),
            'duration_seconds': match.group('seconds'),
        }

    match = FIREWALL_FETCH_ALIAS_ERROR_PATTERN.match(log)
    if match:
        details = match.group('details_bracket') or match.group('details_paren')
        return {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'firewall',
            'log_type': 'alias_fetch_error',
            'url': match.group('url'),
            'details': details,
        }

    match = FIREWALL_ALIAS_RESOLVE_ERROR_PATTERN.match(log)
    if match:
        return {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'firewall',
            'log_type': 'alias_resolve_error',
            'alias': match.group('alias'),
            'details': match.group('details'),
        }

    return None
