import re

SYSLOGNG_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) syslog-ng \d+ - \[meta sequenceId="\d+"\] (?P<message>.+)'
)
SYSLOGNG_ERROR_IP_PATTERN = re.compile(r'server=.*\((\d{1,3}(?:\.\d{1,3}){3})')
STATS_PATTERNS = {
    'eps_last_1h': re.compile(r"eps_last_1h='[^=]+=(\d+)"),
    'msg_size_max': re.compile(r"msg_size_max='[^=]+=(\d+)"),
    'msg_size_avg': re.compile(r"msg_size_avg='[^=]+=(\d+)"),
    'truncated_bytes': re.compile(r"truncated_bytes='[^=]+=(\d+)"),
    'eps_since_start': re.compile(r"eps_since_start='[^=]+=(\d+)"),
    'memory_usage': re.compile(r"memory_usage='[^=]+=(\d+)"),
    'truncated_count': re.compile(r"truncated_count='[^=]+=(\d+)"),
    'eps_last_24h': re.compile(r"eps_last_24h='[^=]+=(\d+)"),
    'processed': re.compile(r"processed='[^=]+=(\d+)"),
}


def parse(log):
    match = SYSLOGNG_PATTERN.match(log)
    if not match:
        return None

    message = match.group('message')
    parsed_log = {
        'timestamp': match.group('timestamp'),
        'hostname': match.group('hostname'),
        'service': 'syslog-ng',
        'message': message,
    }

    if 'Log statistics' in message:
        parsed_log['log_type'] = 'statistics'
        parsed_log.update(parse_statistics(message))
    elif 'error' in message and 'server=' in message:
        ip_match = SYSLOGNG_ERROR_IP_PATTERN.search(message)
        if ip_match:
            parsed_log['log_type'] = 'error'
            parsed_log['ip'] = ip_match.group(1)
        else:
            parsed_log['log_type'] = 'generic'
    else:
        parsed_log['log_type'] = 'generic'

    return parsed_log


def parse_statistics(message):
    stats = {}
    for key, pattern in STATS_PATTERNS.items():
        match = pattern.search(message)
        stats[key] = match.group(1) if match else 'N/A'
    return stats
