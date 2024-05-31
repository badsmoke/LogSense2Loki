import re

def parse(log):
    # Vereinfachtes Regex-Pattern ohne sequenceId und pid
    pattern = (
        r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) syslog-ng \d+ - \[meta sequenceId="\d+"\] '
        r'(?P<message>.+)'
    )

    match = re.match(pattern, log)
    
    if match:
        message = match.group('message')
        parsed_log = {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'syslog-ng',
            'message': message
        }

        # Unterscheidung der Logs
        if "Log statistics" in message:
            parsed_log['log_type'] = 'statistics'
            parsed_log.update(parse_statistics(message))
        elif "error" in message and 'server=' in message:
            ip_match = re.search(r'server=.*\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
            if ip_match:
                parsed_log['log_type'] = 'error'
                parsed_log['ip'] = ip_match.group(1)
            else:
                parsed_log['log_type'] = 'generic'
        else:
            parsed_log['log_type'] = 'generic'

        return parsed_log
    else:
        print(f"No match found! Log: {log}")
    
    return None

def parse_statistics(message):
    stats = {}
    patterns = {
        'eps_last_1h': r"eps_last_1h='[^=]+=(\d+)'",
        'msg_size_max': r"msg_size_max='[^=]+=(\d+)'",
        'msg_size_avg': r"msg_size_avg='[^=]+=(\d+)'",
        'truncated_bytes': r"truncated_bytes='[^=]+=(\d+)'",
        'eps_since_start': r"eps_since_start='[^=]+=(\d+)'",
        'memory_usage': r"memory_usage='[^=]+=(\d+)'",
        'truncated_count': r"truncated_count='[^=]+=(\d+)'",
        'eps_last_24h': r"eps_last_24h='[^=]+=(\d+)'",
        'processed': r"processed='[^=]+=(\d+)'"
    }
    
    for key, pattern in patterns.items():
        match = re.search(pattern, message)
        if match:
            stats[key] = match.group(1)
        else:
            stats[key] = "N/A"
    
    return stats