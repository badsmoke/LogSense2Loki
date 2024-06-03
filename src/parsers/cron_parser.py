import re

def parse(log):
    # Regex pattern for cron logs
    pattern = (
        r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) /usr/sbin/cron \d+ - \[[^\]]+\] '
        r'\((?P<user>\S+)\) CMD \((?P<command>.+?)\)'
    )

    match = re.match(pattern, log)
    
    if match:
        parsed_log = {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'cron',
            'user': match.group('user'),
            'command': match.group('command')
        }
        return parsed_log
    else:
        print(f"No match found! Log: {log}")
    
    return None