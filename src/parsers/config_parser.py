import re

def parse(log):
    # Regex-Pattern für config Logs
    pattern = (
        r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) config \d+ - '
        r'\[meta sequenceId="(?P<sequence_id>\d+)"\] config-event: (?P<message>.+)'
    )
    
    match = re.match(pattern, log)
    
    if match:
        parsed_log = {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'config',
            'message': match.group('message')
        }

        return parsed_log
    else:
        print(f"No match found! Log: {log}")

    return None