import re

def parse(log):
    
    pattern = (
        r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) configctl \d+ - \[[^\]]+\] '
        r'(?P<message>.+)'
    )

    match = re.match(pattern, log)
    
    if match:
        parsed_log = {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'configctl',
            'message': match.group('message')
        }

        return parsed_log
    else:
        print(f"No match found! Log: {log}")
    
    return None

