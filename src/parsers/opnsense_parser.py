import re

def parse(log):
    # Regex pattern für Opnsense-Logs
    pattern = (
        r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) opnsense \d+ - '
        r'\[meta sequenceId="(?P<sequence_id>\d+)"\] (?P<message>.+)'
    )



    match = re.match(pattern, log)
    
    if match:
        parsed_log = {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'opnsense',
            'message': match.group('message')
        }

        return parsed_log
    else:
        print(f"No match found! Log: {log}")
    
    return None