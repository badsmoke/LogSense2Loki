import re

def parse(log):
    
    pattern = (
        r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) configd\.py \d+ - \[[^\]]+\] '
        r'(\[(?P<uuid>[\da-fA-F-]+)\] )?(?P<message>.+)'
    )

    match = re.match(pattern, log)
    
    if match:
        if  match.group('uuid'):
            parsed_log = {
                'timestamp': match.group('timestamp'),
                'hostname': match.group('hostname'),
                'service': 'configd',
                'uuid': match.group('uuid'),
                'message': match.group('message')
            }
        else:
            parsed_log = {
                'timestamp': match.group('timestamp'),
                'hostname': match.group('hostname'),
                'service': 'configd',
                'message': match.group('message')
            }

        return parsed_log
    else:
        print(f"No match found! Log: {log}")
    
    return None