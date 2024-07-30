import re

def parse_rule_updater(log):
    # Regex-Pattern für rule-updater Logs
    pattern = (
        r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) rule-updater.py \d+ - '
        r'\[meta sequenceId="(?P<sequence_id>\d+)"\] (?P<message>.+)'
    )
    
    
    match = re.match(pattern, log)
    
    if match:
        parsed_log = {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'rule-updater',
            'message': match.group('message'),
            'category': categorize_message(match.group('message')),
        }

        return parsed_log
    else:
        print(f"No match found! Log: {log}")
    
    return None

def categorize_message(message):
    if "download completed" in message:
        return "download completed"
    elif "download skipped" in message:
        return "download skipped"
    elif "version response" in message:
        return "version response"
    return "general"