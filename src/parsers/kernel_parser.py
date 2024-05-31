import re

def parse(log):
    # Vereinfachtes Regex-Pattern ohne sequenceId und pid
    pattern = (
        r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) devd \d+ - \[[^\]]+\] '
        r'(?P<message>.+)'
    )

    match = re.match(pattern, log)
    
    if match:
        parsed_log = {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'kernel',
            'message': match.group('message')
        }

        return parsed_log
    else:
        print(f"No match found! Log: {log}")
    
    return None

import re

def parse(log):
    # Aktualisiertes Regex-Pattern
    pattern = (
        r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) kernel - - \[meta sequenceId="\d+"\] (?P<message>.+)'
    )

    match = re.match(pattern, log)

    if match:
        parsed_log = {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'kernel',
            'message': match.group('message')
        }

        # Unterscheidung von ARP-Logs
        if match.group('message').startswith("arp:"):
            parsed_log['log_type'] = 'arp'
            parsed_log.update(parse_arp_message(match.group('message')))
        else:
            parsed_log['log_type'] = 'generic'

        return parsed_log
    else:
        print(f"No match found! Log: {log}")

    return None

def parse_arp_message(message):
    arp_pattern = r"arp: (?P<ip>\d+\.\d+\.\d+\.\d+) moved from (?P<old_mac>[0-9a-f:]+) to (?P<new_mac>[0-9a-f:]+) on (?P<interface>\S+)"
    match = re.search(arp_pattern, message)
    
    if match:
        return {
            'ip': match.group('ip'),
            'old_mac': match.group('old_mac'),
            'new_mac': match.group('new_mac'),
            'interface': match.group('interface')
        }
    
    return {}