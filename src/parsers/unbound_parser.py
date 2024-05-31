import re

def parse(log):
    if ' info: ' in log:
        return parse_unbound_info_log(log)
    elif ' error: ' in log:
        return parse_unbound_error_log(log)
    else:
        return parse_standard_unbound_log(log)

def parse_standard_unbound_log(log):
    # Einfaches und präzises Regex-Pattern für Standard-Unbound-Logs ohne pid
    pattern = (
        r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) unbound \d+ - \[.*?\] '
        r'\[(?P<identifier_1>\d+):(?P<identifier_2>[^\]]+)\] query: (?P<src_ip>\d+\.\d+\.\d+\.\d+) '
        r'(?P<query>[^\s]+) (?P<record_type>[A-Z]+) IN'
    )

    match = re.match(pattern, log)
    
    if match:
        parsed_log = {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'resolver',
            'src_ip': match.group('src_ip'),
            'query': match.group('query'),
            'record_type': match.group('record_type')
        }
        return parsed_log
    else:
        print(f"No match found! Log: {log}")
    
    return None

def parse_unbound_info_log(log):
    pattern = (
        r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) unbound \d+ - \[.*?\] '
        r'\[\d+:[0-9a-f]+\] info: (?P<message>.+)$'
    )
    
    match = re.match(pattern, log)
    
    if match:
        parsed_log = {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'resolver',
            'log_type': 'info',
            'message': match.group('message')
        }
        return parsed_log
    else:
        print(f"Info log not matched! Log: {log}")
    
    return None

def parse_unbound_error_log(log):
    pattern = (
        r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) unbound \d+ - \[.*?\] '
        r'\[\d+:[^\]]+\] error: read \(in tcp s\): (?P<error>.+) for (?P<src_ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)'
    )

    match = re.match(pattern, log)
    
    if match:
        parsed_log = {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'resolver',
            'log_type': 'error',
            'error_message': match.group('error'),
            'src_ip': match.group('src_ip'),
            'port': match.group('port')
        }
        return parsed_log
    else:
        print(f"Error log not matched! Log: {log}")
    
    return None