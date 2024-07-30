import re

def parse(log):
    # Regex pattern für die Standard lighttpd Logs
    standard_pattern = (
        r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) lighttpd \d+ - \[meta sequenceId="\d+"\] '
        r'(?P<client_ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<request_time>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>HTTP/\d+\.\d+)" (?P<status_code>\d+) (?P<response_size>\d+) '
        r'"(?P<referer>[^\"]*)" "(?P<user_agent>[^\"]*)"'
    )

    # Regex pattern für PRI-Requests
    pri_pattern = (
        r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) lighttpd \d+ - \[meta sequenceId="\d+"\] '
        r'(?P<client_ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<request_time>[^\]]+)\] '
        r'"PRI \* (?P<protocol>HTTP/\d+\.\d+)" (?P<status_code>\d+) - "-" "-"'
    )

    # Regex pattern für Server Start/Stop Logs
    server_action_pattern = (
        r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) lighttpd \d+ - \[meta sequenceId="\d+"\] '
        r'\(.*?\) (?P<action>(server started|server stopped|graceful shutdown started)\s*\(lighttpd/[^\)]+\))'
    )

    # Überprüfen, ob es ein Standard-Log ist
    standard_match = re.match(standard_pattern, log)
    if standard_match:
        return {
            'timestamp': standard_match.group('timestamp'),
            'hostname': standard_match.group('hostname'),
            'service': 'lighttpd',
            'client_ip': standard_match.group('client_ip'),
            'request_time': standard_match.group('request_time'),
            'method': standard_match.group('method'),
            'path': standard_match.group('path'),
            'protocol': standard_match.group('protocol'),
            'status_code': standard_match.group('status_code'),
            'response_size': standard_match.group('response_size'),
            'referer': standard_match.group('referer'),
            'user_agent': standard_match.group('user_agent')
        }

    # Überprüfen, ob es ein PRI-Request-Log ist
    pri_match = re.match(pri_pattern, log)
    if pri_match:
        return {
            'timestamp': pri_match.group('timestamp'),
            'hostname': pri_match.group('hostname'),
            'service': 'lighttpd',
            'client_ip': pri_match.group('client_ip'),
            'request_time': pri_match.group('request_time'),
            'protocol': pri_match.group('protocol'),
            'status_code': pri_match.group('status_code'),
            'response_size': '-',
            'referer': '-',
            'user_agent': '-'
        }

    # Überprüfen, ob es sich um einen Server-Aktions-Log handelt
    server_action_match = re.match(server_action_pattern, log)
    if server_action_match:
        return {
            'timestamp': server_action_match.group('timestamp'),
            'hostname': server_action_match.group('hostname'),
            'service': 'lighttpd',
            'action': server_action_match.group('action')
        }

    print(f"No match found! Log: {log}")
    
    return None