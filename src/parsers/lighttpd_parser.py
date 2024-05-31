import re

def parse(log):
    # Regex-Pattern für lighttpd-Logs
    pattern = (
        r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) lighttpd \d+ - \[[^\]]+\] '
        r'(?P<client_ip>\d+\.\d+\.\d+\.\d+) (?P<target_host>\S+) - \[(?P<request_time>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>HTTP/\d+\.\d+)" (?P<status_code>\d+) (?P<response_size>\d+) '
        r'"(?P<referer>[^\"]*)" "(?P<user_agent>[^\"]*)"'
    )

    match = re.match(pattern, log)
    
    if match:
        parsed_log = {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'lighttpd',
            'client_ip': match.group('client_ip'),
            'target_host': match.group('target_host'),
            'request_time': match.group('request_time'),
            'method': match.group('method'),
            'path': match.group('path'),
            'protocol': match.group('protocol'),
            'status_code': match.group('status_code'),
            'response_size': match.group('response_size'),
            'referer': match.group('referer'),
            'user_agent': match.group('user_agent')
        }

        return parsed_log
    else:
        print(f"No match found! Log: {log}")
    
    return None