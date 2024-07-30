import re

def parse(log):
    pattern = (
        r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) dpinger \d+ - '
        r'ALERT: (?P<interface>\S+) '
        r'\(Addr: (?P<addr>[\d\.]+) '
        r'Alarm: (?P<alarm>\S+) '
        r'-> (?P<new_state>\S+) '
        r'RTT: (?P<rtt>[\d\.]+) ms '
        r'RTTd: (?P<rttd>[\d\.]+) ms '
        r'Loss: (?P<loss>[\d\.]+) \%\)'
    )

    match = re.match(pattern, log)
    
    if match:
        parsed_log = {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'dpinger',
            'interface': match.group('interface'),
            'addr': match.group('addr'),
            'alarm': match.group('alarm'),
            'new_state': match.group('new_state'),
            'rtt': match.group('rtt'),
            'rttd': match.group('rttd'),
            'loss': match.group('loss')
        }

        return parsed_log
    else:
        print(f"No match found! Log: {log}")
    
    return None