import re

DPINGER_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) dpinger \d+ - '
    r'(?:\[meta sequenceId="\d+"\] )?ALERT: (?P<interface>\S+) '
    r'\(Addr: (?P<addr>[\d\.]+) Alarm: (?P<alarm>\S+) -> (?P<new_state>\S+) '
    r'RTT: (?P<rtt>[\d\.]+) ms RTTd: (?P<rttd>[\d\.]+) ms Loss: (?P<loss>[\d\.]+) \%\)'
)


def parse(log):
    match = DPINGER_PATTERN.match(log)
    if not match:
        return None
    return {
        'timestamp': match.group('timestamp'),
        'hostname': match.group('hostname'),
        'service': 'dpinger',
        'interface': match.group('interface'),
        'addr': match.group('addr'),
        'alarm': match.group('alarm'),
        'new_state': match.group('new_state'),
        'rtt': match.group('rtt'),
        'rttd': match.group('rttd'),
        'loss': match.group('loss'),
    }
