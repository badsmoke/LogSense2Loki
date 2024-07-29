import re

def parse(log):
    pattern = (
        r'<\d+>1\s(?P<timestamp>[\d\-T:+]+)\s(?P<hostname>\S+)\sfilterlog\s(?P<pid>\d+)\s-\s'
        r'\[meta\ssequenceId="(?P<sequenceId>\d+)"\]\s'
        r'(?P<rulenumber>\d+),,,(?P<uuid>[0-9a-fA-F]+),'
        r'(?P<interface>\S+),(?P<reason>\S*),(?P<action>\S*),'
        r'(?P<direction>\S+),(?P<ipversion>\d+),'
        r'(?P<tclass>[^,]*)(?:,,)?\s?'
        r'(?P<ttl>\d+),(?P<ident>\d+),0,(?P<flags>\S*),'
        r'(?P<proto_num>\d+),(?P<proto>\S+),(?P<protolength>\d+),'
        r'(?P<src_ip>\d+\.\d+\.\d+\.\d+),(?P<dst_ip>\d+\.\d+\.\d+\.\d+),'
        r'(?:(?P<src_port>\d+),(?P<dst_port>\d+),)?'
        r'(?P<length>\d+)?(?:,datalength=(?P<datalength>\d+))?'
    )

    try:
        match = re.match(pattern, log)
    except re.error as e:
        print(f"Regex error: {e}")
        return None

    if match:
        parsed_log = {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'filterlog',
            'rulenumber': match.group('rulenumber'),
            'uuid': match.group('uuid'),
            'interface': match.group('interface'),
            'reason': match.group('reason'),
            'action': match.group('action'),
            'direction': match.group('direction'),
            'ipversion': match.group('ipversion'),
            'tclass': match.group('tclass'),
            'ttl': match.group('ttl'),
            'ident': match.group('ident'),
            'flags': match.group('flags'),
            'proto_num': match.group('proto_num'),
            'proto': match.group('proto'),
            'protolength': match.group('protolength'),
            'src_ip': match.group('src_ip'),
            'dst_ip': match.group('dst_ip')
        }

        # Length is taken from either the 'length' or 'datalength' field.
        if match.group('length'):
            parsed_log['length'] = match.group('length')
        if match.group('datalength'):
            parsed_log['datalength'] = match.group('datalength')

        # Ports are optional, so check and add them separately.
        if match.group('src_port'):
            parsed_log['src_port'] = match.group('src_port')
        if match.group('dst_port'):
            parsed_log['dst_port'] = match.group('dst_port')

        return parsed_log
    else:
        print(f"No match found! Log: {log}")

    return None