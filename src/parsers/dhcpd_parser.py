import re

DHC_DISCOVER_PATTERN = re.compile(
    r"<\d+>1 (?P<timestamp>[\d\-T\:\+\.\:]+) (?P<hostname>[\w\-\.]+) .* DHCPDISCOVER from (?P<mac>[0-9a-f:]+)( \((?P<client_hostname>.+?)\))? via (?P<interface>\w+)"
)
DHC_OFFER_PATTERN = re.compile(
    r"<\d+>1 (?P<timestamp>[\d\-T\:\+\.\:]+) (?P<hostname>[\w\-\.]+) .* DHCPOFFER on (?P<ip>\d+\.\d+\.\d+\.\d+) to (?P<mac>[0-9a-f:]+)( \((?P<client_hostname>.+?)\))? via (?P<interface>\w+)"
)
DHC_REQUEST_PATTERN = re.compile(
    r"<\d+>1 (?P<timestamp>[\d\-T\:\+\.\:]+) (?P<hostname>[\w\-\.]+) .* DHCPREQUEST for (?P<ip>\d+\.\d+\.\d+\.\d+)( \(\d+\.\d+\.\d+\.\d+\))? from (?P<mac>[0-9a-f:]+)( \((?P<client_hostname>.+?)\))? via (?P<interface>\w+)"
)
DHC_ACK_PATTERN = re.compile(
    r"<\d+>1 (?P<timestamp>[\d\-T\:\+\.\:]+) (?P<hostname>[\w\-\.]+) .* "
    r"DHCPACK (?:(?:on (?P<ip_on>\d+\.\d+\.\d+\.\d+) to)|(?:to (?P<ip_to>\d+\.\d+\.\d+\.\d+))) "
    r"\(?(?P<mac>[0-9a-f:]+)\)?( \((?P<client_hostname>.+?)\))? via (?P<interface>\w+)"
)
DHC_RELEASE_PATTERN = re.compile(
    r"<\d+>1 (?P<timestamp>[\d\-T\:\+\.\:]+) (?P<hostname>[\w\-\.]+) .* DHCPRELEASE of (?P<ip>\d+\.\d+\.\d+\.\d+) from (?P<mac>[0-9a-f:]+)( \((?P<client_hostname>.+?)\))? via (?P<interface>\w+) \(found\)"
)
DHC_INFORM_PATTERN = re.compile(
    r"<\d+>1 (?P<timestamp>[\d\-T\:\+\.\:]+) (?P<hostname>[\w\-\.]+) .* DHCPINFORM from (?P<ip>\d+\.\d+\.\d+\.\d+) via (?P<interface>\w+)"
)
DHC_DUPLICATE_PATTERN = re.compile(
    r"<\d+>1 (?P<timestamp>[\d\-T\:\+\.\:]+) (?P<hostname>[\w\-\.]+) .* uid lease (?P<ip>\d+\.\d+\.\d+\.\d+) for client (?P<mac>[0-9a-f:]+) is duplicate on (?P<subnet>[\d\.\/]+)"
)
DHC_REUSE_PATTERN = re.compile(
    r"<\d+>1 (?P<timestamp>[\d\-T\:\+\.\:]+) (?P<hostname>[\w\-\.]+) .* reuse_lease: lease age (?P<age>\d+) \(secs\) under 25% threshold, reply with unaltered, existing lease for (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
DHC_GENERIC_PATTERN = re.compile(
    r"<\d+>1 (?P<timestamp>[\d\-T\:\+\.\:]+) (?P<hostname>[\w\-\.]+) .* - \[meta sequenceId=\"\d+\"\] (?P<message>.+)"
)


def _base(match):
    return {
        'timestamp': match.group('timestamp'),
        'hostname': match.group('hostname'),
        'service': 'dhcp',
    }


def parse_dhcdiscover(line):
    match = DHC_DISCOVER_PATTERN.search(line)
    if not match:
        return None
    result = _base(match)
    result.update(
        {
            'type': 'dhcpdiscover',
            'mac': match.group('mac'),
            'client_hostname': match.group('client_hostname') if match.group('client_hostname') else None,
            'interface': match.group('interface'),
        }
    )
    return result


def parse_dhcpoffer(line):
    match = DHC_OFFER_PATTERN.search(line)
    if not match:
        return None
    result = _base(match)
    result.update(
        {
            'type': 'dhcpoffer',
            'ip': match.group('ip'),
            'mac': match.group('mac'),
            'client_hostname': match.group('client_hostname') if match.group('client_hostname') else None,
            'interface': match.group('interface'),
        }
    )
    return result


def parse_dhcrequest(line):
    match = DHC_REQUEST_PATTERN.search(line)
    if not match:
        return None
    result = _base(match)
    result.update(
        {
            'type': 'dhcprequest',
            'ip': match.group('ip'),
            'mac': match.group('mac'),
            'client_hostname': match.group('client_hostname') if match.group('client_hostname') else None,
            'interface': match.group('interface'),
        }
    )
    return result


def parse_dhcpack(line):
    match = DHC_ACK_PATTERN.search(line)
    if not match:
        return None
    ip = match.group('ip_on') or match.group('ip_to')
    result = _base(match)
    result.update(
        {
            'type': 'dhcpack',
            'ip': ip,
            'mac': match.group('mac'),
            'client_hostname': match.group('client_hostname') if match.group('client_hostname') else None,
            'interface': match.group('interface'),
        }
    )
    return result


def parse_dhcprelease(line):
    match = DHC_RELEASE_PATTERN.search(line)
    if not match:
        return None
    result = _base(match)
    result.update(
        {
            'type': 'dhcprelease',
            'ip': match.group('ip'),
            'mac': match.group('mac'),
            'client_hostname': match.group('client_hostname') if match.group('client_hostname') else None,
            'interface': match.group('interface'),
        }
    )
    return result


def parse_dhcpinform(line):
    match = DHC_INFORM_PATTERN.search(line)
    if not match:
        return None
    result = _base(match)
    result.update(
        {
            'type': 'dhcpinform',
            'ip': match.group('ip'),
            'interface': match.group('interface'),
        }
    )
    return result


def parse_duplicate_uid(line):
    match = DHC_DUPLICATE_PATTERN.search(line)
    if not match:
        return None
    result = _base(match)
    result.update(
        {
            'type': 'duplicate_uid_lease',
            'ip': match.group('ip'),
            'mac': match.group('mac'),
            'subnet': match.group('subnet'),
        }
    )
    return result


def parse_reuse(line):
    match = DHC_REUSE_PATTERN.search(line)
    if not match:
        return None
    result = _base(match)
    result.update(
        {
            'type': 'reuse_lease',
            'ip': match.group('ip'),
            'age': match.group('age'),
        }
    )
    return result


def parse_generic(line):
    match = DHC_GENERIC_PATTERN.search(line)
    if not match:
        return None
    result = _base(match)
    result.update({'message': match.group('message')})
    return result


def parse(log):
    if 'DHCPDISCOVER' in log:
        return parse_dhcdiscover(log)
    if 'DHCPOFFER' in log:
        return parse_dhcpoffer(log)
    if 'DHCPREQUEST' in log:
        return parse_dhcrequest(log)
    if 'DHCPACK' in log:
        return parse_dhcpack(log)
    if 'DHCPRELEASE' in log:
        return parse_dhcprelease(log)
    if 'DHCPINFORM' in log:
        return parse_dhcpinform(log)
    if 'is duplicate on' in log:
        return parse_duplicate_uid(log)
    if 'reuse_lease' in log:
        return parse_reuse(log)
    return parse_generic(log)
