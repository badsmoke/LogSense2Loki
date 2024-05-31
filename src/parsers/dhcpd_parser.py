import re

 
def parse_dhcdiscover(line):
    dhcpdiscover_pattern = re.compile(r"<\d+>1 (?P<timestamp>[\d\-T\:\+\.\:]+) (?P<hostname>[\w\-\.]+) .* DHCPDISCOVER from (?P<mac>[0-9a-f:]+)( \((?P<client_hostname>.+?)\))? via (?P<interface>\w+)")
    discover_match = dhcpdiscover_pattern.search(line)
    return {
            'timestamp': discover_match.group('timestamp'),
            'hostname': discover_match.group('hostname'),
            'type': 'dhcpdiscover',
            'service': 'dhcp',
            'mac': discover_match.group('mac'),
            'client_hostname': discover_match.group('client_hostname') if discover_match.group('client_hostname') else None,
            'interface': discover_match.group('interface')
        }

def parse_dhcpoffer(line):
    dhcpoffer_pattern = re.compile(r"<\d+>1 (?P<timestamp>[\d\-T\:\+\.\:]+) (?P<hostname>[\w\-\.]+) .* DHCPOFFER on (?P<ip>\d+\.\d+\.\d+\.\d+) to (?P<mac>[0-9a-f:]+)( \((?P<client_hostname>.+?)\))? via (?P<interface>\w+)")
    offer_match = dhcpoffer_pattern.search(line)
    return {
            'timestamp': offer_match.group('timestamp'),
            'hostname': offer_match.group('hostname'),
            'type': 'dhcpoffer',
            'service': 'dhcp',
            'ip': offer_match.group('ip'),
            'mac': offer_match.group('mac'),
            'client_hostname': offer_match.group('client_hostname') if offer_match.group('client_hostname') else None,
            'interface': offer_match.group('interface')
        }

def parse_dhcrequest(line):
    dhcprequest_pattern = re.compile(r"<\d+>1 (?P<timestamp>[\d\-T\:\+\.\:]+) (?P<hostname>[\w\-\.]+) .* DHCPREQUEST for (?P<ip>\d+\.\d+\.\d+\.\d+)( \(\d+\.\d+\.\d+\.\d+\))? from (?P<mac>[0-9a-f:]+)( \((?P<client_hostname>.+?)\))? via (?P<interface>\w+)")
    request_match = dhcprequest_pattern.search(line)
    return {
            'timestamp': request_match.group('timestamp'),
            'hostname': request_match.group('hostname'),
            'type': 'dhcprequest',
            'service': 'dhcp',
            'ip': request_match.group('ip'),
            'mac': request_match.group('mac'),
            'client_hostname': request_match.group('client_hostname') if request_match.group('client_hostname') else None,
            'interface': request_match.group('interface')
        }

def parse_dhcpack(line):
    dhcpack_pattern = re.compile(r"<\d+>1 (?P<timestamp>[\d\-T\:\+\.\:]+) (?P<hostname>[\w\-\.]+) .* DHCPACK on (?P<ip>\d+\.\d+\.\d+\.\d+) to (?P<mac>[0-9a-f:]+)( \((?P<client_hostname>.+?)\))? via (?P<interface>\w+)")
    ack_match = dhcpack_pattern.search(line)
    return {
            'timestamp': ack_match.group('timestamp'),
            'hostname': ack_match.group('hostname'),
            'type': 'dhcpack',
            'service': 'dhcp',
            'ip': ack_match.group('ip'),
            'mac': ack_match.group('mac'),
            'client_hostname': ack_match.group('client_hostname') if ack_match.group('client_hostname') else None,
            'interface': ack_match.group('interface')
        }

def parse_dhcprelease(line):
    dhcprelease_pattern = re.compile(r"<\d+>1 (?P<timestamp>[\d\-T\:\+\.\:]+) (?P<hostname>[\w\-\.]+) .* DHCPRELEASE of (?P<ip>\d+\.\d+\.\d+\.\d+) from (?P<mac>[0-9a-f:]+)( \((?P<client_hostname>.+?)\))? via (?P<interface>\w+) \(found\)")
    release_match = dhcprelease_pattern.search(line)
    return {
        'timestamp': release_match.group('timestamp'),
        'hostname': release_match.group('hostname'),
        'type': 'dhcprelease',
        'service': 'dhcp',
        'ip': release_match.group('ip'),
        'mac': release_match.group('mac'),
        'client_hostname': release_match.group('client_hostname') if release_match.group('client_hostname') else None,
        'interface': release_match.group('interface')
    }

def parse_dhcpinform(line):
    dhcpinform_pattern = re.compile(r"<\d+>1 (?P<timestamp>[\d\-T\:\+\.\:]+) (?P<hostname>[\w\-\.]+) .* DHCPINFORM from (?P<ip>\d+\.\d+\.\d+\.\d+) via (?P<interface>\w+)")
    inform_match = dhcpinform_pattern.search(line)
    return {
        'timestamp': inform_match.group('timestamp'),
        'hostname': inform_match.group('hostname'),
        'type': 'dhcpinform',
        'service': 'dhcp',
        'ip': inform_match.group('ip'),
        'interface': inform_match.group('interface')
    }

def parse_duplicate_uid(line):
    duplicate_uid_pattern = re.compile(r"<\d+>1 (?P<timestamp>[\d\-T\:\+\.\:]+) (?P<hostname>[\w\-\.]+) .* uid lease (?P<ip>\d+\.\d+\.\d+\.\d+) for client (?P<mac>[0-9a-f:]+) is duplicate on (?P<subnet>[\d\.\/]+)")
    duplicate_match = duplicate_uid_pattern.search(line)
    return {
        'timestamp': duplicate_match.group('timestamp'),
        'hostname': duplicate_match.group('hostname'),
        'type': 'duplicate_uid_lease',
        'service': 'dhcp',
        'ip': duplicate_match.group('ip'),
        'mac': duplicate_match.group('mac'),
        'subnet': duplicate_match.group('subnet')
    }

def parse_reuse(line):
    reuse_lease_pattern = re.compile(r"<\d+>1 (?P<timestamp>[\d\-T\:\+\.\:]+) (?P<hostname>[\w\-\.]+) .* reuse_lease: lease age (?P<age>\d+) \(secs\) under 25% threshold, reply with unaltered, existing lease for (?P<ip>\d+\.\d+\.\d+\.\d+)")
    reuse_match = reuse_lease_pattern.search(line)
    return {
            'timestamp': reuse_match.group('timestamp'),
            'hostname': reuse_match.group('hostname'),
            'type': 'reuse_lease',
            'service': 'dhcp',
            'ip': reuse_match.group('ip'),
            'age': reuse_match.group('age')
        }

def parse_generic(line):
    generic_pattern = re.compile(r"<\d+>1 (?P<timestamp>[\d\-T\:\+\.\:]+) (?P<hostname>[\w\-\.]+) .* - \[meta sequenceId=\"\d+\"\] (?P<message>.+)")
    generic_match = generic_pattern.search(line)
    return {
        'timestamp': generic_match.group('timestamp'),
        'hostname': generic_match.group('hostname'),
        'service': 'dhcp',
        'message': generic_match.group('message')
    }


def parse(log):

   
    if "DHCPDISCOVER" in log:
        match=parse_dhcdiscover(log)
    elif "DHCPOFFER" in log:
        match=parse_dhcpoffer(log)
    elif "DHCPREQUEST" in log:
        match=parse_dhcrequest(log)
    elif "DHCPACK" in log:
        match=parse_dhcpack(log)
    elif "DHCPRELEASE" in log:
        match = parse_dhcprelease(log) 
    elif "DHCPINFORM" in log:
        match = parse_dhcpinform(log)     
    elif "is duplicate on" in log:
        match = parse_duplicate_uid(log)                  
    elif "reuse_lease" in log:
        match=parse_reuse(log)
    else:
        match=parse_generic(log)

    #match 
    if match:

        return match
    else:
        print("No match found!")
        return None