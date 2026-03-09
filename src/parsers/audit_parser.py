import re

AUDIT_PATTERN = re.compile(
    r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) audit \d+ - \[meta sequenceId="\d+"\] (?P<message>.+)'
)
LOGIN_PATTERNS = {
    'user': re.compile(r"user '(?P<user>\w+)"),
    'ip': re.compile(r'from: (?P<ip>\d+\.\d+\.\d+\.\d+)'),
    'webgui_auth': re.compile(r'user (?P<user>\w+) authenticated successfully for WebGui'),
    'failure_reason': re.compile(r'reason: (?P<failure_reason>.+)'),
}
CHANGE_PATTERNS = {
    'user': re.compile(r'user (?P<user>\w+@[\d\.]+) changed configuration'),
    'config': re.compile(r'configuration to (?P<config_path>.+) in /'),
    'api_call': re.compile(r'in (?P<api_call>\S+)'),
}


def parse(log):
    match = AUDIT_PATTERN.match(log)
    if not match:
        return None

    message = match.group('message')
    parsed_log = {
        'timestamp': match.group('timestamp'),
        'hostname': match.group('hostname'),
        'service': 'audit',
        'message': message,
    }

    if 'Successful login' in message or 'authenticated successfully' in message or 'authentication failure' in message:
        parsed_log['log_type'] = 'login'
        parsed_log.update(parse_login(message))
    elif 'changed configuration' in message:
        parsed_log['log_type'] = 'change'
        parsed_log.update(parse_change(message))
    else:
        parsed_log['log_type'] = 'generic'

    return parsed_log


def parse_login(message):
    login_info = {}
    for key, pattern in LOGIN_PATTERNS.items():
        match = pattern.search(message)
        if match:
            login_info[key] = match.group(key)

    if 'Successful login' in message or 'authenticated successfully' in message:
        login_info['status'] = 'successful'
    elif 'authentication failure' in message:
        login_info['status'] = 'failed'

    return login_info


def parse_change(message):
    change_info = {}
    for key, pattern in CHANGE_PATTERNS.items():
        match = pattern.search(message)
        if not match:
            continue
        groups = match.groupdict()
        if key in groups:
            change_info[key] = groups[key]
        elif key == 'config' and 'config_path' in groups:
            change_info['config_path'] = groups['config_path']

    return change_info
