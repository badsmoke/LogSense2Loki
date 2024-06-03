import re

def parse(log):
    pattern = (
        r'<\d+>1 (?P<timestamp>[\d\-T:+\.]+) (?P<hostname>\S+) audit \d+ - \[meta sequenceId="\d+"\] '
        r'(?P<message>.+)'
    )

    match = re.match(pattern, log)

    if match:
        message = match.group('message')
        parsed_log = {
            'timestamp': match.group('timestamp'),
            'hostname': match.group('hostname'),
            'service': 'audit',
            'message': message
        }

        # Categorization of the logs
        if "Successful login" in message or "authenticated successfully" in message or "authentication failure" in message:
            parsed_log['log_type'] = 'login'
            parsed_log.update(parse_login(message))
        elif "changed configuration" in message:
            parsed_log['log_type'] = 'change'
            parsed_log.update(parse_change(message))
        else:
            parsed_log['log_type'] = 'generic'

        return parsed_log
    else:
        print(f"No match found! Log: {log}")
    
    return None

def parse_login(message):
    login_info = {}
    login_patterns = {
        'user': r"user '(?P<user>\w+)'",
        'ip': r"from: (?P<ip>\d+\.\d+\.\d+\.\d+)",
        'webgui_auth': r"user (?P<user>\w+) authenticated successfully for WebGui",
        'failure_reason': r"reason: (?P<failure_reason>.+)"
    }

    for key, pattern in login_patterns.items():
        match = re.search(pattern, message)
        if match:
            login_info[key] = match.group(key)

    # Determining the login status
    if "Successful login" in message or "authenticated successfully" in message:
        login_info['status'] = 'successful'
    elif "authentication failure" in message:
        login_info['status'] = 'failed'

    return login_info

def parse_change(message):
    change_info = {}
    change_patterns = {
        'user': r"user (?P<user>\w+@[\d\.]+) changed configuration",
        'config': r"configuration to (?P<config_path>.+) in /",
        'api_call': r"in (?P<api_call>\S+)"
    }
    
    for key, pattern in change_patterns.items():
        match = re.search(pattern, message)
        if match:
            change_info[key] = match.group(key)
    
    return change_info