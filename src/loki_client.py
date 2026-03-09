import json
import os
from datetime import datetime

import requests
from requests.adapters import HTTPAdapter
from requests.auth import HTTPBasicAuth
from urllib3.util.retry import Retry
import urllib3

import config

try:
    import orjson
except ImportError:
    orjson = None


session = requests.Session()

retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=['HEAD', 'GET', 'OPTIONS', 'POST'],
)

adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=20, pool_maxsize=20, pool_block=True)
session.mount('http://', adapter)
session.mount('https://', adapter)
session.headers.update({'Connection': 'keep-alive'})


def _labels(job_label, service, hostname):
    return f'{{job="{job_label}",service="{service}",hostname="{hostname}"}}'


def _serialize_log_line(log):
    if orjson is not None:
        return orjson.dumps(log).decode('utf-8')
    return json.dumps(log, separators=(',', ':'))


def _serialize_payload(payload):
    if orjson is not None:
        return orjson.dumps(payload)
    return json.dumps(payload)


def send_to_loki(logs):
    if not logs:
        return 0

    headers = {'Content-Type': 'application/json'}
    job_label = os.getenv('JOB_LABEL', config.JOB_LABEL)

    loki_username = os.getenv('LOKI_AUTH_USERNAME')
    loki_password = os.getenv('LOKI_AUTH_PASSWORD')
    verify_ssl = os.getenv('LOKI_AUTH_VERIFY_SSL', 'True').lower() == 'true'

    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    auth = HTTPBasicAuth(loki_username, loki_password) if loki_username and loki_password else None

    streams_by_labels = {}
    valid_count = 0

    for log in logs:
        if not isinstance(log, dict):
            continue

        service = log.get('service')
        hostname = log.get('hostname')
        if not service or not hostname:
            continue

        labels = _labels(job_label, service, hostname)
        entry = {
            'ts': datetime.utcnow().isoformat('T') + 'Z',
            'line': _serialize_log_line(log),
        }
        streams_by_labels.setdefault(labels, []).append(entry)
        valid_count += 1

    if not streams_by_labels:
        return 0

    payload = {
        'streams': [
            {'labels': labels, 'entries': entries}
            for labels, entries in streams_by_labels.items()
        ]
    }
    loki_url = os.getenv('LOKI_URL', config.LOKI_URL)

    try:
        response = session.post(
            loki_url,
            headers=headers,
            data=_serialize_payload(payload),
            auth=auth,
            verify=verify_ssl,
            timeout=(2, 10),
        )
        if response.status_code != 204:
            raise RuntimeError(f'Loki returned status {response.status_code}: {response.text[:500]}')
    except requests.RequestException as exc:
        raise RuntimeError(f'Failed to send logs to Loki: {exc}') from exc

    return valid_count
