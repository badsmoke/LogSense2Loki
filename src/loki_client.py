import requests
import json
import config
import os
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Global session to maintain keep-alive connections
session = requests.Session()

# Setup retry strategy
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
)

adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=10, pool_block=True)
session.mount("http://", adapter)
session.mount("https://", adapter)

# Keep-Alive header
session.headers.update({
    "Connection": "keep-alive"
})

def send_to_loki(logs):
    headers = {'Content-Type': 'application/json'}
    job_label = os.getenv('JOB_LABEL', config.JOB_LABEL)
    loki_entries = []

    for log in logs:
        # Safety check to ensure log is a dictionary
        if not isinstance(log, dict):
            print(f"Invalid log format, expected dictionary but got {type(log)}")
            continue  # Skip invalid logs
        
        loki_entry = {
            "labels": '{job="%s",service="%s", hostname="%s"}' % (job_label,log["service"],log["hostname"]),
            "entries": [
                {
                    "ts": datetime.utcnow().isoformat("T") + "Z",
                    "line": json.dumps(log)
                }
            ]
        }
        loki_entries.append(loki_entry)

    data = json.dumps({"streams": loki_entries})
    loki_url = os.getenv('LOKI_URL', config.LOKI_URL)

    response = session.post(loki_url, headers=headers, data=data)
    
    if response.status_code != 204:
        print(response.status_code)
        print(f"Failed to send log to Loki: {response.content}")
    #else:
    #    print("Successfully sent logs to Loki")