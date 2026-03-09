import json

import loki_client
from geoip_helper import GeoIPHelper
from syslog_server import SyslogServer


class DummyResp:
    def __init__(self, status_code=204, content=b"ok"):
        self.status_code = status_code
        self.content = content
        self.text = content.decode("utf-8", errors="ignore")


class DummyCityResponse:
    class _City:
        name = "München"

    class _Country:
        name = "Deutschland"
        iso_code = "DE"

    class _Location:
        latitude = 48.137
        longitude = 11.575

    class _Traits:
        organization = "Example Org"

    city = _City()
    country = _Country()
    location = _Location()
    traits = _Traits()


def test_loki_send_to_loki(monkeypatch):
    called = {}

    def fake_post(url, headers=None, data=None, auth=None, verify=True, timeout=None):
        called["url"] = url
        called["headers"] = headers
        called["payload"] = json.loads(data)
        called["auth"] = auth
        called["verify"] = verify
        called["timeout"] = timeout
        return DummyResp(204)

    monkeypatch.setenv("LOKI_URL", "https://logs.example/push")
    monkeypatch.setenv("JOB_LABEL", "testjob")
    monkeypatch.setattr(loki_client.session, "post", fake_post)

    logs = [{"service": "api", "hostname": "fw", "message": "ok"}]
    loki_client.send_to_loki(logs)

    assert called["url"] == "https://logs.example/push"
    stream = called["payload"]["streams"][0]
    assert 'job="testjob"' in stream["labels"]
    assert 'service="api"' in stream["labels"]


def test_geoip_helper_get_city(monkeypatch):
    helper = GeoIPHelper.__new__(GeoIPHelper)

    class Reader:
        def city(self, ip_address):
            assert ip_address == "8.8.8.8"
            return DummyCityResponse()

    helper.reader = Reader()

    out = helper.get_city("8.8.8.8")
    assert out["country_code"] == "DE"
    assert out["city"] == "Munchen"
    assert out["organization"] == "Example Org"


def test_geoip_helper_get_city_without_coordinates():
    helper = GeoIPHelper.__new__(GeoIPHelper)

    class Resp:
        class _City:
            name = "City"

        class _Country:
            name = "Country"
            iso_code = "CC"

        class _Location:
            latitude = None
            longitude = None

        class _Traits:
            organization = "Org"

        city = _City()
        country = _Country()
        location = _Location()
        traits = _Traits()

    class Reader:
        def city(self, _ip):
            return Resp()

    helper.reader = Reader()
    out = helper.get_city("1.2.3.4")
    assert out["latitude"] is None
    assert out["longitude"] is None
    assert out["geohash"] is None


def test_syslog_server_process_log_and_geoip(monkeypatch):
    server = SyslogServer("127.0.0.1", 0, False, "", 10, 1, 10)

    from parsers import api_parser

    monkeypatch.setattr(api_parser, "parse", lambda _: {"service": "api", "hostname": "fw"})

    out = server.process_log("<134>1 2024-05-28T16:39:59+02:00 fw api 1 - [meta sequenceId=\"1\"] x")
    assert out["service"] == "api"
    assert server.is_public_ip("8.8.8.8") is True
    assert server.is_public_ip("10.0.0.1") is False
    assert server.is_public_ip("not_an_ip") is False


def test_syslog_server_process_logs_batch(monkeypatch):
    server = SyslogServer("127.0.0.1", 0, False, "", 10, 1, 10)
    sent = {}

    monkeypatch.setattr(server, "process_log", lambda msg: {"service": "api", "hostname": "fw", "message": msg})

    def fake_send(logs):
        sent["logs"] = logs
        return len(logs)

    monkeypatch.setattr("loki_client.send_to_loki", fake_send)

    server.process_logs_batch(["a", "b"])
    assert len(sent["logs"]) == 2
