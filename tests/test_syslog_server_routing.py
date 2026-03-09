from syslog_server import SyslogServer


def test_process_log_filterlog_route(monkeypatch):
    server = SyslogServer("127.0.0.1", 0, False, "", 10, 1, 1)

    from parsers import filterlog_parser

    monkeypatch.setattr(filterlog_parser, "parse", lambda _: {"service": "filterlog", "hostname": "fw", "src_ip": "1.2.3.4"})

    out = server.process_log("x filterlog y")
    assert out["service"] == "filterlog"


def test_process_log_no_parser():
    server = SyslogServer("127.0.0.1", 0, False, "", 10, 1, 1)
    assert server.process_log("unknown log") is None


def test_process_log_debug_is_silently_dropped():
    server = SyslogServer("127.0.0.1", 0, False, "", 10, 1, 1)
    failed_before = server.FAILED_LOGS._value.get()
    assert server.process_log("some service debug: verbose detail") is None
    assert server.FAILED_LOGS._value.get() == failed_before
