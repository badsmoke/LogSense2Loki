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
    dropped_before = server.DROPPED_DEBUG_LOGS._value.get()
    assert server.process_log("some service debug: verbose detail") is None
    assert server.FAILED_LOGS._value.get() == failed_before
    assert server.DROPPED_DEBUG_LOGS._value.get() == dropped_before + 1


def test_unparsed_unique_metric_increments_once_per_signature():
    server = SyslogServer("127.0.0.1", 0, False, "", 10, 1, 1)
    before = server.UNPARSED_UNIQUE_LOGS._value.get()

    assert server.process_log("unknown log 123") is None
    assert server.process_log("unknown log 456") is None

    assert server.UNPARSED_UNIQUE_LOGS._value.get() == before + 1


def test_queue_full_metric_increments_on_drop():
    server = SyslogServer("127.0.0.1", 0, False, "", 1, 1, 1)
    before = server.DROPPED_QUEUE_FULL_LOGS._value.get()
    received_before = server.RECEIVED_LOGS._value.get()
    failed_before = server.FAILED_LOGS._value.get()

    class FakeSocket:
        def __init__(self):
            self.calls = 0

        def recvfrom(self, _size):
            self.calls += 1
            if self.calls == 1:
                return b"second\n", ("127.0.0.1", 12345)
            raise RuntimeError("stop loop")

        def close(self):
            return None

    server.queue.put_nowait("first")
    server.sock = FakeSocket()
    server.run()

    assert server.RECEIVED_LOGS._value.get() == received_before + 1
    assert server.FAILED_LOGS._value.get() == failed_before + 1
    assert server.DROPPED_QUEUE_FULL_LOGS._value.get() == before + 1
