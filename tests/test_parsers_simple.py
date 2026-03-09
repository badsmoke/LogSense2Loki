from parsers import (
    api_parser,
    config_parser,
    configctl_parser,
    configd_parser,
    cron_parser,
    devd_parser,
    dhclient_parser,
    dpinger_parser,
    opnsense_parser,
)


def test_api_parser():
    log = '<134>1 2024-05-28T16:39:59+02:00 fw api 123 - [meta sequenceId="1"] endpoint called'
    out = api_parser.parse(log)
    assert out["service"] == "api"
    assert out["message"] == "endpoint called"


def test_config_parser():
    log = '<134>1 2024-05-28T16:39:59+02:00 fw config 123 - [meta sequenceId="1"] config-event: changed setting'
    out = config_parser.parse(log)
    assert out["service"] == "config"
    assert out["message"] == "changed setting"


def test_configctl_parser():
    log = '<134>1 2024-05-28T16:39:59+02:00 fw configctl 123 - [meta sequenceId="1"] reconfigure done'
    out = configctl_parser.parse(log)
    assert out["service"] == "configctl"


def test_configd_parser_with_uuid():
    log = '<134>1 2024-05-28T16:39:59+02:00 fw configd.py 123 - [meta sequenceId="1"] [123e4567-e89b-12d3-a456-426614174000] apply template'
    out = configd_parser.parse(log)
    assert out["service"] == "configd"
    assert out["uuid"] == "123e4567-e89b-12d3-a456-426614174000"


def test_configd_parser_without_uuid():
    log = '<134>1 2024-05-28T16:39:59+02:00 fw configd.py 123 - [meta sequenceId="1"] apply template'
    out = configd_parser.parse(log)
    assert out["service"] == "configd"
    assert "uuid" not in out


def test_cron_parser():
    log = '<134>1 2024-05-28T16:39:59+02:00 fw /usr/sbin/cron 123 - [meta sequenceId="1"] (root) CMD (php /usr/local/opnsense/scripts/cron.php)'
    out = cron_parser.parse(log)
    assert out["service"] == "cron"
    assert out["user"] == "root"


def test_devd_parser():
    log = '<134>1 2024-05-28T16:39:59+02:00 fw devd 123 - [meta sequenceId="1"] link up'
    out = devd_parser.parse(log)
    assert out["service"] == "devd"


def test_dhclient_parser():
    log = '<134>1 2024-05-28T16:39:59+02:00 fw dhclient 123 - [meta sequenceId="1"] bound to 10.0.0.2'
    out = dhclient_parser.parse(log)
    assert out["service"] == "dhclient"


def test_dpinger_parser():
    log = '<134>1 2024-05-28T16:39:59+02:00 fw dpinger 123 - ALERT: WAN_DHCP (Addr: 8.8.8.8 Alarm: 0 -> 1 RTT: 12.3 ms RTTd: 1.1 ms Loss: 0.0 %)'
    out = dpinger_parser.parse(log)
    assert out["service"] == "dpinger"
    assert out["interface"] == "WAN_DHCP"


def test_opnsense_parser():
    log = '<134>1 2024-05-28T16:39:59+02:00 fw opnsense 123 - [meta sequenceId="1"] system started'
    out = opnsense_parser.parse(log)
    assert out["service"] == "opnsense"


def test_parser_returns_none_for_invalid_log():
    assert api_parser.parse('invalid') is None
