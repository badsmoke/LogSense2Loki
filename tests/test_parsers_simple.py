from parsers import (
    api_parser,
    config_parser,
    configctl_parser,
    configd_parser,
    cron_parser,
    devd_parser,
    dhclient_parser,
    dpinger_parser,
    firewall_parser,
    hostwatch_parser,
    opnsense_parser,
    qemu_ga_parser,
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
    log = '<134>1 2024-05-28T16:39:59+02:00 fw dpinger 123 - [meta sequenceId="1"] ALERT: WAN_DHCP (Addr: 8.8.8.8 Alarm: 0 -> 1 RTT: 12.3 ms RTTd: 1.1 ms Loss: 0.0 %)'
    out = dpinger_parser.parse(log)
    assert out["service"] == "dpinger"
    assert out["interface"] == "WAN_DHCP"


def test_opnsense_parser():
    log = '<134>1 2024-05-28T16:39:59+02:00 fw opnsense 123 - [meta sequenceId="1"] system started'
    out = opnsense_parser.parse(log)
    assert out["service"] == "opnsense"


def test_hostwatch_parser():
    log = '<13>1 2026-03-09T18:30:26+01:00 fw hostwatch 1 - [meta sequenceId="1"] 2026-03-09T17:30:26.189513Z INFO hostwatch: changed ethernet address host bc:24:11:36:66:62 moved from bc:24:11:d0:90:7e to 10.11.0.9 at vtnet2_vlan1100'
    out = hostwatch_parser.parse(log)
    assert out["service"] == "hostwatch"
    assert out["log_type"] == "changed_ethernet_address"
    assert out["ip"] == "10.11.0.9"


def test_hostwatch_parser_new_station():
    log = '<13>1 2026-03-16T07:25:21+01:00 fw hostwatch 53663 - [meta sequenceId="1"]   2026-03-16T06:25:21.763693Z  INFO hostwatch: new station host 38:ba:f8:d8:d9:2a using 192.168.178.130 at vtnet3'
    out = hostwatch_parser.parse(log)
    assert out["service"] == "hostwatch"
    assert out["log_type"] == "new_station"
    assert out["ip"] == "192.168.178.130"


def test_firewall_parser_dns_not_exists():
    log = '<163>1 2026-03-09T19:04:00+01:00 fw firewall 76807 - [meta sequenceId="1"] The DNS query name does not exist: hub.docker.io. [for allowed_default_hosts]'
    out = firewall_parser.parse(log)
    assert out["service"] == "firewall"
    assert out["log_type"] == "dns_query_name_not_exists"
    assert out["query"] == "hub.docker.io"
    assert out["alias"] == "allowed_default_hosts"


def test_firewall_parser_resolving():
    log = '<165>1 2026-03-09T19:04:00+01:00 fw firewall 76807 - [meta sequenceId="1"] resolving 17 hostnames (67 addresses) for allowed_default_hosts took 0.08 seconds'
    out = firewall_parser.parse(log)
    assert out["service"] == "firewall"
    assert out["log_type"] == "alias_resolving"
    assert out["hostnames"] == "17"


def test_firewall_parser_alias_fetch_and_errors():
    fetch = '<165>1 2026-03-16T02:29:00+01:00 fw firewall 81227 - [meta sequenceId="1"] fetch alias url https://ip-list.zigpos.com/allowed-ips-table.txt (lines: 31)'
    processing = '<165>1 2026-03-16T02:29:00+01:00 fw firewall 81227 - [meta sequenceId="1"] processing alias url https://ip-list.zigpos.com/allowed-ips-table.txt took 0.00s'
    err = '<163>1 2026-03-16T00:55:00+01:00 fw firewall 65115 - [meta sequenceId="1"] error fetching alias url https://talosintelligence.com/documents/ip-blacklist [http_code:404]'
    resolve_err = '<163>1 2026-03-16T00:55:00+01:00 fw firewall 65115 - [meta sequenceId="1"] alias resolve error blocked_ips_table_list (error fetching alias url https://talosintelligence.com/documents/ip-blacklist)'

    out_fetch = firewall_parser.parse(fetch)
    out_processing = firewall_parser.parse(processing)
    out_err = firewall_parser.parse(err)
    out_resolve_err = firewall_parser.parse(resolve_err)

    assert out_fetch["log_type"] == "alias_fetch"
    assert out_fetch["lines"] == "31"
    assert out_processing["log_type"] == "alias_processing"
    assert out_err["log_type"] == "alias_fetch_error"
    assert out_resolve_err["log_type"] == "alias_resolve_error"


def test_lighttpd_parser_http2_pri_request():
    from parsers import lighttpd_parser

    log = '<30>1 2026-03-16T11:18:16+01:00 fw lighttpd 51731 - [meta sequenceId="1"] 192.168.4.109 - - [16/Mar/2026:11:18:16 +0100] "PRI * HTTP/2.0" 100 - "-" "-"'
    out = lighttpd_parser.parse(log)
    assert out["service"] == "lighttpd"
    assert out["method"] == "PRI"
    assert out["path"] == "*"
    assert out["protocol"] == "HTTP/2.0"


def test_cron_parser_mail_log():
    log = '<78>1 2026-03-16T03:55:32+01:00 fw /usr/sbin/cron 95860 - [meta sequenceId="1"] (root) MAIL (mailed 328 bytes of output but got status 0x0001'
    out = cron_parser.parse(log)
    assert out["service"] == "cron"
    assert out["log_type"] == "mail"
    assert out["user"] == "root"


def test_qemu_ga_parser():
    log = '<14>1 2026-03-15T20:00:02+01:00 fw qemu-ga 50065 - [meta sequenceId="1"] info: guest-ping called'
    out = qemu_ga_parser.parse(log)
    assert out["service"] == "qemu-ga"
    assert out["log_type"] == "info"


def test_parser_returns_none_for_invalid_log():
    assert api_parser.parse('invalid') is None
