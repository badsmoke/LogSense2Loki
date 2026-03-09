from parsers import audit_parser, filterlog_parser, kernel_parser, rule_updater_parser, syslogng_parser, unbound_parser


def test_unbound_standard_info_error():
    std = '<134>1 2024-05-28T16:39:59+02:00 fw unbound 123 - [meta sequenceId="1"] [1234:abcd] query: 1.2.3.4 example.com A IN'
    info = '<134>1 2024-05-28T16:39:59+02:00 fw unbound 123 - [meta sequenceId="1"] [1234:abcd] info: worker started'
    err = '<134>1 2024-05-28T16:39:59+02:00 fw unbound 123 - [meta sequenceId="1"] [1234:abcd] error: read (in tcp s): timeout for 1.2.3.4 port 53'
    assert unbound_parser.parse(std)["record_type"] == "A"
    assert unbound_parser.parse(info)["log_type"] == "info"
    assert unbound_parser.parse(err)["log_type"] == "error"


def test_unbound_debug_drop_signature():
    drop = '<31>1 2026-03-09T18:18:39+01:00 fw unbound 1 - [meta sequenceId="1"] [1:a] debug: worker request: max UDP reply size modified (1472 to max-udp-size)'
    keep = '<31>1 2026-03-09T18:18:39+01:00 fw unbound 1 - [meta sequenceId="1"] [1:a] debug: configured stub or forward servers failed -- returning SERVFAIL'
    assert unbound_parser.parse(drop) == {"_drop": True}
    assert unbound_parser.parse(keep)["log_type"] == "debug"


def test_unbound_dhcpd_expired():
    log = '<165>1 2026-03-09T18:53:06+01:00 fw unbound 1 - [meta sequenceId="1"] dhcpd expired Pixel-8a-von-Melli @ 192.168.4.241'
    out = unbound_parser.parse(log)
    assert out["log_type"] == "dhcpd_expired"
    assert out["ip"] == "192.168.4.241"


def test_filterlog_parser_ports_and_length():
    log = '<134>1 2024-05-28T16:39:59+02:00 fw filterlog 1 - [meta sequenceId="1"] 201,,,0a40f86c186bf24db3d173b50ef28a54,vtnet2_vlan99,match,pass,in,4,0x0,,64,35287,0,DF,17,udp,69,10.0.99.244,10.0.99.1,45730,53,49'
    out = filterlog_parser.parse(log)
    assert out["service"] == "filterlog"
    assert out["src_port"] == "45730"
    assert out["dst_port"] == "53"
    assert out["length"] == "49"


def test_filterlog_parser_datalength_variant():
    log = '<134>1 2024-05-28T16:39:59+02:00 fw filterlog 1 - [meta sequenceId="1"] 201,,,0a40f86c186bf24db3d173b50ef28a54,vtnet2_vlan99,match,pass,in,4,0x0,,64,35287,0,DF,17,udp,69,10.0.99.244,10.0.99.1,49,datalength=20'
    out = filterlog_parser.parse(log)
    assert out["datalength"] == "20"


def test_audit_login_change_and_generic():
    login = "<134>1 2024-05-28T16:39:59+02:00 fw audit 1 - [meta sequenceId=\"1\"] Successful login for user 'admin' from: 10.0.0.5"
    change = '<134>1 2024-05-28T16:39:59+02:00 fw audit 1 - [meta sequenceId="1"] user admin@10.0.0.5 changed configuration to /tmp/config.xml in /api/core/system'
    generic = '<134>1 2024-05-28T16:39:59+02:00 fw audit 1 - [meta sequenceId="1"] unrelated event'

    out_login = audit_parser.parse(login)
    out_change = audit_parser.parse(change)
    out_generic = audit_parser.parse(generic)

    assert out_login["log_type"] == "login"
    assert out_login["status"] == "successful"
    assert out_change["log_type"] == "change"
    assert out_change["user"] == "admin@10.0.0.5"
    assert out_generic["log_type"] == "generic"


def test_kernel_arp_and_parse_arp_message():
    log = '<134>1 2024-05-28T16:39:59+02:00 fw kernel - - [meta sequenceId="1"] arp: 10.0.0.2 moved from aa:bb:cc:dd:ee:ff to 11:22:33:44:55:66 on em0'
    out = kernel_parser.parse(log)
    assert out["log_type"] == "arp"
    assert out["ip"] == "10.0.0.2"
    assert kernel_parser.parse_arp_message('x') == {}


def test_rule_updater_categorization_and_parse():
    assert rule_updater_parser.categorize_message('download completed now') == 'download completed'
    assert rule_updater_parser.categorize_message('download skipped due to cache') == 'download skipped'
    assert rule_updater_parser.categorize_message('version response ok') == 'version response'
    assert rule_updater_parser.categorize_message('other') == 'general'

    log = '<134>1 2024-05-28T16:39:59+02:00 fw rule-updater.py 1 - [meta sequenceId="1"] download completed now'
    out = rule_updater_parser.parse_rule_updater(log)
    assert out["service"] == "rule-updater"
    assert out["category"] == "download completed"


def test_syslogng_statistics_error_and_generic():
    stat = "<134>1 2024-05-28T16:39:59+02:00 fw syslog-ng 1 - [meta sequenceId=\"1\"] Log statistics; processed='src.program(abc)=10' eps_last_1h='src.program(abc)=11'"
    err = "<134>1 2024-05-28T16:39:59+02:00 fw syslog-ng 1 - [meta sequenceId=\"1\"] error sending to server='x(1.2.3.4:514)'"
    gen = '<134>1 2024-05-28T16:39:59+02:00 fw syslog-ng 1 - [meta sequenceId="1"] normal message'

    out_stat = syslogng_parser.parse(stat)
    out_err = syslogng_parser.parse(err)
    out_gen = syslogng_parser.parse(gen)

    assert out_stat["log_type"] == "statistics"
    assert out_stat["processed"] == "10"
    assert out_err["log_type"] == "error"
    assert out_err["ip"] == "1.2.3.4"
    assert out_gen["log_type"] == "generic"
