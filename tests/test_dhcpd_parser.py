from parsers import dhcpd_parser


def test_parse_dhcpdiscover():
    log = '<134>1 2024-05-28T16:39:59+02:00 fw dhcpd 1 - [meta sequenceId="1"] DHCPDISCOVER from aa:bb:cc:dd:ee:ff via em0'
    out = dhcpd_parser.parse(log)
    assert out["type"] == "dhcpdiscover"
    assert out["service"] == "dhcp"


def test_parse_dhcpoffer():
    log = '<134>1 2024-05-28T16:39:59+02:00 fw dhcpd 1 - [meta sequenceId="1"] DHCPOFFER on 10.0.0.10 to aa:bb:cc:dd:ee:ff via em0'
    out = dhcpd_parser.parse(log)
    assert out["type"] == "dhcpoffer"
    assert out["ip"] == "10.0.0.10"


def test_parse_dhcrequest():
    log = '<134>1 2024-05-28T16:39:59+02:00 fw dhcpd 1 - [meta sequenceId="1"] DHCPREQUEST for 10.0.0.10 from aa:bb:cc:dd:ee:ff via em0'
    out = dhcpd_parser.parse(log)
    assert out["type"] == "dhcprequest"


def test_parse_dhcpack():
    log = '<134>1 2024-05-28T16:39:59+02:00 fw dhcpd 1 - [meta sequenceId="1"] DHCPACK on 10.0.0.10 to aa:bb:cc:dd:ee:ff via em0'
    out = dhcpd_parser.parse(log)
    assert out["type"] == "dhcpack"


def test_parse_dhcpack_to_variant():
    log = '<190>1 2026-03-16T03:29:00+01:00 fw dhcpd 34015 - [meta sequenceId="1"] DHCPACK to 192.168.4.205 (78:2b:46:7b:f2:9b) via vtnet3'
    out = dhcpd_parser.parse(log)
    assert out["type"] == "dhcpack"
    assert out["ip"] == "192.168.4.205"
    assert out["mac"] == "78:2b:46:7b:f2:9b"


def test_parse_dhcprelease():
    log = '<134>1 2024-05-28T16:39:59+02:00 fw dhcpd 1 - [meta sequenceId="1"] DHCPRELEASE of 10.0.0.10 from aa:bb:cc:dd:ee:ff via em0 (found)'
    out = dhcpd_parser.parse(log)
    assert out["type"] == "dhcprelease"


def test_parse_dhcpinform():
    log = '<134>1 2024-05-28T16:39:59+02:00 fw dhcpd 1 - [meta sequenceId="1"] DHCPINFORM from 10.0.0.10 via em0'
    out = dhcpd_parser.parse(log)
    assert out["type"] == "dhcpinform"


def test_parse_duplicate_uid():
    log = '<134>1 2024-05-28T16:39:59+02:00 fw dhcpd 1 - [meta sequenceId="1"] uid lease 10.0.0.10 for client aa:bb:cc:dd:ee:ff is duplicate on 10.0.0.0/24'
    out = dhcpd_parser.parse(log)
    assert out["type"] == "duplicate_uid_lease"


def test_parse_reuse():
    log = '<134>1 2024-05-28T16:39:59+02:00 fw dhcpd 1 - [meta sequenceId="1"] reuse_lease: lease age 42 (secs) under 25% threshold, reply with unaltered, existing lease for 10.0.0.10'
    out = dhcpd_parser.parse(log)
    assert out["type"] == "reuse_lease"
    assert out["age"] == "42"


def test_parse_generic():
    log = '<134>1 2024-05-28T16:39:59+02:00 fw dhcpd 1 - [meta sequenceId="1"] some generic message'
    out = dhcpd_parser.parse(log)
    assert out["service"] == "dhcp"
    assert out["message"] == "some generic message"
