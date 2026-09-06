import pytest
from app.services.hops import parse_hops_bottom_up, is_public_ip, extract_ips_from_text


def test_rfc1918_and_loopback_filtering():
    """Verify private and loopback subnets are correctly discarded."""
    assert is_public_ip("127.0.0.1") is False
    assert is_public_ip("10.0.1.50") is False
    assert is_public_ip("172.16.5.10") is False
    assert is_public_ip("192.168.1.1") is False
    assert is_public_ip("169.254.1.1") is False  # Link-local
    assert is_public_ip("::1") is False          # IPv6 loopback

    # Globally routable public IPs
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("185.220.101.5") is True
    assert is_public_ip("51.15.43.205") is True


def test_bottom_up_traversal_order():
    """Received headers must be traversed bottom-to-top so the earliest origin MTA IP is identified."""
    received_headers = [
        # Top header: Added last by final recipient MTA
        "from mail-relay.internal.net (10.0.0.2) by mx.destination.com (10.0.0.1); Sat, 5 Sep 2026 20:00:00 +0000",
        # Middle header: Transit hop
        "from hop2.transit.net (104.244.72.115) by mail-relay.internal.net (10.0.0.2); Sat, 5 Sep 2026 19:59:55 +0000",
        # Bottom header: Earliest entry hop added first by origin MTA
        "from client.sender.org (194.26.29.112) by hop2.transit.net (104.244.72.115); Sat, 5 Sep 2026 19:59:50 +0000",
    ]

    hops, earliest_public_ip = parse_hops_bottom_up(received_headers)

    # The internal RFC 1918 hop (10.0.0.2) should be excluded
    # The earliest public IP must be from the bottom-most header: 194.26.29.112
    assert earliest_public_ip == "194.26.29.112"
    assert len(hops) == 2
    assert hops[0]["ip"] == "194.26.29.112"
    assert hops[0]["hop_number"] == 1
    assert hops[1]["ip"] == "104.244.72.115"
    assert hops[1]["hop_number"] == 2
