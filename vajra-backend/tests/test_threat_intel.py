import pytest
from app.services.threat_intel import is_tor_exit_node, is_datacenter_asn


def test_tor_exit_node_detection():
    # 185.220.101.5 is in data/tor_exit_nodes.txt
    assert is_tor_exit_node("185.220.101.5") is True
    # 8.8.8.8 is Google DNS, not a Tor exit node
    assert is_tor_exit_node("8.8.8.8") is False


def test_datacenter_asn_detection():
    # Check by organization string
    assert is_datacenter_asn("Amazon.com, Inc.") is True
    assert is_datacenter_asn("Hetzner Online GmbH") is True
    assert is_datacenter_asn("DigitalOcean, LLC") is True
    assert is_datacenter_asn("OVH SAS") is True
    assert is_datacenter_asn("Google Cloud Platform") is True
    assert is_datacenter_asn("Microsoft Azure") is True

    # Check residential / ISP
    assert is_datacenter_asn("Bharti Airtel Ltd.") is False
    assert is_datacenter_asn("Comcast Cable Communications, LLC") is False

    # Check by ASN number
    assert is_datacenter_asn("Unknown Entity", asn_number=16509) is True
