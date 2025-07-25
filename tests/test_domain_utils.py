import pytest
from domains_scanner.domain_utils import get_ip_addresses
from tests.utils import DummyLogger
import ipaddress

def test_get_ip_addresses_erroneous_domain():
    logger = DummyLogger()
    ips = get_ip_addresses("?", "ipv4", logger)
    assert ips is None
    assert "No ipv4 can be found for ?" in logger.warning_messages[0]

def test_get_ip_addresses_erroneous_address_format():
    logger = DummyLogger()
    ips = get_ip_addresses("?", "ipv5", logger)
    assert ips is None
    assert "get_ip_addresses is called with an incorrect address format" in logger.error_messages[0]

def test_get_ip_addresses_success_ipv4():
    logger = DummyLogger()
    ips = get_ip_addresses("google.com", "ipv4", logger)
    assert ips is not None
    assert len(ips)>0
    assert len(logger.error_messages)==0
    assert len(logger.warning_messages)==0
    #check ip addresses are valid ipv4 addresses
    for ip in ips:
        assert ipaddress.ip_address(ip).version == 4


def test_get_ip_addresses_success_ipv6():
    logger = DummyLogger()
    ips = get_ip_addresses("google.com", "ipv6", logger)
    assert ips is not None
    assert len(ips)>0
    assert len(logger.error_messages)==0
    assert len(logger.warning_messages)==0
    #check ip addresses are valid ipv6 addresses
    for ip in ips:
        assert ipaddress.ip_address(ip).version == 6

#Can we check that all the ip addresses are unique?


#Can we check that IP addresses are actually valid?
