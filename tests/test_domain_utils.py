import pytest
from unittest.mock import patch
from domains_scanner.domain_utils import get_ip_addresses
from tests.utils import DummyLogger
import ipaddress
import socket


def test_get_ip_addresses_erroneous_address_format():
    logger = DummyLogger()
    ips = get_ip_addresses("?", "ipv5", logger)
    assert ips is None
    assert "get_ip_addresses is called with an incorrect address format" in logger.error_messages[0]

def test_get_ip_addresses_ipv4():
    logger = DummyLogger()
    with patch('socket.getaddrinfo') as mock_getaddrinfo:
        # Mock return value for getaddrinfo with IPv4
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, None, None, None, ('142.250.190.78', 0)),
            (socket.AF_INET, None, None, None, ('142.250.190.79', 0))
        ]
        
        ips = get_ip_addresses("example.com", "ipv4", logger)
        
        # Verify the function was called with expected arguments
        mock_getaddrinfo.assert_called()
        assert len(ips) == 2  # Should return unique IPs
        assert "142.250.190.78" in ips
        assert "142.250.190.79" in ips
        assert len(logger.error_messages) == 0
        assert len(logger.warning_messages) == 0
        # Verify IPs are valid IPv4
        for ip in ips:
            assert ipaddress.ip_address(ip).version == 4


def test_get_ip_addresses_ipv6():
    logger = DummyLogger()
    with patch('socket.getaddrinfo') as mock_getaddrinfo:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET6, None, None, None, ('2607:f8b0:4005:804::200e', 0, 0, 0)),
            (socket.AF_INET6, None, None, None, ('2607:f8b0:4005:804::200f', 0, 0, 0))
        ]
        
        ips = get_ip_addresses("example.com", "ipv6", logger)
        
        mock_getaddrinfo.assert_called()
        assert len(ips) == 2  # Should return unique IPs
        assert "2607:f8b0:4005:804::200e" in ips
        assert "2607:f8b0:4005:804::200f" in ips
        assert len(logger.error_messages) == 0
        assert len(logger.warning_messages) == 0
        # Verify IPs are valid IPv6
        for ip in ips:
            assert ipaddress.ip_address(ip).version == 6


def test_get_ip_addresses_no_ips_found():
    logger = DummyLogger()
    with patch('socket.getaddrinfo') as mock_getaddrinfo:
        # Simulate no IPs found (raises socket.gaierror)
        mock_getaddrinfo.side_effect = socket.gaierror("Name or service not known")
        
        ips = get_ip_addresses("nonexistent.example.com", "ipv4", logger)
        
        assert ips is None
        assert "No ipv4 can be found for nonexistent.example.com" in logger.warning_messages[0]
