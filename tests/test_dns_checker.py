import pytest
from tests.utils import DummyLogger
from domains_scanner.dns_checker import DnsChecker
from unittest.mock import patch, MagicMock
import ipaddress

def test_dns_checker_reverse_dns_no_ptr_records():
    logger = DummyLogger()
    dns_checker = DnsChecker(logger, '1.1.1.1')

    with patch('domains_scanner.dns_checker.get_ip_addresses') as mock_get_ip_addresses:
        domain_name_to_ip_addresses = {
            'example.com': {'ipv4': ['127.0.0.1', '127.0.0.2'], 'ipv6': ['::1']},
        }
        # Mock get_ip_addresses to return different results for IPv4 and IPv6
        def mock_get_ip_side_effect(domain, ip_type, logger):
            if domain not in domain_name_to_ip_addresses or ip_type != "ipv4" and ip_type != "ipv6":
                return []
            else:
                return domain_name_to_ip_addresses[domain][ip_type]
        
        mock_get_ip_addresses.side_effect = mock_get_ip_side_effect
        with patch('dns.resolver.resolve_at') as mock_resolve_at:
            mock_resolve_at.return_value = []
            assert dns_checker.reverse_dns('example.com') == []
            assert len(logger.error_messages) == 0
            assert len(logger.warning_messages) == 4
            assert tuple(["No reverse dns entries found for example.com"]) in logger.warning_messages
            assert tuple(["No reverse dns entries found for example.com IP: 127.0.0.1"]) in logger.warning_messages
            assert tuple(["No reverse dns entries found for example.com IP: 127.0.0.2"]) in logger.warning_messages
            assert tuple(["No reverse dns entries found for example.com IP: ::1"]) in logger.warning_messages    

def test_dns_checker_reverse_dns_no_ip_addresses():
    logger = DummyLogger()
    dns_checker = DnsChecker(logger, '1.1.1.1')
    with patch('domains_scanner.dns_checker.get_ip_addresses') as mock_get_ip_addresses:
        mock_get_ip_addresses.return_value = []
        assert dns_checker.reverse_dns('example.com') == []
        assert len(logger.error_messages) == 1
        assert "No ipv4 or ipv6 addresses found for example.com" in logger.error_messages[0]
        assert len(logger.warning_messages) == 0 
   
def test_dns_checker_reverse_dns():
    logger = DummyLogger()
    dns_checker = DnsChecker(logger, '1.1.1.1')
    
    with patch('domains_scanner.dns_checker.get_ip_addresses') as mock_get_ip_addresses, \
         patch('dns.resolver.resolve_at') as mock_resolve_at:
        
        ip_addresses_to_ptr_records = {
            '127.0.0.1': MagicMock(target=MagicMock(to_unicode=MagicMock(return_value='example1_host1.example.com'))),
            '127.0.0.2': MagicMock(target=MagicMock(to_unicode=MagicMock(return_value='example1_host2.example.com'))),
            '::1': MagicMock(target=MagicMock(to_unicode=MagicMock(return_value='example1_ipv6host.example.com'))),
            '127.0.0.3': MagicMock(target=MagicMock(to_unicode=MagicMock(return_value='example2_host1.example.com'))),
            '::2': MagicMock(target=MagicMock(to_unicode=MagicMock(return_value='example2_ipv6host.example.com')))
        }

        def mock_resolve_side_effect(resolver_addr, reverse_pointer, record_type):
            reverse_ptr_str = str(reverse_pointer)
            for ip_address, ptr_record in ip_addresses_to_ptr_records.items():
                if str(ipaddress.ip_address(ip_address).reverse_pointer) == reverse_ptr_str:
                    return [ptr_record]
            return []
            
        
        mock_resolve_at.side_effect = mock_resolve_side_effect

        domain_name_to_ip_addresses = {
            'example.com': {'ipv4': ['127.0.0.1', '127.0.0.2'], 'ipv6': ['::1']},
            'example2.com': {'ipv4': ['127.0.0.3', '127.0.0.4'], 'ipv6': ['::2']}
        }
        # Mock get_ip_addresses to return different results for IPv4 and IPv6
        def mock_get_ip_side_effect(domain, ip_type, logger):
            if domain not in domain_name_to_ip_addresses or ip_type != "ipv4" and ip_type != "ipv6":
                return []
            else:
                return domain_name_to_ip_addresses[domain][ip_type]
        
        mock_get_ip_addresses.side_effect = mock_get_ip_side_effect
        
        result = dns_checker.reverse_dns('example.com')
        
        assert result == ['example1_host1.example.com', 'example1_host2.example.com', 'example1_ipv6host.example.com']
        assert len(logger.error_messages) == 0
        assert len(logger.warning_messages) == 0
        
        result = dns_checker.reverse_dns('example2.com')
        assert result == ['example2_host1.example.com', 'example2_ipv6host.example.com']
        assert len(logger.error_messages) == 0
        assert len(logger.warning_messages) == 1
        assert "No reverse dns entries found for example2.com IP: 127.0.0.4" in logger.warning_messages[0]

        
    
