from domains_scanner.domain_utils import get_ip_addresses
from utils.context_logger import ContextLoggerAdapter
import ipaddress
import dns.resolver
import dns.rdatatype

class DnsChecker:
    def __init__(self, logger:ContextLoggerAdapter, dns_resolver_address:str):
        self.logger=logger
        self.dns_resolver_address = dns_resolver_address
    
    #private method
    def __reverse_dns_per_address(self, func_logger, address, domain_name):
            try:
                responses = dns.resolver.resolve_at(self.dns_resolver_address,
                                                    ipaddress.ip_address(address).reverse_pointer,
                                                    dns.rdatatype.PTR)
                return list(map(lambda response: response.target.to_unicode(), responses))
            except Exception as e:
                func_logger.warning(
                    "While finding reverse dns entries for " + domain_name + " ip:" + address + ", the following error was hit:" + str(
                        e))
                return []
    def reverse_dns(self, domain_name):
        func_logger = self.logger.get_child("reverse_dns", {'domain_name': domain_name})
        ivp4_addresses = get_ip_addresses(domain_name, "ipv4", func_logger)
        ipv6_addresses = get_ip_addresses(domain_name, "ipv6", func_logger)
        reverse_dns_entries = []
        for ivp4_address in ivp4_addresses:
            ptr_records_for_ip = self.__reverse_dns_per_address(func_logger, ivp4_address, domain_name)
            if len(ptr_records_for_ip) == 0:
                func_logger.warning("No reverse dns entries found for " + domain_name + " IP: " + ivp4_address)
            else:
                reverse_dns_entries.extend(ptr_records_for_ip)
        for ipv6_address in ipv6_addresses:
            ptr_records_for_ip = self.__reverse_dns_per_address(func_logger, ipv6_address, domain_name)
            if len(ptr_records_for_ip) == 0:
                func_logger.warning("No reverse dns entries found for " + domain_name + " IP: " + ipv6_address)
            else:
                reverse_dns_entries.extend(ptr_records_for_ip)
        if len(ivp4_addresses) == 0 and len(ipv6_addresses) == 0:
            func_logger.error("No ipv4 or ipv6 addresses found for " + domain_name)
            return reverse_dns_entries
        if len(reverse_dns_entries) == 0:
            func_logger.warning("No reverse dns entries found for " + domain_name)
        return reverse_dns_entries
