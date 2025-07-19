from domains_scanner.domain_utils import get_ip_addresses
from utils.context_logger import ContextLoggerAdapter
import ipaddress
import dns.resolver
import dns.rdatatype

class DnsChecker:
    def __init__(self, logger:ContextLoggerAdapter, dns_resolver_address:str):
        self.logger=logger
        self.dns_resolver_address = dns_resolver_address
    def reverse_dns(self, domain_name):
        func_logger = self.logger.get_child("reverse_dns", {'domain_name': domain_name})
        ivp4_addresses = get_ip_addresses(domain_name, "ipv4", func_logger)
        for ivp4_address in ivp4_addresses:
            try:
                responses = dns.resolver.resolve_at(self.dns_resolver_address,
                                                    ipaddress.ip_address(ivp4_address).reverse_pointer,
                                                    dns.rdatatype.PTR)
                return list(map(lambda response: response.target.to_unicode(), responses))
            except Exception as e:
                func_logger.error(
                    "While finding reverse dns entries for " + domain_name + " ip:" + ivp4_address + ", the following error was hit:" + str(
                        e))
                return None
