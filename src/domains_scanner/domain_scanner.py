from utils.context_logger import ContextLoggerAdapter
from domains_scanner.http_checker import HttpChecker
from domains_scanner.certificate_checker import CertificateChecker
from domains_scanner.rtt_checker import RttChecker
from domains_scanner.dns_checker import DnsChecker
from domains_scanner.domain_utils import get_ip_addresses
from domains_scanner.geo_ip_checker import GeoIpChecker
import time

class DomainScanner:
    def __init__(self, logger: ContextLoggerAdapter):
        self.logger=logger

    def get_domain_security_stats(self, domain_name: str):
        http_checker = HttpChecker(logger= self.logger, timeout_for_requests=2)
        rtt_checker = RttChecker(logger=self.logger)
        dns_checker = DnsChecker(logger=self.logger, dns_resolver_address='1.1.1.1')
        certificate_checker = CertificateChecker(logger=self.logger)
        geo_ip_checker = GeoIpChecker(logger=self.logger)
        return {
            "scan_time": int(time.time()),
            "ipv4_addresses": get_ip_addresses(domain_name, "ipv4", self.logger),
            "ivp6_addresses": get_ip_addresses(domain_name, "ipv6", self.logger),
            "http_server": http_checker.http_server(domain_name),
            "insecure_http": http_checker.listens_for_insecure_connections(domain_name),
            "redirect_to_https": http_checker.insecure_connection_redirects_to_secure(domain_name),
            "rtt_range": rtt_checker.rtt_range(domain_name),
            "root_ca_name": certificate_checker.get_root_ca(domain_name),
            "rdns": dns_checker.reverse_dns(domain_name),
            "geolocation_of_ips": geo_ip_checker.get_geolocation_of_ips(domain_name),
            "domain_enforces_strict_transport": http_checker.domain_enforces_strict_transport(domain_name),
        }



