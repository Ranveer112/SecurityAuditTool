from utils.context_logger import ContextLoggerAdapter
from domains_scanner.domain_utils import get_ip_addresses
import time
import math
import socket

class RttChecker:
    def __init__(self, logger:ContextLoggerAdapter):
        self.logger = logger
    def rtt_range(self, domain_name):
        # for each of ivp4 addresses, create a socket.socket
        func_logger = self.logger.get_child("rtt_range", {'domain_name': domain_name})
        ipv4_addresses = get_ip_addresses(domain_name, "ipv4", func_logger)
        ipv6_addresses = get_ip_addresses(domain_name, "ipv6", func_logger)
        ip_addresses = (ipv4_addresses if ipv4_addresses is not None else []) + (
            ipv6_addresses if ipv6_addresses is not None else [])
        mn = math.inf
        mx = -math.inf
        if len(ip_addresses) > 0:
            for ip_address in ip_addresses:
                socket_family = socket.AF_INET if ip_address in ipv4_addresses else socket.AF_INET6
                sock = socket.socket(socket_family, socket.SOCK_STREAM)
                # Try an HTTPS port, then a HTTP port, and then a FTP port
                for port in (443, 80, 20):
                    try:
                        before = time.time()
                        sock.connect((ip_address, port))
                        rtt = time.time() - before
                        mn = min(rtt, mn)
                        mx = max(rtt, mx)
                        sock.shutdown(socket.SHUT_RDWR)
                        sock.close()
                        break
                    except TimeoutError:
                        func_logger.warning(
                            "TCP connection request for rtt calculation timed out for " + domain_name + " on port:" + str(
                                port) + " " + "timed out.")
                        continue
                    except Exception as e:
                        func_logger.warning(
                            "TCP connection request for rtt calculation timed out for " + domain_name + "'s IP: " + ip_address + " on port:" + str(
                                port) + " " + "timed out.")
                        continue

            if mn == math.inf and mx == -math.inf:
                func_logger.error(
                    "RTT variance calculation failed as TCP connection from multiple ports " + domain_name + " timed out")
                return None
            else:
                return [mn, mx]
        else:
            func_logger.error(
                "RTT variance for " + domain_name + " cannot be calculated since no the IP resolution for domain name failed")
            return None