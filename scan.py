import argparse
import ipaddress
import shutil
import socket
import time
import dns.resolver
import dns.rdatatype
import geoip2.database
import maxminddb
import math
import requests
import texttable
from requests import RequestException, Response
import os
from OpenSSL import SSL
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import certifi
from certvalidator import CertificateValidator, ValidationContext
import logging
import uuid


HTTPS_PORT = 443
DEFAULT_LOGGING_FILE = "log.txt"
DEFAULT_LOGGING_LEVEL = logging.ERROR


class ContextLoggerAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        context_stringified = str({k: v() if callable(v) else v for k, v in self.extra.items()})
        return f"[" +context_stringified + "] {"+msg+"}", kwargs
    def get_child(self, suffix, additional_context):
        """Create child ContextLoggerAdapter with same context as parent but with additional context"""
        child_logger = logging.getLogger(f"{self.logger.name}.{suffix}")
        parent_logger_adapter_context = self.extra.copy()
        return ContextLoggerAdapter(child_logger, parent_logger_adapter_context|additional_context)


def get_ip_addresses(domain_name, address_format, logger) -> list[str]|None:
    """
    :param domain_name: The domain name for which the IP addresses need to be fetched.
    :param address_format: Specifies the IP address format to retrieve. Acceptable values are "ivp4" or "ivp6".
    :return: A list of IP addresses associated with the domain name, None in case of an error,
    """
    func_logger = logger.get_child("get_ip_addresses", {'domain_name': domain_name})
    if address_format == "ipv4" or address_format == "ipv6":
        socket_family = socket.AF_INET if address_format == "ipv4" else socket.AF_INET6
        for service in ('https', 'http'):
            try:
                address_infos = socket.getaddrinfo(domain_name, service, socket_family)
                if len(address_infos)>0:
                    return list(set(map(lambda address_info: address_info[4][0], address_infos)))
            except Exception:
                continue
        func_logger.warning("No " + address_format + " can be found for " + domain_name)
        return None
    else:
        func_logger.error("get_ip_addresses is called with an incorrect address format")
        return None

def http_server(domain_name, logger):
    """
    :param domain_name: The domain name of the server to query.
    :return: The server type obtained from the "server" header of the HTTPS response, or None if the header is not present or an error occurs.
    """
    try:
        response = requests.request("GET", "https://" + domain_name, timeout=2)
        return response.headers["server"] if "server" in response.headers else None
    except RequestException:
        func_logger = logger.get_child("http_server", {'domain_name': domain_name})
        func_logger.warning("Unable to make a HTTPS GET request to " + domain_name + " for determining it's server")
        return None


def listens_for_insecure_connections(domain_name, logger):
    """
    :param domain_name: The domain name to check whether it listens for insecure HTTP connections.
    :return: True if the domain listens for insecure connections and the HTTP request is successful; False if the http request is unsuccesful; None if an exception occurs during the request.
    """
    try:
        response = requests.request("GET", "http://" + domain_name, timeout=2)
        return response.ok
    except RequestException:
        func_logger = logger.get_child("listens_for_insecure_connections", {'domain_name': domain_name})
        func_logger.warning("Unable to make a HTTP GET request to " + domain_name + " for determining whether it listens for insecure requests")
        return None


def insecure_connection_redirects_to_secure(domain_name, logger):
    """
    :param domain_name: The domain name to be checked for insecure HTTP redirects to secure HTTPS
    :return:
             - True if the domain redirects insecure HTTP requests to secure HTTPS within 10 redirects
             - False if the domain does not redirect to HTTPS or exceeds the redirect limit
             - None if there is an requestException during one of the multiple requests
    """
    response = None
    try:
        response = requests.get("http://" + domain_name, allow_redirects=False, timeout=2)
        redirect_limit = 10
        while redirect_limit > 0:
            if 400 > response.status_code >= 300:
                if response.headers["Location"].startswith("https"):
                    return True
                else:
                    response = requests.get(response.headers["Location"], allow_redirects=False)
                    redirect_limit -= 1
            else:
                return False
        return False
    except RequestException:
        func_logger = logger.get_child("insecure_connection_redirects_to_secure", {'domain_name': domain_name})
        if isinstance(response, Response):
            func_logger.warning("Unable to make a HTTP GET request to " + response.headers[
                "Location"] + " for determining whether it listens for insecure requests")
        else:
            func_logger.warning("Unable to make a HTTP GET request to " + domain_name + " for determining whether it listens for insecure requests")
        return None


def rtt_range(domain_name, logger):
    # for each of ivp4 addresses, create a socket.socket
    func_logger = logger.get_child("rtt_range", {'domain_name': domain_name})
    ipv4_addresses = get_ip_addresses(domain_name, "ipv4", func_logger)
    ipv6_addresses = get_ip_addresses(domain_name, "ipv6", func_logger)
    ip_addresses = (ipv4_addresses if ipv4_addresses is not None else []) + (ipv6_addresses if ipv6_addresses is not None else [])
    mn = math.inf
    mx = -math.inf
    if len(ip_addresses)>0:
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
                    func_logger.warning("TCP connection request for rtt calculation timed out for " + domain_name + " on port:" + str(
                        port) + " " + "timed out.")
                    continue
                except Exception as e:
                    func_logger.warning(
                        "TCP connection request for rtt calculation timed out for " + domain_name + "'s IP: " + ip_address +" on port:" + str(
                            port) + " " + "timed out.")
                    continue

        if mn == math.inf and mx == -math.inf:
            func_logger.error("RTT variance calculation failed as TCP connection from multiple ports " + domain_name + " timed out")
            return None
        else:
            return [mn, mx]
    else:
        func_logger.error("RTT variance for "+domain_name + " cannot be calculated since no the IP resolution for domain name failed")
        return None

def get_root_ca(domain_name, logger) -> str|None:
    """
    :param domain_name: The domain of which the root certificate authority is asked
    :return: A string denoting the root certificate authority. Returns None when an error occured
    """
    func_logger = logger.get_child("get_root_ca", {'domain_name': domain_name})
    try:
        server_certs = get_cert_chain_from_server(domain_name)
        if not server_certs:
            func_logger.error("No certificates retrieved from server.")
            return None
        leaf = server_certs[0]
        intermediates = server_certs[1:]

        trust_roots = load_trust_roots()
        if not trust_roots:
            func_logger.error("Error loading root certificates")
            return None
        # TODO-allow_fetching:False is less secure since we would not check whether is certificate has been revoked
        context = ValidationContext(trust_roots=trust_roots, allow_fetching=False)
        validator = CertificateValidator(leaf, intermediates, validation_context=context)
        path = validator.validate_usage(key_usage=set(), extended_key_usage=set(['server_auth']))
        return path.first.subject.human_friendly
    except Exception as e:
        func_logger.error("Something went wrong while getting root certificate authority for " + domain_name)
        return None


def get_cert_chain_from_server(domain_name, port=HTTPS_PORT) -> list[bytes]:
    """
    :param domain_name: The domain_name of whom to request certificate chain from.
    :param port: The port to use for the connection. Defaults TO HTTPS_PORT and specifying a different port
                 comes at a risk of the domain_name rejecting the connection request
    :return: A list of PEM encoded byte strings denoting the certificate chain obtained from the domain_name
    """
    ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    ctx.set_verify(SSL.VERIFY_NONE, lambda *args: True)

    conn = SSL.Connection(ctx, socket.socket())
    conn.set_tlsext_host_name(domain_name.encode())
    conn.connect((domain_name, port))
    conn.do_handshake()

    certs = conn.get_peer_cert_chain(as_cryptography=True)
    conn.close()
    pem_encoded_certs = []
    for cert in certs:
        pem_encoded_certs.append(cert.public_bytes(serialization.Encoding.PEM))
    return pem_encoded_certs


def load_trust_roots() -> list[bytes]:
    """
    Returns the trusted root certificates from certifi store which is Mozilla's carefully curated collection of Root Certificates
    :return: A list of PEM encoded byte strings denoting the root certificates obtained from the certificate store.
    """
    with open(certifi.where(), 'rb') as f:
        pem_data = f.read()
    root_certificates = x509.load_pem_x509_certificates(pem_data)
    pem_encoded_root_certificates = []
    for cert in root_certificates:
        pem_encoded_root_certificates.append(cert.public_bytes(serialization.Encoding.PEM))
    return pem_encoded_root_certificates


def reverse_dns(domain_name, logger):
    func_logger = logger.get_child("reverse_dns", {'domain_name': domain_name})
    ivp4_addresses = get_ip_addresses(domain_name, "ipv4", func_logger)
    dns_resolver_address = "1.1.1.1"
    for ivp4_address in ivp4_addresses:
        try:
            responses = dns.resolver.resolve_at(dns_resolver_address,
                                                ipaddress.ip_address(ivp4_address).reverse_pointer, dns.rdatatype.PTR)
            return list(map(lambda response: response.target.to_unicode(), responses))
        except Exception as e:
            func_logger.error( "While finding reverse dns entries for " + domain_name + " ip:" + ivp4_address + ", the following error was hit:" + str(
                e))
            return None


def get_geolocation_of_ips(domain_name, logger):
    func_logger = logger.get_child("get_geolocation_of_ips", {'domain_name': domain_name})
    ivp4_addresses = get_ip_addresses(domain_name, "ipv4", func_logger)
    geolocations = set()
    with geoip2.database.Reader('./geolite_ip_data/GeoLite2-City.mmdb') as reader:
        for ivp4_address in ivp4_addresses:
            try:
                response = reader.city(ivp4_address)
                if response.city.name is not None and response.country.name is not None:
                    geolocations.add(response.city.name + ", " + response.country.name)
                elif response.city.name is not None:
                    geolocations.add(response.city.name)
                elif response.country.name is not None:
                    geolocations.add(response.country.name)

            except geoip2.errors.AddressNotFoundError:
                func_logger.warning("Geolocation for IP " + ivp4_address + " not found in database.")
            except maxminddb.InvalidDatabaseError:
                func_logger.error("Database file for geolocation is corrupted")
    return list(geolocations)


def domain_enforces_strict_transport(domain_name, logger):
    func_logger = logger.get_child("domain_enforces_strict_transport", {'domain_name': domain_name})
    try:
        response = requests.request("GET", "https://" + domain_name, timeout=2)
        if "hsts" in response.headers:
            return True if response.headers["hsts"] == "true" else False
        else:
            return False
    except RequestException:
        func_logger.warning("Unable to make a HTTPS GET request to " + domain_name + " for determining hsts header")
        return None


def get_domain_security_stats(domain_name, logger):
    return {
        "scan_time": int(time.time()),
        "ipv4_addresses": get_ip_addresses(domain_name, "ipv4", logger),
        "ivp6_addresses": get_ip_addresses(domain_name, "ipv6", logger),
        "http_server": http_server(domain_name, logger),
        "insecure_http": listens_for_insecure_connections(domain_name, logger),
        "redirect_to_https": insecure_connection_redirects_to_secure(domain_name, logger),
        "rtt_range": rtt_range(domain_name, logger),
        "root_ca_name": get_root_ca(domain_name, logger),
        "rdns": reverse_dns(domain_name, logger),
        "geolocation_of_ips": get_geolocation_of_ips(domain_name, logger),
        "domain_enforces_strict_transport": domain_enforces_strict_transport(domain_name, logger),
    }


def create_report_text(domain_security_stats):
    """
    :param domain_security_stats: A dictionary of key-values where key is the domain_name and the value are security stats associated with the domain
    :return: A string denoting the textual content of the output

    """
    table = texttable.Texttable()
    label_names_and_col_nums = {
        "domain_name": ("Domain Name", 0),
        "scan_time": ("Scan Time", 1),
        "ipv4_addresses": ("IPv4 Addresses", 2),
        "ivp6_addresses": ("IPv6 Addresses", 3),
        "http_server": ("HTTP Server", 4),
        "insecure_http": ("Insecure HTTP", 5),
        "redirect_to_https": ("Redirect to HTTPS", 6),
        "rtt_range": ("RTT Range", 7),
        "root_ca_name": ("Root CA Name", 8),
        "rdns": ("Reverse DNS", 9),
        "geolocation_of_ips": ("Geolocation of IPs", 10),
        "domain_enforces_strict_transport": ("Domain Enforces Strict Transport", 11),
    }
    num_cols = 12
    header_row = [None] * num_cols
    cols_width = [15] * num_cols
    table.set_cols_width(cols_width)
    for label, col_num in label_names_and_col_nums.values():
        header_row[col_num] = label
    table.header(header_row)
    for domain_name, security_stats in domain_security_stats.items():
        row = [None] * num_cols
        row[0] = domain_name
        for stat_identifier, stat_value in security_stats.items():
            col_num_for_stat = label_names_and_col_nums[stat_identifier][1]
            row[col_num_for_stat] = "N/A" if stat_value is None else str(stat_value)
        table.add_row(row)
    return table.draw()


def generate_security_report_text(domain_file_content, logger):
    domain_names = []
    for line in domain_file_content.splitlines():
        line_trimmed = line.rstrip()
        if len(line_trimmed) > 0:
            domain_names.append(line_trimmed)

    domain_stats = dict()
    for domain_name in domain_names:
        domain_stats[domain_name] = get_domain_security_stats(domain_name, logger)
    return create_report_text(domain_stats)

def get_logger(output_log_location=DEFAULT_LOGGING_FILE, log_level=DEFAULT_LOGGING_LEVEL)->ContextLoggerAdapter:
    logger = logging.getLogger(__name__)
    logger.setLevel(log_level)
    info_formatter = logging.Formatter(
        '%(name)s - %(levelname)s - %(message)s'
    )

    if output_log_location is not None:
        log_handler = logging.FileHandler(output_log_location)
        log_handler.setLevel(log_level)
        log_handler.setFormatter(info_formatter)
        logger.addHandler(log_handler)

    return ContextLoggerAdapter(logger, {'scan_time' : lambda: time.ctime()})


def output_domain_stats_command_line_mode():
    parser = argparse.ArgumentParser()
    # Input file format is one domain per line, where each line is seperated by a newline
    parser.add_argument("input_file")
    parser.add_argument("output_file")
    parser.add_argument("--output-log", type=str, help="Path to the error log file", required=False)
    log_level_name_to_level = logging.getLevelNamesMapping()
    log_level_names = list(log_level_name_to_level.keys())
    parser.add_argument("--log-level", type=str, choices = log_level_names, help="Logging level. Everything above or equal to the level will be logged", required=False)
    args = parser.parse_args()
    if args.log_level:
        log_level = log_level_name_to_level[args.log_level]
        logger = get_logger(args.output_log, log_level)
    else:
        logger = get_logger(args.output_log)

    with open(args.input_file, "r", newline=None, encoding="utf-8", closefd=True, opener=None) as input_file:
        with open(args.output_file, "w", newline=None, encoding="utf-8", closefd=True, opener=None) as output_file:
            output_file.write(generate_security_report_text(input_file.read(-1), logger))

def output_domain_stats_module_mode(domain_file_content):
    logger = get_logger(DEFAULT_LOGGING_FILE, DEFAULT_LOGGING_LEVEL)
    return generate_security_report_text(domain_file_content, logger)

if os.name != "posix":
    raise Exception("scan.py does not support non-posix operating systems")

for command in ["nslookup", "openssl"]:
    missing_commands = []
    if shutil.which(command) is None:
        missing_commands.append(command)

if len(missing_commands) > 0:
    raise Exception("Missing command(s) ".join(missing_commands))

if __name__ == "__main__":
    output_domain_stats_command_line_mode()
