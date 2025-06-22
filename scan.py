import argparse
import ipaddress
import shutil
import socket
import time
import subprocess
import re

import dns.resolver
import dns.rdatatype
import geoip2.database
import maxminddb
import math
import requests
import texttable
from requests import RequestException, Response
from subprocess import TimeoutExpired, CalledProcessError
from shlex import quote
import os
from OpenSSL import SSL
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import certifi
from certvalidator import CertificateValidator, ValidationContext

error_logs = ""
HTTPS_PORT = 443

def get_ip_addresses(domain_name, address_format) -> list[str]|None:
    """
    :param domain_name: The domain name for which the IP addresses need to be fetched.
    :param address_format: Specifies the IP address format to retrieve. Acceptable values are "ivp4" or "ivp6".
    :return: A list of IP addresses associated with the domain name, None in case of an error,
    """
    global error_logs
    if address_format == "ipv4" or address_format == "ipv6":
        socket_family = socket.AF_INET if address_format == "ipv4" else socket.AF_INET6
        for service in ('https', 'http'):
            try:
                address_infos = socket.getaddrinfo(domain_name, service, socket_family)
                if len(address_infos)>0:
                    return list(set(map(lambda address_info: address_info[4][0], address_infos)))
            except Exception:
                continue
        error_logs += "No " + address_format + " can be found for " + domain_name+"\n"
        return None
    else:
        error_logs += "get_ip_addresses is called with an incorrect address format\n"
        return None

def http_server(domain_name):
    """
    :param domain_name: The domain name of the server to query.
    :return: The server type obtained from the "server" header of the HTTPS response, or None if the header is not present or an error occurs.
    """
    try:
        response = requests.request("GET", "https://" + domain_name, timeout=2)
        return response.headers["server"] if "server" in response.headers else None
    except RequestException:
        global error_logs
        error_logs += "Unable to make a HTTPS GET request to " + domain_name + " for determining it's server\n"
        return None


def listens_for_insecure_connections(domain_name):
    """
    :param domain_name: The domain name to check whether it listens for insecure HTTP connections.
    :return: True if the domain listens for insecure connections and the HTTP request is successful; False if the http request is unsuccesful; None if an exception occurs during the request.
    """
    try:
        response = requests.request("GET", "http://" + domain_name, timeout=2)
        return response.ok
    except RequestException:
        global error_logs
        error_logs += "Unable to make a HTTP GET request to " + domain_name + " for determining whether it listens for insecure requests\n"
        return None


def insecure_connection_redirects_to_secure(domain_name):
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
        global error_logs
        if isinstance(response, Response):
            error_logs += "Unable to make a HTTP GET request to " + response.headers[
                "Location"] + " for determining whether it listens for insecure requests\n"
        else:
            error_logs += "Unable to make a HTTP GET request to " + domain_name + " for determining whether it listens for insecure requests\n"
        return None


def rtt_range(domain_name):
    # for each of ivp4 addresses, create a socket.socket
    ivp4_addresses = get_ip_addresses(domain_name, "ipv4")
    mn = math.inf
    mx = -math.inf
    global error_logs
    if ivp4_addresses is not None:
        for ivp4_address in ivp4_addresses:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Try an HTTPS port, then a HTTP port, and then a FTP port
            for port in (443, 80, 20):
                try:
                    before = time.time()
                    sock.connect((ivp4_address, port))
                    rtt = time.time() - before
                    mn = min(rtt, mn)
                    mx = max(rtt, mx)
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                    break
                except TimeoutError:
                    error_logs += "TCP connection request for rtt calculation timed out for " + domain_name + " on port:" + str(
                        port) + " " + "timed out.\n"
                    continue
    if mn == math.inf and mx == -math.inf:
        error_logs += "RTT variance calculation failed as TCP connection from multiple ports " + domain_name + " timed out.\n"
        return None
    return [mn, mx]


def get_root_ca(domain_name) -> str|None:
    """
    :param domain_name: The domain of which the root certificate authority is asked
    :return: A string denoting the root certificate authority. Returns None when an error occured
    """
    global error_logs
    try:
        server_certs = get_cert_chain_from_server(domain_name)
        if not server_certs:
            raise Exception("No certificates retrieved from server.")

        leaf = server_certs[0]
        intermediates = server_certs[1:]

        trust_roots = load_trust_roots()
        if not trust_roots:
            raise Exception("Error loading root certificates")
        # TODO-allow_fetching:False is less secure since we would not check whether is certificate has been revoked
        context = ValidationContext(trust_roots=trust_roots, allow_fetching=False)
        validator = CertificateValidator(leaf, intermediates, validation_context=context)
        path = validator.validate_usage(key_usage=set(), extended_key_usage=set(['server_auth']))
        return path.first.subject.human_friendly
    except Exception as e:
        error_logs += "Something went wrong while getting root certificate authority for " + domain_name
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


def reverse_dns(domain_name):
    ivp4_addresses = get_ip_addresses(domain_name, "ipv4")
    dns_resolver_address = "1.1.1.1"
    global error_logs
    for ivp4_address in ivp4_addresses:
        try:
            responses = dns.resolver.resolve_at(dns_resolver_address,
                                                ipaddress.ip_address(ivp4_address).reverse_pointer, dns.rdatatype.PTR)
            return list(map(lambda response: response.target.to_unicode(), responses))
        except Exception as e:
            error_logs += "While finding reverse dns entries for " + domain_name + " ip:" + ivp4_address + ", the following error was hit:" + str(
                e) + "\n"
            return None


def get_geolocation_of_ips(domain_name):
    global error_logs
    ivp4_addresses = get_ip_addresses(domain_name, "ipv4")
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
                error_logs += "Geolocation for IP " + ivp4_address + " not found in database.\n"
            except maxminddb.InvalidDatabaseError:
                error_logs += "Database file for geolocation is corrupted.\n"
    return list(geolocations)


def domain_enforces_strict_transport(domain_name):
    try:
        response = requests.request("GET", "https://" + domain_name, timeout=2)
        if "hsts" in response.headers:
            return True if response.headers["hsts"] == "true" else False
        else:
            return False
    except RequestException:
        global error_logs
        error_logs += "Unable to make a HTTPS GET request to " + domain_name + " for determining hsts header\n"
        return None


def get_domain_security_stats(domain_name):
    return {
        "scan_time": int(time.time()),
        "ipv4_addresses": get_ip_addresses(domain_name, "ipv4"),
        "ivp6_addresses": get_ip_addresses(domain_name, "ipv6"),
        "http_server": http_server(domain_name),
        "insecure_http": listens_for_insecure_connections(domain_name),
        "redirect_to_https": insecure_connection_redirects_to_secure(domain_name),
        "rtt_range": rtt_range(domain_name),
        "root_ca_name": get_root_ca(domain_name),
        "rdns": reverse_dns(domain_name),
        "geolocation_of_ips": get_geolocation_of_ips(domain_name),
        "domain_enforces_strict_transport": domain_enforces_strict_transport(domain_name),
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


def generate_security_report_text(domain_file_content):
    domain_names = []
    for line in domain_file_content.splitlines():
        line_trimmed = line.rstrip()
        if len(line_trimmed) > 0:
            domain_names.append(line_trimmed)

    domain_stats = dict()
    for domain_name in domain_names:
        domain_stats[domain_name] = get_domain_security_stats(domain_name)
    return create_report_text(domain_stats)


def go():
    parser = argparse.ArgumentParser()
    # Input file format is one domain per line, where each line is seperated by a newline
    parser.add_argument("input_file")
    parser.add_argument("output_file")
    parser.add_argument("--error-log", help="Path to the error log file", required=False)
    args = parser.parse_args()
    with open(args.input_file, "r", newline=None, encoding="utf-8", closefd=True, opener=None) as input_file:
        with open(args.output_file, "w", newline=None, encoding="utf-8", closefd=True, opener=None) as output_file:
            output_file.write(generate_security_report_text(input_file.read(-1)))
    # If error-log flag is set, dump error log in a log file

    global error_logs
    if args.error_log:
        with open(args.error_log, "w", newline=None, encoding="utf-8", closefd=True, opener=None) as error_log_file:
            if error_logs.strip():
                error_log_file.write(error_logs)


if os.name != "posix":
    raise Exception("scan.py does not support non-posix operating systems")

for command in ["nslookup", "openssl"]:
    missing_commands = []
    if shutil.which(command) is None:
        missing_commands.append(command)

if len(missing_commands) > 0:
    raise Exception("Missing command(s) ".join(missing_commands))

if __name__ == "__main__":
    go()
