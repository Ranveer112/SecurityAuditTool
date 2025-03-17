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

error_logs = ""


def run_command_and_get_result(command):
    """
    Runs specified command on the shell with a timeout of 2 seconds

    :param command: A string representing the shell command to be executed.
    :return: A string representing the decoded output of the executed command.
    :raises TimeoutExpired: If the command execution times out.
    :raises CalledProcessError: If the command execution fails.
    """
    result = subprocess.check_output(command, timeout=2, stderr=subprocess.STDOUT, shell=True).decode("utf-8")
    return result


def get_ip_addresses(domain_name, address_format):
    """
    :param domain_name: The domain name for which the IP addresses need to be fetched.
    :param address_format: Specifies the IP address format to retrieve. Acceptable values are "ivp4" or "ivp6".
    :return: A list of IP addresses associated with the domain name, None in case of an error,
    """
    global error_logs
    try:
        if address_format == "ivp4":
            nslookup_result = run_command_and_get_result("nslookup -type=A " + quote(domain_name))

        elif address_format == "ivp6":
            nslookup_result = run_command_and_get_result("nslookup -type=AAAA " + quote(domain_name))
        else:
            return None
        return get_addresses_from_nslookup_output(nslookup_result)
    except TimeoutExpired:
        error_logs += "nslookup timed out while fetching IPs for " + domain_name +"\n"
        return None
    except ValueError:
        error_logs += "Error while parsing nslookup output for " + domain_name + " " + address_format + " IPs\n"
        return None
    except CalledProcessError:
        error_logs += "Error while executing nslookup for " + domain_name + " " + address_format + " IPs\n"
        return None

def is_valid_ipaddr(address):
    """
    :param address: The IP address string to validate
    :return: Returns True if the given address is a valid IP address, otherwise False
    """
    try:
        ip = ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def get_addresses_from_nslookup_output(result):
    """
    Parses the output of the `nslookup` command and extracts all valid IP addresses.

    :param result: The string output from the `nslookup` command. The string is expected to have the approximately one of the following format
         Name: <domain_name>
         Address:
         <ip_address>
         or
         Name: <domain_name>
         Addresses:
         <ip_address_1>
         <ip_address_2>
    :return: A list of extracted IP addresses.
    :raises ValueError: If the string does not seem to match one of the format.
    """
    prefix_not_having_ips, suffix_having_ips = result.split('Name:', maxsplit=1)
    addresses=[]
    while len(suffix_having_ips)>0:
        current_line, suffix_having_ips = suffix_having_ips.split('\n', maxsplit=1)
        if "Address" in current_line:
            ip_address = re.split("Addresses:|Address:", current_line)[1].strip()
            addresses.append(ip_address)
            while is_valid_ipaddr(suffix_having_ips.split('\n', maxsplit=1)[0].strip()):
                current_line, suffix_having_ips = suffix_having_ips.split('\n', maxsplit=1)
                ip_address = current_line.strip()
                addresses.append(ip_address)
    return addresses
def http_server(domain_name):
    """
    :param domain_name: The domain name of the server to query.
    :return: The server type obtained from the "server" header of the HTTPS response, or None if the header is not present or an error occurs.
    """
    try:
        response = requests.request("GET", "https://"+domain_name, timeout=2)
        return response.headers["server"] if "server" in response.headers else None
    except RequestException:
        global error_logs
        error_logs += "Unable to make a HTTPS GET request to " + domain_name +" for determining it's server\n"
        return None

def listens_for_insecure_connections(domain_name):
    """
    :param domain_name: The domain name to check whether it listens for insecure HTTP connections.
    :return: True if the domain listens for insecure connections and the HTTP request is successful; False if the http request is unsuccesful; None if an exception occurs during the request.
    """
    try:
        response = requests.request("GET", "http://"+domain_name, timeout=2)
        return response.ok
    except RequestException:
        global error_logs
        error_logs += "Unable to make a HTTP GET request to " + domain_name +" for determining whether it listens for insecure requests\n"
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
        response = requests.get("http://"+domain_name, allow_redirects=False, timeout=2)
        redirect_limit = 10
        while redirect_limit>0:
            if 400 > response.status_code >= 300:
                if response.headers["Location"].startswith("https"):
                    return True
                else:
                    response = requests.get(response.headers["Location"], allow_redirects=False)
                    redirect_limit-=1
            else:
                return False
        return False
    except RequestException:
        global error_logs
        if isinstance(response, Response):
            error_logs += "Unable to make a HTTP GET request to " + response.headers["Location"] +" for determining whether it listens for insecure requests\n"
        else :
            error_logs += "Unable to make a HTTP GET request to " + domain_name +" for determining whether it listens for insecure requests\n"
        return None

def rtt_range(domain_name):
    # for each of ivp4 addresses, create a socket.socket
    ivp4_addresses = get_ip_addresses(domain_name, "ivp4")
    mn = math.inf
    mx= -math.inf
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
                    error_logs+="TCP connection request for rtt calculation timed out for " + domain_name + " on port:"+ str(port) + " " + "timed out.\n"
                    continue
    if mn == math.inf and mx == -math.inf:
        error_logs+="RTT variance calculation failed as TCP connection from multiple ports " + domain_name + " timed out.\n"
        return None
    return [mn, mx]

def get_root_ca(domain_name):
    global error_logs
    try:
        openssl_sclient_output = run_command_and_get_result('echo | openssl s_client -connect ' + quote(domain_name)+ ':443')
        root_ca_info = openssl_sclient_output.split("\n")[0]
        suffix_containing_organization_name = re.search(r"O = .*", root_ca_info).group(0).split("O = ")[1]
        # Iterate till a starting quotes is matched with an ending quotes OR a comma is hit
        organization_name=""
        open_quotes_found = False
        for c in suffix_containing_organization_name:
            if (c == '"' and open_quotes_found) or  (c == "," and not open_quotes_found):
                break
            elif c == '"' and not open_quotes_found:
                open_quotes_found=True
            else:
                organization_name+=c
        return organization_name
    except TimeoutExpired:
        error_logs += "Root CA cannot be determined as HTTPS connection via openssl to port 443 for " + domain_name + " timed out\n"
        return None
    except ValueError:
        error_logs += "Root CA cannot be determined as parsing error occured while parsing openssl out for " + domain_name +":443.\n"
        return None
    except CalledProcessError:
        error_logs += "Root CA cannot be determined as an unknown error occured with openssl\n"
        return None

def reverse_dns(domain_name):
    ivp4_addresses = get_ip_addresses(domain_name, "ivp4")
    dns_resolver_address = "1.1.1.1"
    global error_logs
    for ivp4_address in ivp4_addresses:
        try:
            responses = dns.resolver.resolve_at(dns_resolver_address, ipaddress.ip_address(ivp4_address).reverse_pointer, dns.rdatatype.PTR)
            return list(map(lambda response: response.target.to_unicode(), responses))
        except Exception as e:
            error_logs += "While finding reverse dns entries for " + domain_name + " ip:" + ivp4_address + ", the following error was hit:" + str(e)+"\n"
            return None

def get_geolocation_of_ips(domain_name):

    global error_logs
    ivp4_addresses = get_ip_addresses(domain_name, "ivp4")
    geolocations = set()
    with geoip2.database.Reader('./geolite_ip_data/GeoLite2-City.mmdb') as reader:
        for ivp4_address in ivp4_addresses:
            try:
                response = reader.city(ivp4_address)
                if response.city.name is not None and response.country.name is not None:
                    geolocations.add(response.city.name+", "+response.country.name)
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
        response = requests.request("GET", "https://"+domain_name, timeout=2)
        if "hsts" in response.headers:
            return True if response.headers["hsts"] == "true" else False
        else:
            return False
    except RequestException:
        global error_logs
        error_logs += "Unable to make a HTTPS GET request to " + domain_name +" for determining hsts header\n"
        return None

def get_domain_security_stats(domain_name):
    return {
        "scan_time" : int(time.time()),
        "ipv4_addresses": get_ip_addresses(domain_name, "ivp4"),
        "ivp6_addresses": get_ip_addresses(domain_name, "ivp6"),
        "http_server": http_server(domain_name),
        "insecure_http": listens_for_insecure_connections(domain_name),
        "redirect_to_https":insecure_connection_redirects_to_secure(domain_name),
        "rtt_range":rtt_range(domain_name),
        "root_ca_name":get_root_ca(domain_name),
        "rdns" : reverse_dns(domain_name),
        "geolocation_of_ips" : get_geolocation_of_ips(domain_name),
        "domain_enforces_strict_transport": domain_enforces_strict_transport(domain_name),
    }


def create_report_text(domain_security_stats):
    """
    :param domain_security_stats: A dictionary of key-values where key is the domain_name and the value are security stats associated with the domain
    :return: A string denoting the textual content of the output

    """
    table = texttable.Texttable()
    label_names_and_col_nums = {
        "domain_name" : ("Domain Name", 0),
        "scan_time" : ("Scan Time", 1),
        "ipv4_addresses" : ("IPv4 Addresses", 2),
        "ivp6_addresses" : ("IPv6 Addresses", 3),
        "http_server" : ("HTTP Server", 4),
        "insecure_http" : ("Insecure HTTP", 5),
        "redirect_to_https" : ("Redirect to HTTPS", 6),
        "rtt_range" : ("RTT Range", 7),
        "root_ca_name" : ("Root CA Name", 8),
        "rdns" : ("Reverse DNS", 9),
        "geolocation_of_ips" : ("Geolocation of IPs", 10),
        "domain_enforces_strict_transport": ("Domain Enforces Strict Transport", 11),
    }
    num_cols = 12
    header_row = [None]*num_cols
    cols_width = [15]*num_cols
    table.set_cols_width(cols_width)
    for label, col_num in label_names_and_col_nums.values():
        header_row[col_num] = label
    table.header(header_row)
    for domain_name, security_stats in domain_security_stats.items():
        row = [None]*num_cols
        row[0] = domain_name
        for stat_identifier, stat_value in security_stats.items():
            col_num_for_stat=label_names_and_col_nums[stat_identifier][1]
            row[col_num_for_stat] = "N/A" if stat_value is None else str(stat_value)
        table.add_row(row)
    return table.draw()

def generate_security_report_text(domain_file_content):
    domain_names=[]
    for line in domain_file_content.splitlines():
        line_trimmed = line.rstrip()
        if len(line_trimmed) > 0:
            domain_names.append(line_trimmed)

    domain_stats=dict()
    for domain_name in domain_names:
        domain_stats[domain_name]=get_domain_security_stats(domain_name)
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

if len(missing_commands)>0:
        raise Exception("Missing command(s) ".join(missing_commands))

if __name__ == "__main__":
    go()
