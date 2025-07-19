from utils.context_logger import ContextLoggerAdapter
from domains_scanner.constants import DEFAULT_LOGGING_FILE, DEFAULT_LOGGING_LEVEL
from domains_scanner.domain_scanner import DomainScanner
import texttable
import argparse
import logging


# TODO - This method is dependent on stats collected, perhaps this can go in domain_scanner
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
    domain_scanner = DomainScanner(logger)
    for domain_name in domain_names:
        domain_stats[domain_name] = domain_scanner.get_domain_security_stats(domain_name)
    return create_report_text(domain_stats)


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
        logger = ContextLoggerAdapter.get_logger(name='domain_scan', output_log_location=args.output_log, log_level=log_level)
    else:
        logger = ContextLoggerAdapter.get_logger(name='domain_scan',output_log_location=args.output_log)

    with open(args.input_file, "r", newline=None, encoding="utf-8", closefd=True, opener=None) as input_file:
        with open(args.output_file, "w", newline=None, encoding="utf-8", closefd=True, opener=None) as output_file:
            output_file.write(generate_security_report_text(input_file.read(-1), logger))

def output_domain_stats_module_mode(domain_file_content):
    logger = ContextLoggerAdapter.get_logger(output_log_location=DEFAULT_LOGGING_FILE,  log_level=DEFAULT_LOGGING_LEVEL)
    return generate_security_report_text(domain_file_content, logger)
