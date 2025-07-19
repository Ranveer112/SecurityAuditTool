import socket
from utils.context_logger import ContextLoggerAdapter


def get_ip_addresses(domain_name, address_format, logger:ContextLoggerAdapter) -> list[str]|None:
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
