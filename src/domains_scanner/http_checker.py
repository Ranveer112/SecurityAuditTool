from utils.context_logger import ContextLoggerAdapter
import requests
from requests.exceptions import RequestException
from requests.models import Response

class HttpChecker:
    def __init__(self, logger: ContextLoggerAdapter, timeout_for_requests: int):
        self.logger=logger
        self.timeout_for_requests=timeout_for_requests
    def http_server(self, domain_name):
        """
        :param domain_name: The domain name of the server to query.
        :return: The server type obtained from the "server" header of the HTTPS response, or None if the header is not present or an error occurs.
        """
        try:
            response = requests.request("GET", "https://" + domain_name, timeout=self.timeout_for_requests)
            return response.headers["server"] if "server" in response.headers else None
        except RequestException:
            func_logger = self.logger.get_child("http_server", {'domain_name': domain_name})
            func_logger.warning("Unable to make a HTTPS GET request to " + domain_name + " for determining it's server")
            return None

    def listens_for_insecure_connections(self, domain_name):
        """
        :param domain_name: The domain name to check whether it listens for insecure HTTP connections.
        :return: True if the domain listens for insecure connections and the HTTP request is successful; False if the http request is unsuccesful; None if an exception occurs during the request.
        """
        try:
            response = requests.request("GET", "http://" + domain_name, timeout=self.timeout_for_requests)
            return response.ok
        except RequestException:
            func_logger = self.logger.get_child("listens_for_insecure_connections", {'domain_name': domain_name})
            func_logger.warning(
                "Unable to make a HTTP GET request to " + domain_name + " for determining whether it listens for insecure requests")
            return None

    def insecure_connection_redirects_to_secure(self, domain_name):
        """
        :param domain_name: The domain name to be checked for insecure HTTP redirects to secure HTTPS
        :return:
                 - True if the domain redirects insecure HTTP requests to secure HTTPS within 10 redirects
                 - False if the domain does not redirect to HTTPS or exceeds the redirect limit
                 - None if there is an requestException during one of the multiple requests
        """
        response = None
        try:
            response = requests.get("http://" + domain_name, allow_redirects=False, timeout=self.timeout_for_requests)
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
            func_logger = self.logger.get_child("insecure_connection_redirects_to_secure", {'domain_name': domain_name})
            if isinstance(response, Response):
                func_logger.warning("Unable to make a HTTP GET request to " + response.headers[
                    "Location"] + " for determining whether it listens for insecure requests")
            else:
                func_logger.warning(
                    "Unable to make a HTTP GET request to " + domain_name + " for determining whether it listens for insecure requests")
            return None

    def domain_enforces_strict_transport(self, domain_name):
        func_logger = self.logger.get_child("domain_enforces_strict_transport", {'domain_name': domain_name})
        try:
            response = requests.request("GET", "https://" + domain_name, timeout=self.timeout_for_requests)
            if "hsts" in response.headers:
                return True if response.headers["hsts"] == "true" else False
            else:
                return False
        except RequestException:
            func_logger.warning("Unable to make a HTTPS GET request to " + domain_name + " for determining hsts header")
            return None

