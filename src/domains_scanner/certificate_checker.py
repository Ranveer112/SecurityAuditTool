from utils.context_logger import ContextLoggerAdapter
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import certifi
from OpenSSL import SSL
from certvalidator import CertificateValidator, ValidationContext
import socket

HTTPS_PORT=443
class CertificateChecker:
    def __init__(self, logger: ContextLoggerAdapter):
        self.logger=logger
    def get_root_ca(self, domain_name) -> str | None:
        """
        :param domain_name: The domain of which the root certificate authority is asked
        :return: A string denoting the root certificate authority. Returns None when an error occured
        """
        func_logger = self.logger.get_child("get_root_ca", {'domain_name': domain_name})
        try:
            server_certs = self.__get_cert_chain_from_server(domain_name)
            if not server_certs:
                func_logger.error("No certificates retrieved from server.")
                return None
            leaf = server_certs[0]
            intermediates = server_certs[1:]

            trust_roots = self.__load_trust_roots()
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

    def __get_cert_chain_from_server(self, domain_name, port=HTTPS_PORT) -> list[bytes]:
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

    def __load_trust_roots(self) -> list[bytes]:
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
