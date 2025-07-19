import pytest
from domains_scanner.dns_checker import DnsChecker
from utils.context_logger import ContextLoggerAdapter

class DummyLogger(ContextLoggerAdapter):
    def __init__(self):
        pass
    def get_child(self, *args, **kwargs):
        return self
    def error(self, *args, **kwargs):
        pass
    def warning(self, *args, **kwargs):
        pass
    def info(self, *args, **kwargs):
        pass

def test_dns_checker_instantiation():
    logger = DummyLogger()
    checker = DnsChecker(logger, dns_resolver_address='1.1.1.1')
    assert isinstance(checker, DnsChecker)
