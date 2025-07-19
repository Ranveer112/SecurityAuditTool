import pytest
from domains_scanner.domain_scanner import DomainScanner
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

def test_domain_scanner_instantiation():
    logger = DummyLogger()
    scanner = DomainScanner(logger)
    assert isinstance(scanner, DomainScanner)
