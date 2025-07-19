import pytest
from domains_scanner.geo_ip_checker import GeoIpChecker
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

def test_geo_ip_checker_instantiation():
    logger = DummyLogger()
    checker = GeoIpChecker(logger)
    assert isinstance(checker, GeoIpChecker)
