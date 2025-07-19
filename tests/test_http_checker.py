import pytest
from domains_scanner.http_checker import HttpChecker
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

def test_http_checker_instantiation():
    logger = DummyLogger()
    checker = HttpChecker(logger, timeout_for_requests=2)
    assert isinstance(checker, HttpChecker)
