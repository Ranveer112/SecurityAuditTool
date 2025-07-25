
from utils.context_logger import ContextLoggerAdapter


class DummyLogger(ContextLoggerAdapter):
    def __init__(self):
        self.error_messages=[]
        self.warning_messages=[]
        self.info_messages=[]
    def get_child(self, *args, **kwargs):
        return self
    def error(self, *args, **kwargs):
        self.error_messages.append(args)
    def warning(self, *args, **kwargs):
        self.warning_messages.append(args)
    def info(self, *args, **kwargs):
        self.info_messages.append(args)