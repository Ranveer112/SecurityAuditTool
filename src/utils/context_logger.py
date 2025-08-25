import logging
from logging import LoggerAdapter
import time
DEFAULT_LOGGING_FILE = "log.txt"
DEFAULT_LOGGING_LEVEL = logging.ERROR


class ContextLoggerAdapter(logging.LoggerAdapter):
    @classmethod
    def get_logger(ContextLoggerAdapter, name: str = __name__, output_log_location: str = DEFAULT_LOGGING_FILE, log_level=DEFAULT_LOGGING_LEVEL):
        logger = logging.getLogger(name)
        logger.setLevel(log_level)

        formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')

        if output_log_location:
            log_handler = logging.FileHandler(output_log_location)
            log_handler.setLevel(log_level)
            log_handler.setFormatter(formatter)
            logger.addHandler(log_handler)

        return ContextLoggerAdapter(logger, {'scan_time': lambda: time.ctime()})

    def process(self, msg, kwargs):
        context_stringified = str({k: v() if callable(v) else v for k, v in self.extra.items()})
        return f"[" +context_stringified + "] {"+msg+"}", kwargs

    def get_child(self, suffix, additional_context):
        """Create child ContextLoggerAdapter with same context as parent but with additional context"""
        child_logger = logging.getLogger(f"{self.name}.{suffix}")
        parent_logger_adapter_context = self.extra.copy()
        return ContextLoggerAdapter(child_logger, parent_logger_adapter_context|additional_context)
