import logging
import os

type Logger = logging.Logger | logging.LoggerAdapter

def get_log_level(log_level_str: str):
    log_level = getattr(logging, log_level_str, None)
    if not isinstance(log_level, int):
        raise ValueError('Invalid log level: %s' % log_level)
    return log_level

logging.basicConfig(level=get_log_level(os.getenv("LOG_LEVEL", "INFO")))
logging.getLogger("httpx").setLevel(os.getenv("HTTPX_LOG_LEVEL", "WARNING"))

logger = logging.getLogger("owasp-dtrack-azure-devops")

def get_logger(sub_logger:Logger = None, **kwargs) -> logging.LoggerAdapter:
    if sub_logger is None:
        sub_logger = logger
    return ContextStreamLogger(sub_logger, **kwargs)

class ContextStreamLogger(logging.LoggerAdapter):
    def __init__(self, parent_logger: Logger, **kwargs):
        super().__init__(parent_logger, extra=kwargs, merge_extra=True)

    def _format_extras(self):
        extras_string = f"{'] ['.join(map(lambda item: str(item[0])+'='+str(item[1]), self.extra.items()))}"
        if len(extras_string) > 0:
            return f"[{extras_string}] "
        else:
            return ""

    def process(self, msg, kwargs: dict):
        return f"{self._format_extras()}{msg}", kwargs
