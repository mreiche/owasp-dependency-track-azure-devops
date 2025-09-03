import logging
import os

type Logger = logging.Logger | logging.LoggerAdapter

numeric_level = getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), None)
if not isinstance(numeric_level, int):
    raise ValueError('Invalid log level: %s' % numeric_level)

logging.basicConfig(level=numeric_level)
logger = logging.getLogger("owasp-dtrack-azure-devops")

def get_logger(sub_logger: str | Logger=None, **kwargs) -> logging.LoggerAdapter:
    if sub_logger is None:
        sub_logger = logger
    elif isinstance(sub_logger, str):
        sub_logger = logging.getLogger(sub_logger)

    return ContextStreamLogger(sub_logger, **kwargs)

class ContextStreamLogger(logging.LoggerAdapter):
    def __init__(self, logger: Logger, **kwargs):
        super().__init__(logger, extra=kwargs)

    def _format_extras(self):
        extras = f"{'] ['.join(map(lambda item: str(item[0])+'='+str(item[1]), self.extra.items()))}"
        if len(extras) > 0:
            return f"[{extras}] "
        else:
            return ""

    def process(self, msg, kwargs: dict):
        return f"{self._format_extras()}{msg}", kwargs
