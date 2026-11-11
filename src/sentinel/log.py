"""Structured JSON logging with secret redaction.

Every log line, whether it comes from Sentinel code (structlog) or from a
library using the standard ``logging`` module, passes through one redactor
before it is written. The redactor removes values stored under sensitive keys,
whole header mappings, and any occurrence of a known secret value.
"""

import logging
import re
import sys
from collections.abc import Sequence
from typing import Any

import structlog
from structlog.typing import EventDict, Processor

REDACTED = "[REDACTED]"

_SENSITIVE_KEY = re.compile(
    r"(^|_)(api_?key|authorization|password|passwd|secret|token|cookie)(_|$)"
)
_HEADERS_KEY = re.compile(r"(^|_)headers(_|$)")


def _normalise(key: object) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(key).lower())


def make_redactor(secrets: Sequence[str] = ()) -> Processor:
    """Build a structlog processor that removes secrets from a log event.

    Args:
        secrets: Known secret values (for example the NextDNS API key). Any
            occurrence inside any string field is replaced, whatever its key.
    """
    known = tuple(sorted({s for s in secrets if s.strip()}, key=len, reverse=True))

    def scrub(value: Any) -> Any:
        if isinstance(value, str):
            for secret in known:
                value = value.replace(secret, REDACTED)
            return value
        if isinstance(value, dict):
            return {key: scrub_item(key, item) for key, item in value.items()}
        if isinstance(value, list):
            return [scrub(item) for item in value]
        if isinstance(value, tuple):
            return tuple(scrub(item) for item in value)
        return value

    def scrub_item(key: object, value: Any) -> Any:
        name = _normalise(key)
        if _SENSITIVE_KEY.search(name) or _HEADERS_KEY.search(name):
            return REDACTED
        return scrub(value)

    def redact(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
        return {key: scrub_item(key, value) for key, value in event_dict.items()}

    return redact


def configure_logging(level: str = "INFO", secrets: Sequence[str] = ()) -> None:
    """Send all logs to stdout as redacted JSON, one object per line.

    Args:
        level: Minimum level to emit (``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``).
        secrets: Secret values to scrub from every log line.
    """
    shared: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
    ]
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            *shared,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,
    )
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.format_exc_info,
            make_redactor(secrets),
            structlog.processors.JSONRenderer(),
        ],
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)
