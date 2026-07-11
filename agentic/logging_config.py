"""
NisargHunter AI Agent Logging Configuration

Configures logging with file rotation, console output, and proper formatting.
"""
import contextvars
import logging
import uuid
from contextlib import contextmanager
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Iterator, Optional

from project_settings import get_setting

# =============================================================================
# REQUEST/CORRELATION ID (Phase 16)
# =============================================================================
# A contextvar rather than a parameter threaded through every function call —
# the idiomatic way to propagate a correlation id through Python's logging
# module. api.py's HTTP middleware sets this once per request (from an
# incoming X-Request-ID header, or a freshly generated one); every log line
# emitted anywhere during that request — including deep inside the
# orchestrator/tool-call stack — picks it up automatically via the filter
# installed on every handler below.
_request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")


def get_request_id() -> str:
    """Current request/correlation id, or '-' if none is set (e.g. a background task)."""
    return _request_id_var.get()


def set_request_id(request_id: Optional[str] = None) -> str:
    """Set the current request id, generating a short one if not provided. Returns the id in use."""
    value = request_id or uuid.uuid4().hex[:12]
    _request_id_var.set(value)
    return value


@contextmanager
def request_context(request_id: Optional[str] = None) -> Iterator[str]:
    """Scope a request id to a `with` block; restores the previous value on exit."""
    token = _request_id_var.set(request_id or uuid.uuid4().hex[:12])
    try:
        yield _request_id_var.get()
    finally:
        _request_id_var.reset(token)


class RequestIdFilter(logging.Filter):
    """Injects the current contextvar's request id as record.request_id for every log line."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = get_request_id()
        return True

# =============================================================================
# LOGGING SETTINGS
# =============================================================================

# Log directory (relative to this file)
LOG_DIR = Path(__file__).parent / "logs"

# Module-specific log directories
CODEFIX_LOG_DIR = Path(__file__).parent / "cypherfix_codefix" / "logs"
TRIAGE_LOG_DIR = Path(__file__).parent / "cypherfix_triage" / "logs"

# Module log config: (logger_name, log_dir, log_file_name)
MODULE_LOGS = [
    ("cypherfix_codefix", CODEFIX_LOG_DIR, "codefix.log"),
    ("cypherfix_triage", TRIAGE_LOG_DIR, "triage.log"),
]

# Log file settings
LOG_FILE_NAME = "agent.log"
LOG_MAX_BYTES = get_setting('LOG_MAX_MB', 10) * 1024 * 1024  # Convert MB to bytes

# Log levels
FILE_LOG_LEVEL = logging.DEBUG
CONSOLE_LOG_LEVEL = logging.INFO

# Log format — %(request_id)s is injected by RequestIdFilter, not a stdlib
# LogRecord attribute, so every handler this format is applied to MUST have
# the filter attached (setup_logging does this for all of them below).
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | req=%(request_id)s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Detailed format for file (includes more context)
FILE_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-25s | %(funcName)-20s | req=%(request_id)s | %(message)s"


def setup_logging(
    log_level: int = logging.INFO,
    log_to_console: bool = True,
    log_to_file: bool = True,
) -> None:
    """
    Configure logging for the NisargHunter AI agent.

    Args:
        log_level: Minimum log level for console output
        log_to_console: Whether to output logs to console
        log_to_file: Whether to output logs to file with rotation
    """
    # Ensure log directory exists
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    # Get root logger for agentic module
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  # Capture all levels, handlers will filter

    # Clear existing handlers to avoid duplicates
    root_logger.handlers.clear()

    # request_id is injected per-handler (not per-logger): logger-level
    # filters only run for the originating logger, but every module logger
    # here propagates up to root's handlers, so the filter has to live on
    # each Handler to guarantee it fires regardless of where a record
    # originated.
    request_id_filter = RequestIdFilter()

    # Console handler
    if log_to_console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
        console_handler.setFormatter(console_formatter)
        console_handler.addFilter(request_id_filter)
        root_logger.addHandler(console_handler)

    # File handler with rotation
    if log_to_file:
        log_file_path = LOG_DIR / LOG_FILE_NAME
        file_handler = RotatingFileHandler(
            filename=str(log_file_path),
            maxBytes=LOG_MAX_BYTES,
            backupCount=get_setting('LOG_BACKUP_COUNT', 5),
            encoding="utf-8",
        )
        file_handler.setLevel(FILE_LOG_LEVEL)
        file_formatter = logging.Formatter(FILE_LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
        file_handler.setFormatter(file_formatter)
        file_handler.addFilter(request_id_filter)
        root_logger.addHandler(file_handler)

    # Module-specific file handlers (separate log files for CypherFix agents)
    if log_to_file:
        for module_name, log_dir, log_file in MODULE_LOGS:
            log_dir.mkdir(parents=True, exist_ok=True)
            module_handler = RotatingFileHandler(
                filename=str(log_dir / log_file),
                maxBytes=LOG_MAX_BYTES,
                backupCount=get_setting('LOG_BACKUP_COUNT', 5),
                encoding="utf-8",
            )
            module_handler.setLevel(FILE_LOG_LEVEL)
            module_handler.setFormatter(
                logging.Formatter(FILE_LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
            )
            module_handler.addFilter(request_id_filter)
            module_logger = logging.getLogger(module_name)
            module_logger.handlers.clear()  # Prevent duplicates on re-init
            module_logger.addHandler(module_handler)

    # Reduce noise from third-party libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("anthropic").setLevel(logging.WARNING)
    logging.getLogger("langchain").setLevel(logging.INFO)
    logging.getLogger("langgraph").setLevel(logging.INFO)
    logging.getLogger("neo4j").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    # MCP client logs are very verbose - suppress them
    logging.getLogger("mcp").setLevel(logging.WARNING)
    logging.getLogger("mcp.client").setLevel(logging.WARNING)
    logging.getLogger("mcp.client.sse").setLevel(logging.WARNING)

    # Log startup message
    logger = logging.getLogger(__name__)
    logger.info(f"Logging configured - File: {LOG_DIR / LOG_FILE_NAME}")
    for module_name, log_dir, log_file in MODULE_LOGS:
        logger.info(f"  Module log: {module_name} -> {log_dir / log_file}")
    logger.info(f"Max file size: {LOG_MAX_BYTES / 1024 / 1024:.1f} MB, Backup count: {get_setting('LOG_BACKUP_COUNT', 5)}")


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the given name.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)
