"""
Centralized logging configuration for the application.

Provides structured logging with automatic error tracking and contextual information.
"""
import logging
import sys
from datetime import datetime
from typing import Any


# Color codes for console output
class ColoredFormatter(logging.Formatter):
    """Colored formatter for console development output."""

    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m',       # Reset
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        record.levelname = f"{color}{record.levelname}{self.COLORS['RESET']}"
        return super().format(record)


def setup_logging(
    level: str = "INFO",
    log_file: str | None = None,
    json_output: bool = False
) -> None:
    """
    Setup application logging.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path to write logs to
        json_output: Use JSON formatted output (useful for production/log aggregation)
    """
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))

    # Remove existing handlers
    root_logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)

    if json_output:
        # Use JSON formatter for production
        formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s"}',
            datefmt='%Y-%m-%dT%H:%M:%S'
        )
    else:
        # Use colored formatter for development
        formatter = ColoredFormatter(
            '%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(
            '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s"}',
            datefmt='%Y-%m-%dT%H:%M:%S'
        ))
        root_logger.addHandler(file_handler)

    # Configure specific loggers
    logging.getLogger("uvicorn").setLevel(logging.INFO)
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)
    logging.getLogger("fastapi").setLevel(logging.INFO)
    logging.getLogger("keycloak").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with the given name."""
    return logging.getLogger(name)


def log_function_call(logger: logging.Logger, func_name: str, **kwargs):
    """Log a function call with parameters."""
    logger.debug(f"Calling {func_name} with params: {kwargs}")


def log_error(logger: logging.Logger, error: Exception, context: dict[str, Any] | None = None):
    """
    Log an error with full context.

    Args:
        logger: Logger instance
        error: Exception that was raised
        context: Additional context information
    """
    error_context = {
        "error_type": type(error).__name__,
        "error_message": str(error),
    }
    if context:
        error_context.update(context)

    logger.error(f"Error occurred: {error_context}", exc_info=error)


def log_http_response(
    logger: logging.Logger,
    method: str,
    path: str,
    status_code: int,
    duration_ms: float,
    user_id: str | None = None,
    error: str | None = None
):
    """
    Log HTTP request/response information.

    Args:
        logger: Logger instance
        method: HTTP method
        path: Request path
        status_code: HTTP status code
        duration_ms: Request duration in milliseconds
        user_id: User ID if authenticated
        error: Error message if request failed
    """
    log_data = {
        "method": method,
        "path": path,
        "status_code": status_code,
        "duration_ms": round(duration_ms, 2),
        "user_id": user_id,
    }
    if error:
        log_data["error"] = error
        logger.error(f"HTTP request failed: {log_data}")
    elif status_code >= 500:
        logger.error(f"HTTP request server error: {log_data}")
    elif status_code >= 400:
        logger.warning(f"HTTP request client error: {log_data}")
    else:
        logger.info(f"HTTP request: {log_data}")
