"""Console and logging utilities."""

import logging
from typing import Any

# Optional imports with fallbacks
try:
    from rich.console import Console as RichConsole
    from rich.logging import RichHandler
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    class RichConsole:  # type: ignore
        def print(self, *args: Any) -> None:
            print(*args)
    RichHandler = None  # type: ignore


def setup_logging() -> None:
    """Setup logging with Rich integration if available."""
    if RICH_AVAILABLE and RichHandler is not None:
        logging.basicConfig(
            level=logging.INFO,
            format="%(message)s",
            handlers=[RichHandler(rich_tracebacks=True)]
        )
    else:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s: %(message)s"
        )


def create_console() -> RichConsole:
    """Create console instance with fallback."""
    return RichConsole()