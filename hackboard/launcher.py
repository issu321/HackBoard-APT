"""
HackBoard — Launcher Module
===========================

Provides programmatic launch capabilities and auto-discovery
of the HackBoard application.
"""

import os
import sys
from pathlib import Path
from typing import List, Optional

from hackboard.cli import launch_streamlit
from hackboard.utils import logger


def launch(
    port: int = 8501,
    host: str = "localhost",
    headless: bool = False,
    no_browser: bool = False,
) -> int:
    """Programmatically launch the HackBoard dashboard.

    Args:
        port: Server port.
        host: Server host.
        headless: Headless mode.
        no_browser: Skip browser open.

    Returns:
        Exit code.
    """
    return launch_streamlit(
        port=port,
        host=host,
        headless=headless,
        no_browser=no_browser,
    )


def launch_from_module() -> int:
    """Launch HackBoard when called as a module (`python -m hackboard`)."""
    return launch()
