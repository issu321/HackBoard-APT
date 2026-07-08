"""
HackBoard — Professional Cybersecurity Intelligence Platform
=============================================================

A next-generation cybersecurity dashboard for ethical hacking,
OSINT intelligence, threat analysis, and defensive security operations.

Package: hackboard
Version: 1.0.0
Author: issu321
License: MIT
"""

from pathlib import Path

__version__ = "1.0.0"
__author__ = "issu321"
__license__ = "MIT"
__title__ = "HackBoard"
__description__ = "Professional Cybersecurity Intelligence Platform"
__url__ = "https://github.com/issu321/hackboard"

# Ensure config directories exist on import
from hackboard.utils import ensure_config_dirs

ensure_config_dirs()
