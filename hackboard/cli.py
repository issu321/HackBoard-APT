"""
HackBoard — Command-Line Interface
====================================

Provides the `hackboard` command to launch the Streamlit dashboard
or run tools directly from the terminal.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from hackboard.utils import get_banner, ensure_config_dirs, logger


def get_app_path() -> Path:
    """Return the path to the main Streamlit application script."""
    return Path(__file__).parent / "app.py"


def launch_streamlit(
    app_path: Optional[Path] = None,
    port: int = 8501,
    host: str = "localhost",
    headless: bool = False,
    no_browser: bool = False,
) -> int:
    """Launch the HackBoard Streamlit dashboard.

    Args:
        app_path: Path to the Streamlit app script.
        port: Server port.
        host: Server host.
        headless: Run in headless mode.
        no_browser: Do not open browser automatically.

    Returns:
        Exit code from the subprocess.
    """
    if app_path is None:
        app_path = get_app_path()

    if not app_path.exists():
        logger.error(f"Application script not found: {app_path}")
        print(f"[ERROR] Application script not found: {app_path}", file=sys.stderr)
        return 1

    ensure_config_dirs()

    cmd: List[str] = [
        sys.executable, "-m", "streamlit", "run",
        str(app_path),
        "--server.port", str(port),
        "--server.address", host,
    ]

    if headless:
        cmd.extend(["--server.headless", "true"])
    if no_browser:
        cmd.extend(["--browser.gatherUsageStats", "false"])

    logger.info(f"Launching HackBoard on http://{host}:{port}")
    print(get_banner())
    print(f"🚀 Starting HackBoard on http://{host}:{port}")
    print("=" * 60)

    try:
        result = subprocess.run(cmd, check=False)
        return result.returncode
    except KeyboardInterrupt:
        print("\n👋 HackBoard stopped by user.")
        return 0
    except Exception as e:
        logger.error(f"Failed to launch HackBoard: {e}")
        print(f"[ERROR] Failed to launch: {e}", file=sys.stderr)
        return 1


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entry point for HackBoard.

    Args:
        argv: Command-line arguments.

    Returns:
        Exit code.
    """
    parser = argparse.ArgumentParser(
        prog="hackboard",
        description="HackBoard — Professional Cybersecurity Intelligence Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  hackboard                    Launch the dashboard (default)
  hackboard --port 8080        Launch on port 8080
  hackboard --host 0.0.0.0     Bind to all interfaces
  hackboard --no-browser       Launch without opening browser
  hackboard --version          Show version
        """
    )

    parser.add_argument(
        "--version", "-v",
        action="version",
        version="%(prog)s 1.0.0"
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=8501,
        help="Port to run the Streamlit server on (default: 8501)"
    )
    parser.add_argument(
        "--host", "-H",
        type=str,
        default="localhost",
        help="Host to bind the server to (default: localhost)"
    )
    parser.add_argument(
        "--no-browser", "-n",
        action="store_true",
        help="Do not open browser automatically"
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run in headless mode (no browser, no UI prompts)"
    )
    parser.add_argument(
        "--config-dir",
        action="store_true",
        help="Print the configuration directory path and exit"
    )

    args = parser.parse_args(argv)

    if args.config_dir:
        config_dir = ensure_config_dirs()
        print(config_dir)
        return 0

    return launch_streamlit(
        port=args.port,
        host=args.host,
        headless=args.headless,
        no_browser=args.no_browser,
    )


if __name__ == "__main__":
    sys.exit(main())
