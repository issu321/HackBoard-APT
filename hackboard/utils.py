"""
HackBoard — Core Utilities Module
====================================

Validation, formatting, export, logging, event system, SOC feed,
terminal utilities, AI insight generator, and configuration helpers.
"""

import csv
import hashlib
import io
import json
import logging
import logging.handlers
import os
import random
import re
import string
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# ═══════════════════════════════════════════════════════════
# CONFIGURATION PATHS
# ═══════════════════════════════════════════════════════════


def get_config_dir() -> Path:
    """Return the HackBoard configuration directory."""
    config_dir = Path.home() / ".config" / "hackboard"
    return config_dir


def ensure_config_dirs() -> Path:
    """Create all required HackBoard configuration directories.

    Creates:
        ~/.config/hackboard/logs
        ~/.config/hackboard/reports
        ~/.config/hackboard/history
        ~/.config/hackboard/settings

    Returns:
        Path to the base config directory.
    """
    config_dir = get_config_dir()
    for subdir in ("logs", "reports", "history", "settings"):
        (config_dir / subdir).mkdir(parents=True, exist_ok=True)
    return config_dir


# ═══════════════════════════════════════════════════════════
# LOGGING SETUP
# ═══════════════════════════════════════════════════════════


def setup_logging(name: str = "hackboard", level: int = logging.INFO) -> logging.Logger:
    """Configure rotating file logging for HackBoard.

    Logs are written to ~/.config/hackboard/logs/hackboard.log
    with automatic rotation (5 backups, 5MB each).

    Args:
        name: Logger name.
        level: Logging level.

    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(level)
    logger.propagate = False

    ensure_config_dirs()
    log_path = get_config_dir() / "logs" / "hackboard.log"

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Rotating file handler
    file_handler = logging.handlers.RotatingFileHandler(
        log_path, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


logger = setup_logging()


# ═══════════════════════════════════════════════════════════
# VALIDATION UTILITIES
# ═══════════════════════════════════════════════════════════


def validate_ip(ip: str) -> bool:
    """Validate an IPv4 or IPv6 address string.

    Args:
        ip: IP address string to validate.

    Returns:
        True if valid IP, False otherwise.
    """
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_domain(domain: str) -> bool:
    """Validate a domain name format.

    Args:
        domain: Domain string to validate.

    Returns:
        True if valid domain, False otherwise.
    """
    pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
    return bool(re.match(pattern, domain) and "." in domain)


def validate_email(email: str) -> bool:
    """Validate an email address format.

    Args:
        email: Email string to validate.

    Returns:
        True if valid email, False otherwise.
    """
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


# ═══════════════════════════════════════════════════════════
# FORMATTING UTILITIES
# ═══════════════════════════════════════════════════════════


def format_bytes(size: int) -> str:
    """Convert bytes to a human-readable string.

    Args:
        size: Size in bytes.

    Returns:
        Human-readable size string (e.g., "1.50 MB").
    """
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} EB"


def format_duration(seconds: float) -> str:
    """Format a duration in human-readable form.

    Args:
        seconds: Duration in seconds.

    Returns:
        Formatted duration string.
    """
    if seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        return f"{seconds / 60:.2f}m"
    else:
        return f"{seconds / 3600:.2f}h"


def truncate_string(s: str, max_len: int = 100) -> str:
    """Truncate a string with ellipsis.

    Args:
        s: Input string.
        max_len: Maximum length before truncation.

    Returns:
        Truncated string.
    """
    return s if len(s) <= max_len else s[: max_len - 3] + "..."


# ═══════════════════════════════════════════════════════════
# EXPORT UTILITIES
# ═══════════════════════════════════════════════════════════


def export_to_csv(data: List[Dict[str, Any]], filename: str = "report.csv") -> bytes:
    """Export a list of dictionaries to CSV bytes.

    Args:
        data: List of dictionaries.
        filename: Unused (kept for API compatibility).

    Returns:
        CSV data as UTF-8 encoded bytes.
    """
    if not data:
        return b""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=data[0].keys())
    writer.writeheader()
    writer.writerows(data)
    return output.getvalue().encode("utf-8")


def export_to_json(data: Any, filename: str = "report.json") -> bytes:
    """Export data to JSON bytes.

    Args:
        data: Any serializable data.
        filename: Unused (kept for API compatibility).

    Returns:
        JSON data as UTF-8 encoded bytes.
    """
    return json.dumps(data, indent=2, default=str).encode("utf-8")


def export_to_txt(content: str, filename: str = "report.txt") -> bytes:
    """Export a string to TXT bytes.

    Args:
        content: Text content.
        filename: Unused (kept for API compatibility).

    Returns:
        Text data as UTF-8 encoded bytes.
    """
    return content.encode("utf-8")


def export_to_html(content: str, title: str = "HackBoard Report") -> bytes:
    """Export content as a styled HTML report.

    Args:
        content: HTML body content or plain text.
        title: Report title.

    Returns:
        HTML data as UTF-8 encoded bytes.
    """
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
body {{ font-family: 'Courier New', monospace; background: #0a0a0a; color: #e0e0e0; padding: 2rem; }}
h1 {{ color: #00f0ff; border-bottom: 2px solid #00f0ff; padding-bottom: 0.5rem; }}
pre {{ background: #111; padding: 1rem; border-left: 3px solid #00f0ff; overflow-x: auto; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
th, td {{ border: 1px solid #222; padding: 0.5rem; text-align: left; }}
th {{ background: #1a1a1a; color: #00f0ff; }}
tr:nth-child(even) {{ background: #111; }}
.footer {{ margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #222; color: #666; font-size: 0.8rem; }}
</style>
</head>
<body>
<h1>{title}</h1>
<pre>{content}</pre>
<div class="footer">Generated by HackBoard v1.0.0 | hackboard.dev</div>
</body>
</html>"""
    return html.encode("utf-8")


def generate_security_report(
    title: str,
    findings: List[Dict[str, Any]],
    recommendations: List[str],
    metadata: Dict[str, Any]
) -> str:
    """Generate a formatted security report text.

    Args:
        title: Report title.
        findings: List of finding dictionaries.
        recommendations: List of recommendation strings.
        metadata: Metadata dictionary.

    Returns:
        Formatted report string.
    """
    lines = [
        "=" * 70,
        "  HACKBOARD — SECURITY INTELLIGENCE REPORT",
        f"  {title}",
        "=" * 70,
        f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "  Platform: HackBoard — Cybersecurity Intelligence Platform",
        "  Developer: issu321 | https://github.com/issu321/hackboard",
        "=" * 70,
        "",
        "[METADATA]",
    ]
    for key, value in metadata.items():
        lines.append(f"  {key}: {value}")
    lines.extend(["", "[FINDINGS]", "-" * 70])
    for i, finding in enumerate(findings, 1):
        lines.append(f"  #{i}")
        for k, v in finding.items():
            lines.append(f"    {k}: {v}")
        lines.append("")
    lines.extend(["-" * 70, "", "[RECOMMENDATIONS]", "-" * 70])
    for i, rec in enumerate(recommendations, 1):
        lines.append(f"  {i}. {rec}")
    lines.extend(["", "=" * 70, "  END OF REPORT", "=" * 70])
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════
# LOGGING & EVENT SYSTEM
# ═══════════════════════════════════════════════════════════


def log_event(event_type: str, message: str, level: str = "info") -> Dict[str, Any]:
    """Log a security event and return the event dictionary.

    Args:
        event_type: Type of event (e.g., SCAN, WHOIS).
        message: Event message.
        level: Log level (critical, error, warning, info).

    Returns:
        Event dictionary.
    """
    event = {
        "timestamp": datetime.now().isoformat(),
        "type": event_type,
        "message": message,
        "level": level.upper()
    }
    log_func = getattr(logger, level.lower(), logger.info)
    log_func(f"[{event_type}] {message}")
    return event


def save_threat_log(event: Dict[str, Any], filepath: Optional[str] = None) -> None:
    """Append an event to the threat log JSON file.

    Args:
        event: Event dictionary to append.
        filepath: Custom path, or defaults to ~/.config/hackboard/history/threat_logs.json.
    """
    if filepath is None:
        ensure_config_dirs()
        filepath = str(get_config_dir() / "history" / "threat_logs.json")

    try:
        path = Path(filepath)
        data: List[Dict[str, Any]] = []
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        data.append(event)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    except Exception as e:
        logger.error(f"Failed to save threat log: {e}")


# ═══════════════════════════════════════════════════════════
# REPORT ARCHITECTURE
# ═══════════════════════════════════════════════════════════


def get_report_dir() -> Path:
    """Return the daily report directory path.

    Creates ~/.config/hackboard/reports/YYYY-MM-DD/ if needed.

    Returns:
        Path to the daily report directory.
    """
    today = datetime.now().strftime("%Y-%m-%d")
    report_dir = get_config_dir() / "reports" / today
    report_dir.mkdir(parents=True, exist_ok=True)
    return report_dir


def save_report(
    data: Any,
    title: str,
    report_type: str = "analysis",
    fmt: str = "json"
) -> Path:
    """Save a report to the daily report directory.

    Args:
        data: Report data.
        title: Report title (used in filename).
        report_type: Type of report.
        fmt: Export format (csv, json, txt, html).

    Returns:
        Path to the saved report file.
    """
    report_dir = get_report_dir()
    safe_title = re.sub(r"[^\w\-]", "_", title)[:50]
    timestamp = datetime.now().strftime("%H%M%S")
    filename = f"{safe_title}_{timestamp}.{fmt}"
    filepath = report_dir / filename

    if fmt == "csv":
        content = export_to_csv(data) if isinstance(data, list) else export_to_txt(str(data))
    elif fmt == "json":
        content = export_to_json(data)
    elif fmt == "html":
        content = export_to_html(str(data), title=title)
    else:
        content = export_to_txt(str(data))

    with open(filepath, "wb") as f:
        f.write(content)

    logger.info(f"Report saved: {filepath}")
    return filepath


# ═══════════════════════════════════════════════════════════
# FAKE SOC FEED GENERATOR
# ═══════════════════════════════════════════════════════════

_SOC_ALERTS: List[Tuple[str, str, str]] = [
    ("INTRUSION_DETECTION", "Suspicious login attempt blocked from {ip}", "warning"),
    ("FIREWALL", "Outbound connection to known C2 domain flagged: {domain}", "critical"),
    ("MALWARE_SCAN", "Heuristic match on file hash: {hash}", "warning"),
    ("NETWORK", "Anomalous traffic spike detected on port {port}", "warning"),
    ("AUTH", "Multiple failed authentication attempts from {ip}", "error"),
    ("SYSTEM", "Unexpected process elevation detected: {proc}", "critical"),
    ("DNS", "DNS tunneling pattern detected from {ip}", "error"),
    ("WEB", "SQL injection attempt blocked on endpoint /api/login", "warning"),
    ("EMAIL", "Phishing email campaign detected targeting internal users", "warning"),
    ("CRYPTO", "Cryptomining activity detected on host {ip}", "error"),
    ("PATCH", "Critical vulnerability CVE-2024-{cve} scan completed", "info"),
    ("AI_SOC", "AI anomaly model flagged behavioral deviation", "warning"),
]

_SOC_IPS = ["192.168.1.105", "10.0.0.23", "172.16.0.5", "203.0.113.44", "198.51.100.12"]
_SOC_DOMAINS = ["evil-c2.xyz", "phish-bank.tk", "darknet-node.onion", "malware-dl.cc"]
_SOC_PROCS = ["svch0st.exe", "crss.exe", "lsass_clone.exe", "winlogon_helper.exe"]


def generate_soc_alert() -> Dict[str, str]:
    """Generate a single fake SOC alert for educational simulation."""
    alert_type, template, level = random.choice(_SOC_ALERTS)
    msg = template.format(
        ip=random.choice(_SOC_IPS),
        domain=random.choice(_SOC_DOMAINS),
        hash=hashlib.md5(os.urandom(16)).hexdigest()[:16],
        port=random.choice([22, 23, 25, 53, 80, 443, 3389, 8080]),
        proc=random.choice(_SOC_PROCS),
        cve=random.randint(1000, 9999)
    )
    return {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "type": alert_type,
        "message": msg,
        "level": level.upper()
    }


def get_soc_feed(count: int = 20) -> List[Dict[str, str]]:
    """Generate multiple fake SOC alerts.

    Args:
        count: Number of alerts to generate.

    Returns:
        List of alert dictionaries.
    """
    random.seed(int(time.time() // 30))
    return [generate_soc_alert() for _ in range(count)]


# ═══════════════════════════════════════════════════════════
# TERMINAL / BOOT UTILITIES
# ═══════════════════════════════════════════════════════════


def get_banner() -> str:
    """Return the ASCII banner string."""
    banner_path = Path(__file__).parent / "assets" / "banner.txt"
    if banner_path.exists():
        return banner_path.read_text(encoding="utf-8")
    return """
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║     ██╗  ██╗ █████╗  ██████╗██╗  ██╗██████╗  ██████╗  █████╗ ██████╗  ║
║     ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔══██╗██╔═══██╗██╔══██╗██╔══██╗ ║
║     ███████║███████║██║     █████╔╝ ██████╔╝██║   ██║███████║██║  ██║ ║
║     ██╔══██║██╔══██║██║     ██╔═██╗ ██╔══██╗██║   ██║██╔══██║██║  ██║ ║
║     ██║  ██║██║  ██║╚██████╗██║  ██╗██████╔╝╚██████╔╝██║  ██║██████╔╝ ║
║     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝  ║
║                                                                      ║
║              CYBERSECURITY INTELLIGENCE PLATFORM                      ║
║                                                                      ║
║     Developed by issu321  |  github.com/issu321/hackboard            ║
╚══════════════════════════════════════════════════════════════════════╝
"""


def get_boot_sequence() -> List[str]:
    """Generate boot sequence lines for the terminal animation."""
    return [
        "[BOOT] Initializing HackBoard Kernel...",
        "[BOOT] Loading security modules...",
        "[BOOT] Mounting threat intelligence database...",
        "[BOOT] Initializing neural heuristic engine...",
        "[BOOT] Calibrating OSINT sensors...",
        "[BOOT] Loading packet analytics submodule...",
        "[BOOT] Establishing secure telemetry channel...",
        "[BOOT] Handshake with SOC grid: ESTABLISHED",
        "[BOOT] Threat feed synchronization: ACTIVE",
        "[BOOT] AI Security Insight Engine: ONLINE",
        "[BOOT] Cyber visualization engine: RENDERING",
        "[BOOT] System integrity check: PASSED",
        "[BOOT] All defensive modules armed.",
        "[BOOT] Welcome to HackBoard — Cybersecurity Intelligence Platform",
    ]


# ═══════════════════════════════════════════════════════════
# MISC HELPERS
# ═══════════════════════════════════════════════════════════


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data.

    Args:
        data: Byte data.

    Returns:
        Shannon entropy value.
    """
    from math import log2
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / length
        if p_x > 0:
            entropy -= p_x * log2(p_x)
    return entropy


def get_common_passwords() -> List[str]:
    """Return a list of common weak passwords for educational comparison."""
    return [
        "123456", "password", "12345678", "qwerty", "123456789",
        "letmein", "1234567", "football", "iloveyou", "admin",
        "welcome", "monkey", "login", "abc123", "111111",
        "123123", "password123", "1234", "baseball", "qwertyuiop"
    ]


def get_dangerous_extensions() -> List[str]:
    """Return potentially dangerous file extensions for educational warning."""
    return [
        ".exe", ".dll", ".bat", ".cmd", ".sh", ".bin",
        ".scr", ".msi", ".vbs", ".js", ".jar", ".ps1",
        ".php", ".asp", ".aspx", ".jsp", ".cgi", ".pl"
    ]


def safe_file_read(filepath: str, max_size: int = 10 * 1024 * 1024) -> Optional[bytes]:
    """Safely read a file with a size limit.

    Args:
        filepath: Path to the file.
        max_size: Maximum allowed file size in bytes.

    Returns:
        File contents or None if too large or unreadable.
    """
    try:
        size = os.path.getsize(filepath)
        if size > max_size:
            return None
        with open(filepath, "rb") as f:
            return f.read()
    except Exception:
        return None


def get_platform_info() -> Dict[str, str]:
    """Return basic platform information."""
    return {
        "system": os.name,
        "platform": sys.platform,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "cwd": os.getcwd(),
    }


# ═══════════════════════════════════════════════════════════
# COLOR / THEME UTILITIES
# ═══════════════════════════════════════════════════════════


def get_cyberpunk_css() -> str:
    """Return cyberpunk CSS for Streamlit injection."""
    css_path = Path(__file__).parent / "assets" / "styles.css"
    if css_path.exists():
        return f"<style>{css_path.read_text(encoding='utf-8')}</style>"
    return ""


def severity_color(severity: str) -> str:
    """Return a hex color for a severity level.

    Args:
        severity: Severity string.

    Returns:
        Hex color code.
    """
    colors = {
        "critical": "#ff0040",
        "high": "#ff4500",
        "medium": "#ffaa00",
        "low": "#00ff41",
        "info": "#00f0ff",
        "safe": "#00ff41",
        "warning": "#ffaa00",
        "error": "#ff0040",
    }
    return colors.get(severity.lower(), "#00f0ff")


def severity_badge(severity: str) -> str:
    """Return an HTML badge for a severity level.

    Args:
        severity: Severity string.

    Returns:
        HTML badge string.
    """
    color = severity_color(severity)
    return f"""
    <span style="
        background-color: {color}22;
        color: {color};
        border: 1px solid {color};
        border-radius: 4px;
        padding: 2px 8px;
        font-size: 0.75rem;
        font-weight: bold;
        text-transform: uppercase;
    ">{severity.upper()}</span>
    """


# ═══════════════════════════════════════════════════════════
# AI-LIKE INSIGHT GENERATOR
# ═══════════════════════════════════════════════════════════


def generate_ai_insight(context: str, metrics: Dict[str, Any]) -> str:
    """Generate an AI-like security insight based on context and metrics.

    Args:
        context: Analysis context (password, network, file, vulnerability, domain).
        metrics: Dictionary of relevant metrics.

    Returns:
        Insight string.
    """
    insights: List[str] = []

    if context == "password":
        score = metrics.get("score", 0)
        entropy = metrics.get("entropy", 0)
        if score < 30:
            insights.append(
                "Password exhibits critically low entropy and appears in common dictionary patterns. "
                "Immediate rotation recommended."
            )
        elif score < 60:
            insights.append(
                "Password entropy is moderate. Consider increasing length and adding special characters "
                "to resist brute-force attacks."
            )
        else:
            insights.append(
                "Password demonstrates strong entropy characteristics. Maintain this complexity standard "
                "across all credentials."
            )
        if entropy < 25:
            insights.append(
                "Shannon entropy analysis reveals predictable character distribution. Attackers using "
                "Markov chains could reduce cracking time significantly."
            )

    elif context == "network":
        open_ports = metrics.get("open_ports", [])
        risk_score = metrics.get("risk_score", 0)
        if len(open_ports) > 5:
            insights.append(
                f"Attack surface is expanded with {len(open_ports)} exposed services. "
                "Each open port represents a potential ingress vector."
            )
        if risk_score > 70:
            insights.append(
                "Network risk profile is elevated. Consider implementing additional segmentation "
                "and ingress filtering rules."
            )
        elif risk_score < 30:
            insights.append(
                "Network posture appears defensive. Minimal exposed services reduce lateral movement "
                "opportunities for adversaries."
            )

    elif context == "file":
        suspicious = metrics.get("suspicious", False)
        if suspicious:
            insights.append(
                "File extension and entropy analysis suggest potentially executable payload. "
                "Quarantine and sandbox analysis recommended."
            )
        else:
            insights.append(
                "File structure appears benign based on extension and entropy baseline. "
                "Standard defensive monitoring sufficient."
            )

    elif context == "vulnerability":
        count = metrics.get("count", 0)
        if count == 0:
            insights.append(
                "No simulated vulnerabilities detected in current scan scope. "
                "Maintain regular assessment cadence."
            )
        elif count > 5:
            insights.append(
                f"Concentration of {count} simulated vulnerabilities indicates systemic configuration drift. "
                "Prioritize patch management cycle."
            )
        else:
            insights.append(
                "Moderate vulnerability count detected. Address high-severity findings before "
                "medium and low priority items."
            )

    elif context == "domain":
        age_days = metrics.get("age_days", 0)
        if age_days < 30:
            insights.append(
                "Domain registration is recent. Phishing campaigns frequently utilize newly registered domains. "
                "Elevate monitoring."
            )
        else:
            insights.append(
                "Domain exhibits established registration history. Reputation-based filtering likely "
                "permits standard traffic."
            )

    else:
        insights.append(
            "Security metrics analyzed. Maintain defense-in-depth strategy with layered controls."
        )

    return " ".join(insights)


# ═══════════════════════════════════════════════════════════
# SESSION / STATE HELPERS
# ═══════════════════════════════════════════════════════════


def init_session_state(st_module: Any, defaults: Dict[str, Any]) -> None:
    """Initialize Streamlit session state variables.

    Args:
        st_module: The streamlit module (st).
        defaults: Dictionary of default values.
    """
    for key, val in defaults.items():
        if key not in st_module.session_state:
            st_module.session_state[key] = val


# ═══════════════════════════════════════════════════════════
# PLUGIN ARCHITECTURE
# ═══════════════════════════════════════════════════════════


def discover_plugins(plugin_dir: Optional[Path] = None) -> List[Any]:
    """Discover and load plugins from the plugins directory.

    Every Python file in the plugins directory is imported dynamically.

    Args:
        plugin_dir: Custom plugin directory, or defaults to hackboard/plugins/.

    Returns:
        List of loaded plugin module objects.
    """
    if plugin_dir is None:
        plugin_dir = Path(__file__).parent / "plugins"

    plugins: List[Any] = []
    if not plugin_dir.exists():
        logger.warning(f"Plugin directory not found: {plugin_dir}")
        return plugins

    for file_path in sorted(plugin_dir.glob("*.py")):
        if file_path.name.startswith("_"):
            continue
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location(file_path.stem, file_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                plugins.append(module)
                logger.info(f"Plugin loaded: {file_path.name}")
        except Exception as e:
            logger.error(f"Failed to load plugin {file_path.name}: {e}")

    return plugins
