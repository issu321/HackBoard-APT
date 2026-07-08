
"""
HackBoard — Security Tools Module
==================================

Core security utilities: network scanning, password analysis, cryptographic
hashing, file security analysis, vulnerability simulation, packet analytics,
and system monitoring. All tools are SAFE, EDUCATIONAL, and DEFENSIVE-only.

Author: issu321
License: MIT
"""

import hashlib
import math
import os
import random
import re
import socket
import string
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

from hackboard.utils import (
    calculate_entropy,
    get_common_passwords,
    get_dangerous_extensions,
    log_event,
    validate_domain,
    validate_ip,
)

# Optional imports with graceful fallbacks
try:
    import psutil
    PSUTIL_AVAILABLE: bool = True
except ImportError:
    PSUTIL_AVAILABLE = False

# ═══════════════════════════════════════════════════════════
# NETWORK SCANNER (SAFE EDUCATIONAL)
# ═══════════════════════════════════════════════════════════

COMMON_PORTS: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
    6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached"
}

PORT_SEVERITY: Dict[int, str] = {
    21: "medium", 22: "low", 23: "critical", 25: "medium", 53: "low",
    80: "low", 110: "medium", 143: "medium", 443: "low", 445: "high",
    3306: "medium", 3389: "high", 5432: "medium", 5900: "high",
    8080: "medium", 8443: "low", 27017: "medium", 6379: "medium",
    9200: "medium", 11211: "high"
}


def scan_port(ip: str, port: int, timeout: float = 1.0) -> Dict[str, Any]:
    """Scan a single TCP port using a connect attempt.

    This is a safe, educational scanner that only attempts a TCP
    connection without sending any payload data.

    Args:
        ip: Target IP address.
        port: Target port number.
        timeout: Connection timeout in seconds.

    Returns:
        Dictionary with scan results including state, service, severity,
        latency, and banner (if available).
    """
    result: Dict[str, Any] = {
        "ip": ip,
        "port": port,
        "state": "closed",
        "service": COMMON_PORTS.get(port, "Unknown"),
        "severity": PORT_SEVERITY.get(port, "info"),
        "latency_ms": None,
        "banner": None,
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    start = time.time()

    try:
        code = sock.connect_ex((ip, port))
        latency = (time.time() - start) * 1000
        result["latency_ms"] = round(latency, 2)

        if code == 0:
            result["state"] = "open"
            # Safe banner grab — just peek, no full protocol exchange
            try:
                sock.settimeout(1.0)
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                if banner:
                    result["banner"] = banner[:200]
            except Exception:
                pass
        else:
            result["state"] = "closed"
    except socket.timeout:
        result["state"] = "filtered"
    except Exception as e:
        result["state"] = "error"
        result["error"] = str(e)
    finally:
        sock.close()

    return result


def scan_ports(
    ip: str,
    ports: Optional[List[int]] = None,
    max_workers: int = 50,
    timeout: float = 1.0,
) -> Dict[str, Any]:
    """Scan multiple TCP ports concurrently using threading.

    Args:
        ip: Target IP address.
        ports: List of ports to scan. Defaults to COMMON_PORTS keys.
        max_workers: Maximum number of concurrent threads.
        timeout: Connection timeout per port in seconds.

    Returns:
        Dictionary with complete scan results, open/closed/filtered lists,
        risk score, and scan duration.
    """
    if not validate_ip(ip):
        return {"error": "Invalid IP address", "ip": ip}

    if ports is None:
        ports = list(COMMON_PORTS.keys())

    result: Dict[str, Any] = {
        "ip": ip,
        "timestamp": datetime.now().isoformat(),
        "ports_scanned": len(ports),
        "open_ports": [],
        "closed_ports": [],
        "filtered_ports": [],
        "all_results": [],
        "risk_score": 0,
        "scan_duration_ms": 0,
    }

    start = time.time()
    open_count = 0
    high_risk_ports: List[Dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_port, ip, port, timeout): port for port in ports
        }
        for future in as_completed(future_to_port):
            port_result = future.result()
            result["all_results"].append(port_result)

            if port_result["state"] == "open":
                result["open_ports"].append(port_result)
                open_count += 1
                if port_result["severity"] in ("high", "critical"):
                    high_risk_ports.append(port_result)
            elif port_result["state"] == "closed":
                result["closed_ports"].append(port_result)
            else:
                result["filtered_ports"].append(port_result)

    result["scan_duration_ms"] = round((time.time() - start) * 1000, 2)

    # Educational risk score calculation
    risk = min(100, open_count * 8 + len(high_risk_ports) * 15)
    result["risk_score"] = risk
    result["high_risk_ports"] = high_risk_ports

    log_event("SCAN", f"Scanned {ip}: {open_count} open ports, risk={risk}", "info")
    return result


def discover_hosts(network: str, timeout: float = 0.5) -> Dict[str, Any]:
    """Discover active hosts in a network range.

    Educational simulation with TCP port 80 probes.

    Args:
        network: Network range in CIDR notation (e.g., "192.168.1.0/24").
        timeout: Probe timeout in seconds.

    Returns:
        Dictionary with active hosts and scan statistics.
    """
    result: Dict[str, Any] = {
        "network": network,
        "timestamp": datetime.now().isoformat(),
        "active_hosts": [],
        "total_scanned": 0,
    }

    try:
        import ipaddress
        net = ipaddress.ip_network(network, strict=False)
        hosts = list(net.hosts())[:254]  # Safety limit for education
        result["total_scanned"] = len(hosts)

        for host in hosts:
            ip = str(host)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                code = sock.connect_ex((ip, 80))
                sock.close()
                # Open or actively refused = host is up
                if code == 0 or code == 111:
                    result["active_hosts"].append({
                        "ip": ip,
                        "status": "active",
                        "method": "TCP-80",
                    })
            except Exception:
                pass
    except Exception as e:
        result["error"] = str(e)

    return result


# ═══════════════════════════════════════════════════════════
# PASSWORD STRENGTH ANALYZER
# ═══════════════════════════════════════════════════════════

# Pre-compiled regex patterns for performance
_RE_LOWER = re.compile(r"[a-z]")
_RE_UPPER = re.compile(r"[A-Z]")
_RE_DIGIT = re.compile(r"[0-9]")
_RE_SPECIAL = re.compile(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]")
_RE_SEQ_LETTERS = re.compile(
    r"(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|"
    r"nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)"
)
_RE_SEQ_NUMBERS = re.compile(r"(012|123|234|345|456|567|678|789|890)")
_RE_REPEATED = re.compile(r"(.)\1{2,}")
_RE_YEAR = re.compile(r"(19|20)\d{2}")

_KEYBOARD_PATTERNS = ["qwerty", "asdfgh", "zxcvbn", "qazwsx", "!@#$%"]


def analyze_password(password: str) -> Dict[str, Any]:
    """Analyze password strength with entropy and pattern detection.

    Evaluates length, character diversity, entropy, common password
    matching, sequential patterns, keyboard patterns, and date patterns.

    Args:
        password: The password string to analyze.

    Returns:
        Dictionary with score (0-100), entropy, complexity flags,
        detected patterns, and recommendations.
    """
    result: Dict[str, Any] = {
        "password_length": len(password),
        "entropy": 0.0,
        "entropy_bits": 0.0,
        "score": 0,
        "strength_label": "",
        "complexity": {
            "has_lower": False,
            "has_upper": False,
            "has_digit": False,
            "has_special": False,
            "has_space": False,
        },
        "patterns_found": [],
        "recommendations": [],
        "common_password_match": False,
        "character_distribution": {},
    }

    if not password:
        result["strength_label"] = "Empty"
        result["recommendations"].append("Password cannot be empty.")
        return result

    # Character analysis
    has_lower = bool(_RE_LOWER.search(password))
    has_upper = bool(_RE_UPPER.search(password))
    has_digit = bool(_RE_DIGIT.search(password))
    has_special = bool(_RE_SPECIAL.search(password))
    has_space = " " in password

    result["complexity"]["has_lower"] = has_lower
    result["complexity"]["has_upper"] = has_upper
    result["complexity"]["has_digit"] = has_digit
    result["complexity"]["has_special"] = has_special
    result["complexity"]["has_space"] = has_space

    # Pool size calculation
    pool = 0
    if has_lower:
        pool += 26
    if has_upper:
        pool += 26
    if has_digit:
        pool += 10
    if has_special:
        pool += 33
    if has_space:
        pool += 1
    if pool == 0:
        pool = 1

    # Entropy calculation
    length = len(password)
    result["entropy_bits"] = round(length * math.log2(pool), 2)
    result["entropy"] = result["entropy_bits"]

    # Score calculation
    score = 0
    score += min(30, length * 2)  # Length up to 30 points
    score += 10 if has_lower else 0
    score += 10 if has_upper else 0
    score += 10 if has_digit else 0
    score += 15 if has_special else 0
    score += min(25, int(result["entropy_bits"] / 4))  # Entropy bonus

    # Pattern detection and penalties
    patterns: List[str] = []
    pwd_lower = password.lower()

    # Common password check
    common = get_common_passwords()
    if pwd_lower in common:
        patterns.append("Common password dictionary match")
        score -= 40
        result["common_password_match"] = True

    # Sequential characters
    if _RE_SEQ_LETTERS.search(pwd_lower):
        patterns.append("Sequential letters detected")
        score -= 10

    if _RE_SEQ_NUMBERS.search(password):
        patterns.append("Sequential numbers detected")
        score -= 10

    # Repeated characters
    if _RE_REPEATED.search(password):
        patterns.append("Repeated characters detected")
        score -= 10

    # Keyboard patterns
    for pat in _KEYBOARD_PATTERNS:
        if pat in pwd_lower:
            patterns.append(f"Keyboard pattern: {pat}")
            score -= 15
            break

    # Date patterns
    if _RE_YEAR.search(password):
        patterns.append("Year pattern detected")
        score -= 5

    # Length-based recommendations
    if length < 8:
        patterns.append("Length below 8 characters")
        score -= 20
        result["recommendations"].append(
            "Increase password length to at least 12 characters."
        )
    elif length < 12:
        result["recommendations"].append(
            "Consider increasing length to 16+ characters for optimal security."
        )

    if not has_special:
        result["recommendations"].append(
            "Add special characters (!@#$%^&* etc.) to increase entropy."
        )
    if not has_digit:
        result["recommendations"].append(
            "Include numeric digits to resist dictionary attacks."
        )
    if not has_upper or not has_lower:
        result["recommendations"].append(
            "Use mixed case (upper and lower) letters."
        )

    if not patterns:
        result["recommendations"].append(
            "Password structure appears complex. Ensure it is also memorable "
            "or stored in a password manager."
        )

    result["patterns_found"] = patterns
    result["score"] = max(0, min(100, score))

    # Strength label
    s = result["score"]
    if s < 20:
        result["strength_label"] = "Very Weak"
    elif s < 40:
        result["strength_label"] = "Weak"
    elif s < 60:
        result["strength_label"] = "Moderate"
    elif s < 80:
        result["strength_label"] = "Strong"
    else:
        result["strength_label"] = "Very Strong"

    # Character distribution
    dist: Dict[str, int] = {}
    for char in password:
        dist[char] = dist.get(char, 0) + 1
    result["character_distribution"] = dist

    return result


# ═══════════════════════════════════════════════════════════
# HASHING LABORATORY
# ═══════════════════════════════════════════════════════════

HASH_ALGORITHMS: Dict[str, Any] = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
    "sha3_256": hashlib.sha3_256,
    "sha3_512": hashlib.sha3_512,
    "blake2b": hashlib.blake2b,
    "blake2s": hashlib.blake2s,
}


def _get_hasher(algorithm: str) -> Any:
    """Resolve a hash algorithm name to a hashlib constructor.

    Args:
        algorithm: Algorithm name (case-insensitive, hyphens converted).

    Returns:
        Hash constructor callable.

    Raises:
        ValueError: If the algorithm is not supported.
    """
    algo = algorithm.lower().replace("-", "_")
    if algo not in HASH_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm: {algorithm}. "
            f"Supported: {list(HASH_ALGORITHMS.keys())}"
        )
    return HASH_ALGORITHMS[algo]


def hash_text(text: str, algorithm: str = "sha256") -> Dict[str, Any]:
    """Hash text with the specified algorithm.

    Args:
        text: Input text to hash.
        algorithm: Hash algorithm name.

    Returns:
        Dictionary with algorithm, hash hex digest, and metadata.
    """
    hasher = _get_hasher(algorithm)()
    hasher.update(text.encode("utf-8"))

    return {
        "input_type": "text",
        "algorithm": algorithm.upper(),
        "hash": hasher.hexdigest(),
        "length": hasher.digest_size * 8,
        "timestamp": datetime.now().isoformat(),
    }


def hash_file(file_content: bytes, algorithm: str = "sha256") -> Dict[str, Any]:
    """Hash file bytes with the specified algorithm.

    Args:
        file_content: Raw file bytes.
        algorithm: Hash algorithm name.

    Returns:
        Dictionary with algorithm, hash hex digest, size, and metadata.
    """
    hasher = _get_hasher(algorithm)()
    hasher.update(file_content)

    return {
        "input_type": "file",
        "algorithm": algorithm.upper(),
        "hash": hasher.hexdigest(),
        "size_bytes": len(file_content),
        "length": hasher.digest_size * 8,
        "timestamp": datetime.now().isoformat(),
    }


def verify_hash(
    data: Union[str, bytes], algorithm: str, expected_hash: str
) -> Dict[str, Any]:
    """Verify data against an expected hash.

    Args:
        data: Text string or bytes to hash.
        algorithm: Hash algorithm name.
        expected_hash: Expected hex digest.

    Returns:
        Dictionary with match result, expected and actual hashes.
    """
    if isinstance(data, str):
        result = hash_text(data, algorithm)
    else:
        result = hash_file(data, algorithm)

    actual = result["hash"]
    expected = expected_hash.lower().strip()

    return {
        "algorithm": algorithm.upper(),
        "expected_hash": expected,
        "actual_hash": actual,
        "match": actual == expected,
        "timestamp": datetime.now().isoformat(),
    }


# ═══════════════════════════════════════════════════════════
# FILE SECURITY ANALYZER
# ═══════════════════════════════════════════════════════════


def analyze_file_security(file_content: bytes, filename: str) -> Dict[str, Any]:
    """Perform comprehensive file security analysis.

    Analyzes extensions, magic bytes, MIME types, entropy, and size
    to determine risk level. Educational and defensive only.

    Args:
        file_content: Raw file bytes.
        filename: Original filename.

    Returns:
        Dictionary with security analysis results and risk assessment.
    """
    from hackboard.osint_tools import extract_file_metadata

    result = extract_file_metadata(file_content, filename)
    result["timestamp"] = datetime.now().isoformat()
    result["suspicious"] = False
    result["risk_level"] = "Low"
    result["risk_score"] = 0
    result["warnings"] = []
    result["recommendations"] = []

    ext = result.get("extension", "")
    dangerous = [e.lstrip(".") for e in get_dangerous_extensions()]

    # Extension analysis
    if ext in dangerous:
        result["suspicious"] = True
        result["warnings"].append(f"Potentially dangerous extension: .{ext}")
        result["risk_score"] += 30

    # Entropy analysis
    entropy = result.get("entropy", 0)
    if entropy > 7.5 and ext in dangerous:
        result["warnings"].append(
            "High entropy in executable file. Possible packing/encryption."
        )
        result["risk_score"] += 25
        result["suspicious"] = True
    elif entropy > 7.0:
        result["warnings"].append(
            "High entropy detected. May be compressed or encrypted."
        )
        result["risk_score"] += 10
    elif entropy < 1.0 and len(file_content) > 100:
        result["warnings"].append(
            "Very low entropy. Possible plaintext credential file or config dump."
        )
        result["risk_score"] += 15

    # Size analysis
    size = len(file_content)
    if size == 0:
        result["warnings"].append("File is empty.")
        result["risk_score"] += 5
    elif size > 100 * 1024 * 1024:
        result["warnings"].append(
            "File exceeds 100MB. Large files may contain embedded payloads."
        )
        result["risk_score"] += 10

    # MIME mismatch detection
    mime = result.get("mime_guess")
    if mime and ext:
        mime_ext_map: Dict[str, List[str]] = {
            "image/png": ["png"],
            "image/jpeg": ["jpg", "jpeg"],
            "image/gif": ["gif"],
            "application/pdf": ["pdf"],
            "application/zip": ["zip"],
            "application/x-elf": ["elf"],
            "application/x-dosexec": ["exe", "dll", "scr"],
        }
        expected_exts = mime_ext_map.get(mime, [])
        if expected_exts and ext not in expected_exts:
            result["warnings"].append(
                f"Extension .{ext} does not match detected MIME type {mime}."
            )
            result["risk_score"] += 20
            result["suspicious"] = True

    # Magic bytes for Windows executables
    magic = result.get("magic_bytes", "")
    if magic and magic.startswith("4D5A") and ext not in ("exe", "dll", "scr", "msi"):
        result["warnings"].append(
            "Windows executable magic bytes detected but extension is not .exe/.dll."
        )
        result["risk_score"] += 35
        result["suspicious"] = True

    # Risk level determination
    if result["risk_score"] >= 60:
        result["risk_level"] = "Critical"
    elif result["risk_score"] >= 40:
        result["risk_level"] = "High"
    elif result["risk_score"] >= 20:
        result["risk_level"] = "Medium"
    else:
        result["risk_level"] = "Low"

    # Recommendations
    if result["warnings"]:
        result["recommendations"].append(
            "Review all warnings before executing or processing this file."
        )
    if result["suspicious"]:
        result["recommendations"].extend([
            "Consider submitting to sandbox environment for dynamic analysis.",
            "Quarantine file until classification is complete.",
        ])
    else:
        result["recommendations"].append(
            "File appears low-risk based on static analysis. Continue with standard procedures."
        )

    return result


# ═══════════════════════════════════════════════════════════
# VULNERABILITY ASSESSMENT SIMULATION
# ═══════════════════════════════════════════════════════════

SIMULATED_VULNERABILITIES: List[Dict[str, Any]] = [
    {
        "id": "SIM-001",
        "name": "Exposed Telnet Service",
        "description": (
            "Telnet (port 23) is open. Telnet transmits data in plaintext "
            "including credentials."
        ),
        "severity": "critical",
        "cvss_simulated": 9.8,
        "port": 23,
        "recommendation": (
            "Disable Telnet and migrate to SSH with key-based authentication."
        ),
    },
    {
        "id": "SIM-002",
        "name": "Open RDP Without NLA",
        "description": (
            "Remote Desktop Protocol exposed. Brute-force and BlueKeep-style "
            "attacks possible."
        ),
        "severity": "high",
        "cvss_simulated": 8.5,
        "port": 3389,
        "recommendation": (
            "Enable Network Level Authentication. Restrict access via VPN or firewall rules."
        ),
    },
    {
        "id": "SIM-003",
        "name": "SMBv1 Exposure",
        "description": (
            "SMB service detected. Legacy SMBv1 is vulnerable to EternalBlue "
            "and similar exploits."
        ),
        "severity": "high",
        "cvss_simulated": 8.1,
        "port": 445,
        "recommendation": (
            "Disable SMBv1. Ensure SMB signing is enabled. Apply latest security patches."
        ),
    },
    {
        "id": "SIM-004",
        "name": "Unsecured VNC Access",
        "description": (
            "VNC service without authentication allows remote desktop control."
        ),
        "severity": "critical",
        "cvss_simulated": 9.5,
        "port": 5900,
        "recommendation": (
            "Enable VNC authentication with strong password. Tunnel through SSH or VPN."
        ),
    },
    {
        "id": "SIM-005",
        "name": "Memcached Without Authentication",
        "description": (
            "Memcached exposed. Can be abused for amplification DDoS attacks."
        ),
        "severity": "high",
        "cvss_simulated": 7.5,
        "port": 11211,
        "recommendation": (
            "Bind Memcached to localhost or enable SASL authentication. Firewall egress."
        ),
    },
    {
        "id": "SIM-006",
        "name": "Default/FTP Anonymous Access",
        "description": (
            "FTP service may allow anonymous login. Data exfiltration risk."
        ),
        "severity": "medium",
        "cvss_simulated": 6.5,
        "port": 21,
        "recommendation": (
            "Disable anonymous FTP. Use SFTP or FTPS with strong authentication."
        ),
    },
    {
        "id": "SIM-007",
        "name": "Outdated SSH Version",
        "description": (
            "SSH service detected. Older versions may be vulnerable to Terrapin "
            "or similar."
        ),
        "severity": "medium",
        "cvss_simulated": 5.9,
        "port": 22,
        "recommendation": (
            "Update OpenSSH to latest stable. Disable weak ciphers and algorithms."
        ),
    },
    {
        "id": "SIM-008",
        "name": "HTTP Without HTTPS Redirect",
        "description": (
            "Plain HTTP service active. Data transmitted without encryption."
        ),
        "severity": "medium",
        "cvss_simulated": 5.3,
        "port": 80,
        "recommendation": (
            "Implement HTTPS with HSTS. Redirect all HTTP traffic to HTTPS."
        ),
    },
    {
        "id": "SIM-009",
        "name": "Elasticsearch Exposure",
        "description": (
            "Elasticsearch API exposed without authentication. Data leakage risk."
        ),
        "severity": "high",
        "cvss_simulated": 7.8,
        "port": 9200,
        "recommendation": (
            "Enable X-Pack security. Bind to localhost or internal network only."
        ),
    },
    {
        "id": "SIM-010",
        "name": "Redis Without Authentication",
        "description": (
            "Redis instance exposed. Can lead to remote code execution via "
            "module loading."
        ),
        "severity": "critical",
        "cvss_simulated": 9.1,
        "port": 6379,
        "recommendation": (
            "Enable requirepass and protected-mode. Bind to localhost or use Unix socket."
        ),
    },
]


def simulate_vulnerability_assessment(
    scan_results: Dict[str, Any]
) -> Dict[str, Any]:
    """Simulate vulnerability assessment based on port scan results.

    Maps open ports to known simulated vulnerabilities for educational
    visualization. No actual exploitation is performed.

    Args:
        scan_results: Dictionary from scan_ports() containing open_ports.

    Returns:
        Dictionary with vulnerability findings, summary, CVSS scores,
        risk level, and recommendations.
    """
    result: Dict[str, Any] = {
        "timestamp": datetime.now().isoformat(),
        "target": scan_results.get("ip", "unknown"),
        "vulnerabilities": [],
        "summary": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "total": 0,
        },
        "overall_cvss": 0.0,
        "risk_level": "Low",
        "recommendations": [],
    }

    open_ports = {p["port"]: p for p in scan_results.get("open_ports", [])}

    for vuln in SIMULATED_VULNERABILITIES:
        if vuln["port"] in open_ports:
            finding = vuln.copy()
            finding["detected_on"] = open_ports[vuln["port"]]
            result["vulnerabilities"].append(finding)
            result["summary"][vuln["severity"]] += 1
            result["summary"]["total"] += 1

    # Calculate overall simulated CVSS
    if result["vulnerabilities"]:
        total_cvss = sum(v["cvss_simulated"] for v in result["vulnerabilities"])
        result["overall_cvss"] = round(
            total_cvss / len(result["vulnerabilities"]), 1
        )

    # Risk level determination
    summary = result["summary"]
    if summary["critical"] > 0:
        result["risk_level"] = "Critical"
    elif summary["high"] > 0:
        result["risk_level"] = "High"
    elif summary["medium"] > 0:
        result["risk_level"] = "Medium"
    elif summary["low"] > 0:
        result["risk_level"] = "Low"
    else:
        result["risk_level"] = "Info"

    # Aggregate unique recommendations
    all_recs = list(set(
        v["recommendation"] for v in result["vulnerabilities"]
    ))
    result["recommendations"] = all_recs

    if not result["vulnerabilities"]:
        result["recommendations"].append(
            "No simulated vulnerabilities detected. Maintain regular scanning cadence."
        )

    return result


# ═══════════════════════════════════════════════════════════
# PACKET ANALYTICS (SAFE EDUCATIONAL)
# ═══════════════════════════════════════════════════════════


def get_packet_analytics() -> Dict[str, Any]:
    """Generate safe packet/network analytics using psutil.

    Falls back to simulated data if psutil is unavailable or permissions
    are insufficient.

    Returns:
        Dictionary with interface stats, connections, protocol distribution,
        and traffic statistics.
    """
    result: Dict[str, Any] = {
        "timestamp": datetime.now().isoformat(),
        "interfaces": [],
        "connections": [],
        "protocol_distribution": {},
        "traffic_stats": {},
        "packet_simulation": {},
    }

    if not PSUTIL_AVAILABLE:
        result["error"] = "psutil not installed. Run: pip install psutil"
        result["packet_simulation"] = generate_simulated_packet_data()
        return result

    try:
        # Network IO counters per interface
        io_stats = psutil.net_io_counters(pernic=True)
        for iface, stats in io_stats.items():
            result["interfaces"].append({
                "name": iface,
                "bytes_sent": stats.bytes_sent,
                "bytes_recv": stats.bytes_recv,
                "packets_sent": stats.packets_sent,
                "packets_recv": stats.packets_recv,
                "err_in": stats.errin,
                "err_out": stats.errout,
                "drop_in": stats.dropin,
                "drop_out": stats.dropout,
            })

        # Active connections
        try:
            conns = psutil.net_connections(kind="inet")
            for conn in conns[:50]:  # Limit for performance
                result["connections"].append({
                    "fd": conn.fd,
                    "family": str(conn.family),
                    "type": str(conn.type),
                    "local_addr": (
                        f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None
                    ),
                    "remote_addr": (
                        f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None
                    ),
                    "status": conn.status,
                    "pid": conn.pid,
                })
        except (psutil.AccessDenied, PermissionError):
            result["connections_error"] = (
                "Permission denied. Run with elevated privileges to view connections."
            )

        # Protocol distribution
        proto_dist: Dict[str, int] = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        for conn in result["connections"]:
            if conn["type"] == "SocketKind.SOCK_STREAM":
                proto_dist["TCP"] += 1
            elif conn["type"] == "SocketKind.SOCK_DGRAM":
                proto_dist["UDP"] += 1
            else:
                proto_dist["Other"] += 1

        if sum(proto_dist.values()) == 0:
            proto_dist = {"TCP": 65, "UDP": 25, "ICMP": 8, "Other": 2}

        result["protocol_distribution"] = proto_dist

        # Traffic stats summary
        total_sent = sum(i["bytes_sent"] for i in result["interfaces"])
        total_recv = sum(i["bytes_recv"] for i in result["interfaces"])
        result["traffic_stats"] = {
            "total_bytes_sent": total_sent,
            "total_bytes_recv": total_recv,
            "total_packets_sent": sum(i["packets_sent"] for i in result["interfaces"]),
            "total_packets_recv": sum(i["packets_recv"] for i in result["interfaces"]),
        }

    except Exception as e:
        result["error"] = str(e)
        result["packet_simulation"] = generate_simulated_packet_data()

    return result


def generate_simulated_packet_data() -> Dict[str, Any]:
    """Generate simulated packet data for educational visualization.

    Used when psutil is unavailable or permissions are insufficient.

    Returns:
        Dictionary with simulated protocol distribution, packet sizes,
        top ports, and bandwidth.
    """
    random.seed(int(time.time() // 60))
    return {
        "note": "Simulated data for educational visualization.",
        "protocol_distribution": {
            "TCP": random.randint(50, 80),
            "UDP": random.randint(15, 35),
            "ICMP": random.randint(2, 10),
            "ARP": random.randint(1, 5),
            "Other": random.randint(1, 5),
        },
        "packet_sizes": {
            "64-127": random.randint(100, 500),
            "128-255": random.randint(200, 800),
            "256-511": random.randint(150, 600),
            "512-1023": random.randint(100, 400),
            "1024-1518": random.randint(50, 300),
        },
        "top_ports": [
            {"port": 443, "count": random.randint(1000, 5000), "service": "HTTPS"},
            {"port": 80, "count": random.randint(500, 2000), "service": "HTTP"},
            {"port": 53, "count": random.randint(300, 1500), "service": "DNS"},
            {"port": 22, "count": random.randint(50, 300), "service": "SSH"},
            {"port": 123, "count": random.randint(20, 100), "service": "NTP"},
        ],
        "bandwidth_mbps": round(random.uniform(10, 500), 2),
    }


# ═══════════════════════════════════════════════════════════
# SYSTEM MONITOR
# ═══════════════════════════════════════════════════════════


def get_system_monitor_data() -> Dict[str, Any]:
    """Gather system resource usage data.

    Uses psutil when available. Returns CPU, memory, disk, network,
    process, boot time, and user information.

    Returns:
        Dictionary with comprehensive system telemetry.
    """
    result: Dict[str, Any] = {
        "timestamp": datetime.now().isoformat(),
        "cpu": {},
        "memory": {},
        "disk": {},
        "network": {},
        "processes": [],
        "boot_time": None,
        "users": [],
    }

    if not PSUTIL_AVAILABLE:
        result["error"] = "psutil not installed. Run: pip install psutil"
        return result

    try:
        # CPU
        result["cpu"]["percent"] = psutil.cpu_percent(interval=0.5)
        result["cpu"]["count_physical"] = psutil.cpu_count(logical=False)
        result["cpu"]["count_logical"] = psutil.cpu_count(logical=True)
        freq = psutil.cpu_freq()
        result["cpu"]["freq"] = freq._asdict() if freq else {}
        result["cpu"]["per_cpu"] = psutil.cpu_percent(percpu=True, interval=0.5)

        # Memory
        mem = psutil.virtual_memory()
        result["memory"] = {
            "total": mem.total,
            "available": mem.available,
            "percent": mem.percent,
            "used": mem.used,
            "free": mem.free,
            "buffers": getattr(mem, "buffers", 0),
            "cached": getattr(mem, "cached", 0),
        }

        # Disk
        disk = psutil.disk_usage("/")
        result["disk"] = {
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
            "percent": disk.percent,
        }

        # Network
        net_io = psutil.net_io_counters()
        result["network"] = {
            "bytes_sent": net_io.bytes_sent,
            "bytes_recv": net_io.bytes_recv,
            "packets_sent": net_io.packets_sent,
            "packets_recv": net_io.packets_recv,
            "errin": net_io.errin,
            "errout": net_io.errout,
        }

        # Processes (top 15 by CPU)
        procs: List[Dict[str, Any]] = []
        for p in psutil.process_iter(
            ["pid", "name", "cpu_percent", "memory_percent", "status", "username"]
        ):
            try:
                procs.append(p.info)
            except Exception:
                pass
        procs.sort(key=lambda x: x.get("cpu_percent", 0) or 0, reverse=True)
        result["processes"] = procs[:15]

        # Boot time
        result["boot_time"] = datetime.fromtimestamp(
            psutil.boot_time()
        ).isoformat()

        # Users
        try:
            result["users"] = [u._asdict() for u in psutil.users()]
        except Exception:
            pass

    except Exception as e:
        result["error"] = str(e)

    return result
