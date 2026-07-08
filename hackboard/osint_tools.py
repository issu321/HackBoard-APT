
"""
HackBoard — OSINT Intelligence Module
=======================================

OSINT-inspired tools: WHOIS lookup, DNS resolution, subdomain enumeration,
IP intelligence, SSL certificate analysis, metadata extraction, and domain
reputation simulation. All tools are for educational and defensive use.

Author: issu321
License: MIT
"""

import hashlib
import ipaddress
import random
import socket
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from hackboard.utils import log_event, validate_domain, validate_ip

# Optional imports with graceful fallback
try:
    import whois
    WHOIS_AVAILABLE: bool = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE: bool = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE: bool = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ═══════════════════════════════════════════════════════════
# WHOIS LOOKUP
# ═══════════════════════════════════════════════════════════


def whois_lookup(domain: str) -> Dict[str, Any]:
    """Perform a WHOIS lookup on a domain.

    Args:
        domain: Domain name to look up.

    Returns:
        Dictionary with registrar, dates, name servers, and other
        WHOIS information. Includes domain age calculation if possible.
    """
    if not validate_domain(domain):
        return {"error": "Invalid domain format", "domain": domain}

    result: Dict[str, Any] = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "name_servers": [],
        "status": [],
        "emails": [],
        "org": None,
        "country": None,
        "raw_available": False,
    }

    if not WHOIS_AVAILABLE:
        result["error"] = "python-whois not installed. Run: pip install python-whois"
        return result

    try:
        w = whois.whois(domain)
        result["registrar"] = getattr(w, "registrar", None)
        result["creation_date"] = str(getattr(w, "creation_date", None))
        result["expiration_date"] = str(getattr(w, "expiration_date", None))
        result["name_servers"] = getattr(w, "name_servers", [])
        result["status"] = getattr(w, "status", [])
        result["emails"] = getattr(w, "emails", [])
        result["org"] = getattr(w, "org", None)
        result["country"] = getattr(w, "country", None)
        result["raw_available"] = True

        # Calculate domain age
        cd = getattr(w, "creation_date", None)
        if cd:
            try:
                if isinstance(cd, list):
                    cd = cd[0]
                if hasattr(cd, "year"):
                    age_days = (datetime.now() - cd).days
                    result["age_days"] = age_days
            except Exception:
                pass

    except Exception as e:
        result["error"] = str(e)
        log_event("WHOIS", f"Lookup failed for {domain}: {e}", "warning")

    return result


# ═══════════════════════════════════════════════════════════
# DNS INTELLIGENCE
# ═══════════════════════════════════════════════════════════


def dns_lookup(
    domain: str, record_types: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Perform DNS resolution for multiple record types.

    Args:
        domain: Domain to resolve.
        record_types: List of DNS record types. Defaults to common types.

    Returns:
        Dictionary with resolved records per type.
    """
    if not validate_domain(domain):
        return {"error": "Invalid domain", "domain": domain}

    if record_types is None:
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]

    result: Dict[str, Any] = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "records": {},
        "resolvable": False,
    }

    if not DNS_AVAILABLE:
        result["error"] = "dnspython not installed. Run: pip install dnspython"
        # Fallback to socket.gethostbyname for A records
        try:
            ip = socket.gethostbyname(domain)
            result["records"]["A"] = [ip]
            result["resolvable"] = True
        except Exception as e:
            result["records"]["A"] = [f"Error: {e}"]
        return result

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            records = [str(rdata) for rdata in answers]
            result["records"][rtype] = records
            result["resolvable"] = True
        except dns.resolver.NXDOMAIN:
            result["records"][rtype] = ["NXDOMAIN"]
        except dns.resolver.NoAnswer:
            result["records"][rtype] = ["NoAnswer"]
        except Exception as e:
            result["records"][rtype] = [f"Error: {e}"]

    return result


def reverse_dns(ip: str) -> Dict[str, Any]:
    """Perform a reverse DNS lookup.

    Args:
        ip: IP address to look up.

    Returns:
        Dictionary with resolved hostnames.
    """
    if not validate_ip(ip):
        return {"error": "Invalid IP", "ip": ip}

    result: Dict[str, Any] = {
        "ip": ip,
        "timestamp": datetime.now().isoformat(),
        "hostnames": [],
    }

    try:
        hostnames = socket.gethostbyaddr(ip)
        result["hostnames"] = [hostnames[0]]
    except Exception as e:
        result["error"] = str(e)

    return result


# ═══════════════════════════════════════════════════════════
# SUBDOMAIN INTELLIGENCE (SIMULATED EDUCATIONAL)
# ═══════════════════════════════════════════════════════════

_COMMON_SUBDOMAINS: List[str] = [
    "www", "mail", "ftp", "admin", "blog", "shop", "api", "dev", "test",
    "staging", "portal", "vpn", "remote", "webmail", "secure", "cdn",
    "media", "static", "docs", "support", "help", "forum", "chat",
    "app", "mobile", "download", "downloads", "news", "beta", "alpha",
    "demo", "internal", "extranet", "intranet", "git", "repo", "ci",
    "jenkins", "jira", "confluence", "wiki", "monitor", "grafana",
    "prometheus", "kibana", "elastic", "db", "database", "sql", "mysql",
    "postgres", "redis", "mongo", "rabbitmq", "kafka", "backend",
    "frontend", "proxy", "gateway", "lb", "loadbalancer", "dns",
    "ns1", "ns2", "mx", "smtp", "imap", "pop", "webdav", "caldav",
    "autodiscover", "autoconfig", "m", "s", "t", "i", "o", "p", "v"
]


def subdomain_enumeration(
    domain: str,
    wordlist: Optional[List[str]] = None,
    max_subs: int = 50,
) -> Dict[str, Any]:
    """Enumerate subdomains via DNS resolution.

    Educational tool that resolves common subdomain prefixes against
    the target domain.

    Args:
        domain: Target domain.
        wordlist: Custom subdomain wordlist. Defaults to built-in list.
        max_subs: Maximum subdomains to test.

    Returns:
        Dictionary with resolved subdomains and statistics.
    """
    if not validate_domain(domain):
        return {"error": "Invalid domain", "domain": domain}

    if wordlist is None:
        wordlist = _COMMON_SUBDOMAINS[:max_subs]

    result: Dict[str, Any] = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "subdomains": [],
        "total_tested": len(wordlist),
        "found_count": 0,
    }

    found: List[Dict[str, Any]] = []
    for sub in wordlist[:max_subs]:
        full_domain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full_domain)
            found.append({
                "subdomain": full_domain,
                "ip": ip,
                "status": "resolved",
            })
        except socket.gaierror:
            pass
        except Exception as e:
            found.append({
                "subdomain": full_domain,
                "ip": None,
                "status": f"error: {e}",
            })

    result["subdomains"] = found
    result["found_count"] = len([s for s in found if s.get("ip")])
    return result


# ═══════════════════════════════════════════════════════════
# IP INTELLIGENCE
# ═══════════════════════════════════════════════════════════


def ip_intelligence(ip: str) -> Dict[str, Any]:
    """Gather IP intelligence with educational simulation.

    Performs real IP validation and reverse DNS, with simulated
    ASN, country, and threat score for visualization.

    Args:
        ip: IP address to analyze.

    Returns:
        Dictionary with IP properties and simulated threat intelligence.
    """
    if not validate_ip(ip):
        return {"error": "Invalid IP", "ip": ip}

    result: Dict[str, Any] = {
        "ip": ip,
        "timestamp": datetime.now().isoformat(),
        "version": None,
        "is_private": False,
        "is_loopback": False,
        "is_multicast": False,
        "reverse_dns": None,
        "asn_simulated": None,
        "country_simulated": None,
        "threat_score_simulated": 0,
    }

    try:
        addr = ipaddress.ip_address(ip)
        result["version"] = f"IPv{addr.version}"
        result["is_private"] = addr.is_private
        result["is_loopback"] = addr.is_loopback
        result["is_multicast"] = addr.is_multicast
        result["is_reserved"] = addr.is_reserved
        result["is_link_local"] = addr.is_link_local
    except Exception as e:
        result["error"] = str(e)
        return result

    # Reverse DNS
    try:
        rdns = socket.gethostbyaddr(ip)
        result["reverse_dns"] = rdns[0]
    except Exception:
        pass

    # Simulated threat intelligence (deterministic based on IP hash)
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    random.seed(h)
    result["asn_simulated"] = f"AS{random.randint(1000, 65000)}"
    countries = ["US", "DE", "GB", "FR", "NL", "SG", "JP", "CA", "AU", "BR"]
    result["country_simulated"] = random.choice(countries)
    result["threat_score_simulated"] = random.randint(0, 100)
    result["reputation_simulated"] = random.choice(
        ["clean", "suspicious", "malicious", "clean", "clean"]
    )

    return result


# ═══════════════════════════════════════════════════════════
# SSL / CERTIFICATE ANALYSIS
# ═══════════════════════════════════════════════════════════


def ssl_certificate_info(domain: str, port: int = 443) -> Dict[str, Any]:
    """Analyze SSL certificate for a domain.

    Args:
        domain: Domain to analyze.
        port: Port to connect to (default 443).

    Returns:
        Dictionary with certificate details, expiry, and cipher info.
    """
    if not validate_domain(domain):
        return {"error": "Invalid domain", "domain": domain}

    result: Dict[str, Any] = {
        "domain": domain,
        "port": port,
        "timestamp": datetime.now().isoformat(),
        "has_ssl": False,
        "issuer": None,
        "subject": None,
        "not_before": None,
        "not_after": None,
        "serial_number": None,
        "version": None,
        "cipher": None,
    }

    try:
        import ssl
        import certifi

        context = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                result["has_ssl"] = True
                result["subject"] = cert.get("subject")
                result["issuer"] = cert.get("issuer")
                result["not_before"] = cert.get("notBefore")
                result["not_after"] = cert.get("notAfter")
                result["serial_number"] = cert.get("serialNumber")
                result["version"] = version
                result["cipher"] = cipher[0] if cipher else None

                # Check expiration
                not_after_str = cert.get("notAfter")
                if not_after_str:
                    try:
                        not_after = datetime.strptime(
                            not_after_str, "%b %d %H:%M:%S %Y %Z"
                        )
                        days_left = (not_after - datetime.utcnow()).days
                        result["days_until_expiry"] = days_left
                        result["expired"] = days_left < 0
                    except Exception:
                        pass
    except Exception as e:
        result["error"] = str(e)
        result["has_ssl"] = False

    return result


# ═══════════════════════════════════════════════════════════
# METADATA EXTRACTION
# ═══════════════════════════════════════════════════════════


def extract_file_metadata(file_content: bytes, filename: str) -> Dict[str, Any]:
    """Extract basic metadata from file bytes.

    Args:
        file_content: Raw file bytes.
        filename: Original filename.

    Returns:
        Dictionary with hashes, entropy, magic bytes, and MIME guess.
    """
    result: Dict[str, Any] = {
        "filename": filename,
        "size_bytes": len(file_content),
        "md5": hashlib.md5(file_content).hexdigest(),
        "sha1": hashlib.sha1(file_content).hexdigest(),
        "sha256": hashlib.sha256(file_content).hexdigest(),
        "entropy": None,
        "mime_guess": None,
        "extension": None,
        "magic_bytes": None,
    }

    # Extension extraction
    if "." in filename:
        result["extension"] = filename.split(".")[-1].lower()

    # Magic bytes (first 8 bytes hex)
    if len(file_content) >= 8:
        result["magic_bytes"] = file_content[:8].hex().upper()

    # Simple MIME guess based on magic bytes
    magic = result["magic_bytes"] or ""
    mime_map: Dict[str, str] = {
        "89504E47": "image/png",
        "FFD8FF": "image/jpeg",
        "47494638": "image/gif",
        "25504446": "application/pdf",
        "504B0304": "application/zip",
        "52617221": "application/x-rar",
        "7F454C46": "application/x-elf",
        "4D5A": "application/x-dosexec",
        "1F8B08": "application/gzip",
    }
    for sig, mime in mime_map.items():
        if magic.startswith(sig):
            result["mime_guess"] = mime
            break

    # Entropy calculation
    from math import log2
    if file_content:
        entropy = 0.0
        length = len(file_content)
        for x in range(256):
            p_x = float(file_content.count(bytes([x]))) / length
            if p_x > 0:
                entropy -= p_x * log2(p_x)
        result["entropy"] = round(entropy, 4)

    return result


# ═══════════════════════════════════════════════════════════
# DOMAIN REPUTATION SIMULATION
# ═══════════════════════════════════════════════════════════


def domain_reputation_simulation(domain: str) -> Dict[str, Any]:
    """Simulate domain reputation scoring for educational visualization.

    Generates deterministic pseudo-random scores based on domain hash
    for consistent results across repeated queries.

    Args:
        domain: Domain to simulate reputation for.

    Returns:
        Dictionary with simulated reputation metrics.
    """
    if not validate_domain(domain):
        return {"error": "Invalid domain", "domain": domain}

    h = int(hashlib.md5(domain.encode()).hexdigest(), 16)
    random.seed(h)

    categories = [
        "Business", "Technology", "Education", "Suspicious",
        "Hosting", "CDN", "News"
    ]
    k = random.randint(1, min(3, len(categories)))

    return {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "reputation_score": random.randint(0, 100),
        "malware_score_simulated": random.randint(0, 100),
        "phishing_score_simulated": random.randint(0, 100),
        "spam_score_simulated": random.randint(0, 100),
        "categories_simulated": random.sample(categories, k=k),
        "risk_level": random.choice(["Low", "Medium", "High", "Critical"]),
        "note": "Simulated data for educational threat intelligence visualization only.",
    }
