"""
Tests for hackboard.utils
"""

import pytest
from hackboard.utils import (
    validate_ip,
    validate_domain,
    validate_email,
    format_bytes,
    format_duration,
    truncate_string,
    calculate_entropy,
    get_common_passwords,
    get_dangerous_extensions,
    severity_color,
    generate_ai_insight,
)


class TestValidation:
    def test_validate_ip_valid_ipv4(self):
        assert validate_ip("192.168.1.1") is True
        assert validate_ip("127.0.0.1") is True
        assert validate_ip("8.8.8.8") is True

    def test_validate_ip_valid_ipv6(self):
        assert validate_ip("::1") is True
        assert validate_ip("2001:db8::1") is True

    def test_validate_ip_invalid(self):
        assert validate_ip("not-an-ip") is False
        assert validate_ip("999.999.999.999") is False
        assert validate_ip("") is False

    def test_validate_domain_valid(self):
        assert validate_domain("example.com") is True
        assert validate_domain("sub.example.co.uk") is True

    def test_validate_domain_invalid(self):
        assert validate_domain("not-a-domain") is False
        assert validate_domain("") is False
        assert validate_domain("-invalid.com") is False

    def test_validate_email_valid(self):
        assert validate_email("test@example.com") is True
        assert validate_email("user.name@domain.co.uk") is True

    def test_validate_email_invalid(self):
        assert validate_email("not-an-email") is False
        assert validate_email("@example.com") is False
        assert validate_email("") is False


class TestFormatting:
    def test_format_bytes(self):
        assert format_bytes(0) == "0.00 B"
        assert format_bytes(1024) == "1.00 KB"
        assert format_bytes(1024 * 1024) == "1.00 MB"
        assert format_bytes(1024 * 1024 * 1024) == "1.00 GB"

    def test_format_duration(self):
        assert format_duration(30.0) == "30.00s"
        assert format_duration(90.0) == "1.50m"
        assert format_duration(3700.0) == "1.03h"

    def test_truncate_string(self):
        assert truncate_string("short", 100) == "short"
        assert len(truncate_string("a" * 200, 50)) == 50


class TestEntropy:
    def test_calculate_entropy_empty(self):
        assert calculate_entropy(b"") == 0.0

    def test_calculate_entropy_uniform(self):
        # Uniform distribution of 256 bytes
        data = bytes(range(256))
        entropy = calculate_entropy(data)
        assert entropy == pytest.approx(8.0, abs=0.01)

    def test_calculate_entropy_single_byte(self):
        data = b"\\x00" * 1000
        assert calculate_entropy(data) == 0.0


class TestLists:
    def test_get_common_passwords(self):
        passwords = get_common_passwords()
        assert isinstance(passwords, list)
        assert len(passwords) > 0
        assert "password" in passwords

    def test_get_dangerous_extensions(self):
        exts = get_dangerous_extensions()
        assert isinstance(exts, list)
        assert ".exe" in exts
        assert ".dll" in exts


class TestSeverity:
    def test_severity_color(self):
        assert severity_color("critical") == "#ff0040"
        assert severity_color("high") == "#ff4500"
        assert severity_color("low") == "#00ff41"
        assert severity_color("unknown") == "#00f0ff"


class TestAIInsight:
    def test_password_insight_weak(self):
        insight = generate_ai_insight("password", {"score": 10, "entropy": 5})
        assert "low entropy" in insight.lower() or "dictionary" in insight.lower()

    def test_password_insight_strong(self):
        insight = generate_ai_insight("password", {"score": 90, "entropy": 80})
        assert "strong" in insight.lower()

    def test_network_insight(self):
        insight = generate_ai_insight("network", {"open_ports": [80, 443, 22], "risk_score": 20})
        assert isinstance(insight, str)
        assert len(insight) > 0
