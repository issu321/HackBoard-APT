"""
Tests for hackboard.security_tools
"""

import pytest
from hackboard.security_tools import (
    COMMON_PORTS,
    PORT_SEVERITY,
    scan_port,
    scan_ports,
    analyze_password,
    hash_text,
    hash_file,
    verify_hash,
    analyze_file_security,
    simulate_vulnerability_assessment,
    get_packet_analytics,
    get_system_monitor_data,
    generate_simulated_packet_data,
)


class TestPortScanner:
    def test_common_ports_defined(self):
        assert 80 in COMMON_PORTS
        assert 443 in COMMON_PORTS
        assert COMMON_PORTS[80] == "HTTP"

    def test_port_severity_defined(self):
        assert PORT_SEVERITY[22] == "low"
        assert PORT_SEVERITY[23] == "critical"

    def test_scan_port_localhost(self):
        result = scan_port("127.0.0.1", 9999, timeout=0.5)
        assert "port" in result
        assert "state" in result
        assert result["port"] == 9999

    def test_scan_ports_invalid_ip(self):
        result = scan_ports("not-an-ip")
        assert "error" in result

    def test_scan_ports_localhost(self):
        result = scan_ports("127.0.0.1", ports=[9999], timeout=0.5)
        assert result["ports_scanned"] == 1
        assert "all_results" in result


class TestPasswordAnalyzer:
    def test_analyze_password_empty(self):
        result = analyze_password("")
        assert result["strength_label"] == "Empty"

    def test_analyze_password_weak(self):
        result = analyze_password("123456")
        assert result["score"] < 40
        assert result["common_password_match"] is True

    def test_analyze_password_strong(self):
        result = analyze_password("MyStr0ng!P@ssw0rd#2024")
        assert result["score"] >= 60
        assert result["entropy_bits"] > 50

    def test_complexity_checks(self):
        result = analyze_password("Abc123!")
        comp = result["complexity"]
        assert comp["has_lower"] is True
        assert comp["has_upper"] is True
        assert comp["has_digit"] is True
        assert comp["has_special"] is True


class TestHashing:
    def test_hash_text_sha256(self):
        result = hash_text("hello", "sha256")
        assert result["algorithm"] == "SHA256"
        assert len(result["hash"]) == 64

    def test_hash_text_md5(self):
        result = hash_text("hello", "md5")
        assert result["algorithm"] == "MD5"
        assert len(result["hash"]) == 32

    def test_hash_file(self):
        data = b"test file content"
        result = hash_file(data, "sha256")
        assert result["size_bytes"] == len(data)
        assert result["algorithm"] == "SHA256"

    def test_verify_hash_match(self):
        result = verify_hash("hello", "sha256", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        assert result["match"] is True

    def test_verify_hash_mismatch(self):
        result = verify_hash("hello", "sha256", "wronghash")
        assert result["match"] is False


class TestFileSecurity:
    def test_analyze_file_security_text(self):
        data = b"This is a plain text file for testing."
        result = analyze_file_security(data, "test.txt")
        assert result["filename"] == "test.txt"
        assert "md5" in result
        assert "sha256" in result

    def test_analyze_file_security_suspicious(self):
        data = b"MZ" + b"\x00" * 100  # Fake Windows executable header
        result = analyze_file_security(data, "test.exe")
        assert result["extension"] == "exe"
        assert "entropy" in result


class TestVulnerabilityAssessment:
    def test_simulate_vulnerability_assessment(self):
        scan = {
            "ip": "192.168.1.1",
            "open_ports": [
                {"port": 23, "service": "Telnet", "state": "open", "severity": "critical"},
                {"port": 22, "service": "SSH", "state": "open", "severity": "low"},
            ]
        }
        result = simulate_vulnerability_assessment(scan)
        assert "vulnerabilities" in result
        assert "summary" in result
        assert result["summary"]["critical"] >= 1


class TestPacketAnalytics:
    def test_generate_simulated_packet_data(self):
        data = generate_simulated_packet_data()
        assert "protocol_distribution" in data
        assert "bandwidth_mbps" in data

    def test_get_packet_analytics(self):
        result = get_packet_analytics()
        assert "timestamp" in result


class TestSystemMonitor:
    def test_get_system_monitor_data(self):
        result = get_system_monitor_data()
        assert "timestamp" in result
        assert "cpu" in result
        assert "memory" in result
