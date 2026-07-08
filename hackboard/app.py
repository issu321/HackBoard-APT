
"""
HackBoard — Main Streamlit Application
=======================================

Professional Cybersecurity Intelligence Platform.
AI-inspired security analysis, cyber threat intelligence, OSINT analytics,
and cyberpunk SOC dashboard.

This application is STRICTLY EDUCATIONAL, DEFENSIVE, and ETHICAL.

Author: issu321
Version: 1.0.0
License: MIT
"""

import base64
import datetime
import io
import json
import os
import random
import sys
import time
from typing import Any, Dict, List

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# ═══════════════════════════════════════════════════════════
# IMPORT HACKBOARD MODULES
# ═══════════════════════════════════════════════════════════

try:
    from hackboard.utils import (
        validate_ip,
        validate_domain,
        format_bytes,
        format_duration,
        log_event,
        save_threat_log,
        get_soc_feed,
        get_banner,
        get_boot_sequence,
        get_cyberpunk_css,
        severity_badge,
        severity_color,
        generate_ai_insight,
        init_session_state,
        export_to_csv,
        export_to_json,
        export_to_txt,
        generate_security_report,
        get_platform_info,
        save_report,
        discover_plugins,
    )
    from hackboard.security_tools import (
        scan_ports,
        discover_hosts,
        analyze_password,
        hash_text,
        hash_file,
        verify_hash,
        analyze_file_security,
        simulate_vulnerability_assessment,
        get_packet_analytics,
        get_system_monitor_data,
        HASH_ALGORITHMS,
        COMMON_PORTS,
    )
    from hackboard.osint_tools import (
        whois_lookup,
        dns_lookup,
        reverse_dns,
        subdomain_enumeration,
        ip_intelligence,
        ssl_certificate_info,
        extract_file_metadata,
        domain_reputation_simulation,
    )
    from hackboard.analytics import (
        create_radar_chart,
        create_heatmap,
        create_port_heatmap,
        create_network_topology_graph,
        create_subdomain_graph,
        create_risk_gauge,
        create_entropy_gauge,
        create_bar_chart,
        create_pie_chart,
        create_line_chart,
        create_threat_radar,
        create_attack_chain_graph,
        create_protocol_distribution,
        create_system_gauges,
        create_vulnerability_summary_table,
        create_threat_timeline,
        generate_csv_report,
        generate_json_report,
        generate_txt_report,
        CYBER_COLORS,
        CYBER_PALETTE,
    )

    MODULES_LOADED = True
except Exception as e:
    MODULES_LOADED = False
    MODULE_ERROR = str(e)

# ═══════════════════════════════════════════════════════════
# PAGE CONFIGURATION
# ═══════════════════════════════════════════════════════════

st.set_page_config(
    page_title="HackBoard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ═══════════════════════════════════════════════════════════
# CYBERPUNK CSS INJECTION
# ═══════════════════════════════════════════════════════════

CYBER_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');

/* Global theme */
.stApp {
    background-color: #0a0a0a;
    font-family: 'Share Tech Mono', 'Courier New', monospace;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background-color: #0d0d0d !important;
    border-right: 1px solid #1a1a1a;
}
[data-testid="stSidebar"] .stRadio label {
    color: #00f0ff !important;
    font-size: 0.9rem;
    font-weight: 500;
}
[data-testid="stSidebar"] .stRadio > div {
    gap: 0.3rem;
}

/* Headers */
.stMarkdown h1, .stMarkdown h2, .stMarkdown h3, .stMarkdown h4, .stMarkdown h5, .stMarkdown h6,
.element-container h1, .element-container h2, .element-container h3, .element-container h4, .element-container h5, .element-container h6 {
    color: #00f0ff !important;
    font-family: 'Share Tech Mono', 'Courier New', monospace;
}

/* Text content */
.stMarkdown p, .stMarkdown span, .stMarkdown label,
.element-container p, .element-container span, .element-container label,
[data-testid="stTextInput"] label, [data-testid="stNumberInput"] label,
.stTextArea label, [data-testid="stSelectbox"] label,
[data-testid="stMultiselect"] label, [data-testid="stSlider"] label,
[data-testid="stCheckbox"] label, [data-testid="stRadio"] label {
    color: #e0e0e0;
    font-family: 'Share Tech Mono', 'Courier New', monospace;
}

/* Buttons */
.stButton > button {
    background-color: #00f0ff22 !important;
    color: #00f0ff !important;
    border: 1px solid #00f0ff !important;
    border-radius: 4px !important;
    font-family: 'Share Tech Mono', 'Courier New', monospace;
    transition: all 0.3s ease;
}
.stButton > button:hover {
    background-color: #00f0ff44 !important;
    box-shadow: 0 0 15px #00f0ff66;
}

/* Metric cards */
[data-testid="stMetricValue"] {
    color: #00ff41 !important;
    font-size: 1.8rem !important;
    font-weight: bold !important;
}
[data-testid="stMetricLabel"] {
    color: #00f0ff !important;
    font-size: 0.85rem !important;
}

/* Dataframes */
.stDataFrame {
    background-color: #111111 !important;
    border: 1px solid #222222 !important;
}
.stDataFrame th {
    background-color: #1a1a1a !important;
    color: #00f0ff !important;
    font-family: 'Share Tech Mono', monospace;
}
.stDataFrame td {
    color: #e0e0e0 !important;
    font-family: 'Share Tech Mono', monospace;
    border-bottom: 1px solid #222222 !important;
}

/* Code blocks */
.stCodeBlock {
    background-color: #111111 !important;
    border: 1px solid #222222 !important;
    border-left: 3px solid #00f0ff !important;
}

/* Expander */
[data-testid="stExpander"] .streamlit-expanderHeader {
    background-color: #111111 !important;
    color: #00f0ff !important;
    border: 1px solid #222222 !important;
    border-radius: 4px !important;
    font-family: 'Share Tech Mono', 'Courier New', monospace;
}
[data-testid="stExpander"] .streamlit-expanderContent {
    background-color: #0d0d0d !important;
    border: 1px solid #1a1a1a !important;
}

/* Input fields */
.stTextInput > div > div > input,
.stNumberInput > div > div > input,
.stTextArea > div > div > textarea {
    background-color: #111111 !important;
    color: #00f0ff !important;
    border: 1px solid #222222 !important;
    font-family: 'Share Tech Mono', monospace;
}
.stTextInput > div > div > input:focus,
.stTextArea > div > div > textarea:focus {
    border-color: #00f0ff !important;
    box-shadow: 0 0 10px #00f0ff44 !important;
}

/* Selectbox */
.stSelectbox > div > div {
    background-color: #111111 !important;
    color: #00f0ff !important;
    border: 1px solid #222222 !important;
}

/* File uploader */
.stFileUploader > div > div {
    background-color: #111111 !important;
    border: 2px dashed #00f0ff44 !important;
    color: #e0e0e0 !important;
}
.stFileUploader > div > div:hover {
    border-color: #00f0ff !important;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    gap: 2px;
    background-color: #0d0d0d !important;
}
.stTabs [data-baseweb="tab"] {
    background-color: #111111 !important;
    color: #00f0ff !important;
    border: 1px solid #222222 !important;
    border-radius: 4px 4px 0 0 !important;
}
.stTabs [aria-selected="true"] {
    background-color: #00f0ff22 !important;
    border-bottom: 2px solid #00f0ff !important;
}

/* Scrollbars */
::-webkit-scrollbar {
    width: 8px;
    height: 8px;
}
::-webkit-scrollbar-track {
    background: #0a0a0a;
}
::-webkit-scrollbar-thumb {
    background: #222222;
    border-radius: 4px;
}
::-webkit-scrollbar-thumb:hover {
    background: #00f0ff44;
}

/* Terminal box */
.terminal-box {
    background-color: #0d0d0d;
    border: 1px solid #00f0ff33;
    border-radius: 6px;
    padding: 1rem;
    font-family: 'Share Tech Mono', monospace;
    color: #00ff41;
    font-size: 0.85rem;
    line-height: 1.5;
    max-height: 400px;
    overflow-y: auto;
    box-shadow: inset 0 0 20px #00f0ff11;
}

/* Alert boxes */
.alert-critical {
    background-color: #ff004011;
    border-left: 3px solid #ff0040;
    color: #ff0040;
    padding: 0.5rem 1rem;
    margin: 0.3rem 0;
    border-radius: 0 4px 4px 0;
    font-size: 0.8rem;
    font-family: 'Share Tech Mono', monospace;
}
.alert-warning {
    background-color: #ffaa0011;
    border-left: 3px solid #ffaa00;
    color: #ffaa00;
    padding: 0.5rem 1rem;
    margin: 0.3rem 0;
    border-radius: 0 4px 4px 0;
    font-size: 0.8rem;
    font-family: 'Share Tech Mono', monospace;
}
.alert-info {
    background-color: #00f0ff11;
    border-left: 3px solid #00f0ff;
    color: #00f0ff;
    padding: 0.5rem 1rem;
    margin: 0.3rem 0;
    border-radius: 0 4px 4px 0;
    font-size: 0.8rem;
    font-family: 'Share Tech Mono', monospace;
}
.alert-safe {
    background-color: #00ff4111;
    border-left: 3px solid #00ff41;
    color: #00ff41;
    padding: 0.5rem 1rem;
    margin: 0.3rem 0;
    border-radius: 0 4px 4px 0;
    font-size: 0.8rem;
    font-family: 'Share Tech Mono', monospace;
}

/* Glowing cards */
.glow-card {
    background-color: #111111;
    border: 1px solid #222222;
    border-radius: 8px;
    padding: 1rem;
    transition: all 0.3s ease;
}
.glow-card:hover {
    border-color: #00f0ff44;
    box-shadow: 0 0 15px #00f0ff22;
}

/* Footer */
.footer {
    text-align: center;
    color: #444444;
    font-size: 0.75rem;
    margin-top: 2rem;
    padding-top: 1rem;
    border-top: 1px solid #1a1a1a;
    font-family: 'Share Tech Mono', monospace;
}
</style>
"""

st.markdown(CYBER_CSS, unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════
# SESSION STATE INITIALIZATION
# ═══════════════════════════════════════════════════════════

SESSION_DEFAULTS = {
    "boot_complete": False,
    "scan_results": None,
    "domain_results": None,
    "subdomain_results": None,
    "password_results": None,
    "hash_results": None,
    "file_results": None,
    "vuln_results": None,
    "packet_results": None,
    "system_results": None,
    "uploaded_files": [],
    "reports": [],
    "threat_logs": [],
    "last_page": "🏠 Dashboard",
    "terminal_lines": [],
    "soc_feed": [],
}

init_session_state(st, SESSION_DEFAULTS)

# ═══════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════

with st.sidebar:
    st.markdown(
        """
    <div style="text-align:center; margin-bottom:1rem;">
        <h2 style="color:#00f0ff; text-shadow:0 0 15px #00f0ff66; margin:0;">🛡️</h2>
        <h3 style="color:#00f0ff; text-shadow:0 0 10px #00f0ff44; margin:0; font-size:1.1rem;">
            HACKBOARD
        </h3>
        <p style="color:#444; font-size:0.7rem; margin-top:0.3rem;">
            Security Intelligence Platform v1.0.0
        </p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    st.markdown(
        "<hr style='border-color:#1a1a1a; margin:0.5rem 0;'>", unsafe_allow_html=True
    )

    pages = [
        "🏠 Dashboard",
        "🔍 Advanced Network Scanner",
        "🌐 Domain Intelligence",
        "📡 Subdomain Intelligence",
        "🔐 Password Analyzer",
        "🧪 Hashing Laboratory",
        "📁 File Security Analyzer",
        "⚠️ Vulnerability Intelligence",
        "📊 Packet Analytics",
        "🧠 Threat Intelligence",
        "💻 System Monitor",
        "📂 Upload Center",
        "📥 Download Center",
        "📈 Cyber Analytics",
        "🌍 DNS Intelligence",
        "🛰️ Network Topology",
        "📋 Reports Center",
        "🤖 AI Security Insights",
    ]

    page = st.radio(
        "NAVIGATION",
        pages,
        index=(
            pages.index(st.session_state.last_page)
            if st.session_state.last_page in pages
            else 0
        ),
        label_visibility="collapsed",
    )
    st.session_state.last_page = page

    st.markdown(
        "<hr style='border-color:#1a1a1a; margin:0.5rem 0;'>", unsafe_allow_html=True
    )

    # Mini SOC feed in sidebar
    st.markdown(
        "<p style='color:#00f0ff; font-size:0.75rem; margin-bottom:0.3rem;'>🔴 LIVE SOC FEED</p>",
        unsafe_allow_html=True,
    )

    if not st.session_state.soc_feed or random.random() < 0.3:
        try:
            st.session_state.soc_feed = get_soc_feed(8)
        except Exception:
            st.session_state.soc_feed = []

    for alert in st.session_state.soc_feed[:6]:
        level = alert.get("level", "INFO").lower()
        color = {
            "critical": "#ff0040",
            "error": "#ff0040",
            "warning": "#ffaa00",
            "info": "#00f0ff",
        }.get(level, "#00f0ff")
        st.markdown(
            f"""
        <div style="font-size:0.68rem; color:{color}; border-left:2px solid {color}; padding-left:4px; margin-bottom:3px; opacity:0.85;">
            <span style="opacity:0.6;">[{alert.get("timestamp", "--:--:--")}]</span> {alert.get("type", "")}: {alert.get("message", "")[:60]}...
        </div>
        """,
            unsafe_allow_html=True,
        )

    st.markdown(
        "<hr style='border-color:#1a1a1a; margin:0.5rem 0;'>", unsafe_allow_html=True
    )
    st.markdown(
        """
    <div class="footer" style="text-align:center;">
        <p style="color:#333; font-size:0.7rem;">
            Developed by <span style="color:#00f0ff;">issu321</span><br>
            <a href="https://github.com/issu321/hackboard" style="color:#444; text-decoration:none;">github.com/issu321/hackboard</a>
        </p>
    </div>
    """,
        unsafe_allow_html=True,
    )

# ═══════════════════════════════════════════════════════════
# MODULE ERROR CHECK
# ═══════════════════════════════════════════════════════════

if not MODULES_LOADED:
    st.error(f"Failed to load modules: {MODULE_ERROR}")
    st.info(
        "Please ensure all dependencies are installed: pip install -r requirements.txt"
    )
    st.stop()

# ═══════════════════════════════════════════════════════════
# BOOT SEQUENCE (First visit)
# ═══════════════════════════════════════════════════════════

if not st.session_state.boot_complete:
    boot_container = st.empty()
    lines = get_boot_sequence()
    display_lines = []
    for line in lines:
        display_lines.append(line)
        boot_text = "\n".join(display_lines)
        boot_container.markdown(
            f"""
        <div class="terminal-box">
            <pre style="margin:0; color:#00ff41; font-family:'Share Tech Mono',monospace;">{boot_text}</pre>
        </div>
        """,
            unsafe_allow_html=True,
        )
        time.sleep(0.08)
    st.session_state.boot_complete = True
    boot_container.empty()
    st.rerun()

# ═══════════════════════════════════════════════════════════
# HELPER FUNCTIONS FOR UI
# ═══════════════════════════════════════════════════════════


def render_terminal_box(content: str, height: int = 300) -> None:
    """Render content in a terminal-styled box."""
    st.markdown(
        f"""
    <div class="terminal-box" style="max-height:{height}px;">
        <pre style="margin:0; color:#00ff41; font-family:'Share Tech Mono',monospace; white-space:pre-wrap;">{content}</pre>
    </div>
    """,
        unsafe_allow_html=True,
    )


def render_glow_card(title: str, content: str, icon: str = "🔹") -> None:
    """Render a glowing dashboard card."""
    st.markdown(
        f"""
    <div class="glow-card" style="margin-bottom:0.5rem;">
        <h4 style="color:#00f0ff; margin:0 0 0.5rem 0; font-size:0.95rem;">{icon} {title}</h4>
        <p style="color:#e0e0e0; margin:0; font-size:0.85rem;">{content}</p>
    </div>
    """,
        unsafe_allow_html=True,
    )


def render_alert(level: str, message: str) -> None:
    """Render an alert box."""
    css_class = f"alert-{level.lower()}"
    st.markdown(f'<div class="{css_class}">{message}</div>', unsafe_allow_html=True)


def add_report(title: str, data: Any, report_type: str = "analysis") -> None:
    """Add a report to session state and save to disk."""
    report = {
        "id": f"RPT-{len(st.session_state.reports)+1:04d}",
        "title": title,
        "type": report_type,
        "timestamp": datetime.datetime.now().isoformat(),
        "data": data,
    }
    st.session_state.reports.append(report)
    # Auto-save to disk
    try:
        save_report(data, title, report_type, "json")
    except Exception:
        pass
    try:
        save_threat_log(
            {
                "timestamp": report["timestamp"],
                "type": "REPORT_GENERATED",
                "message": f"Report {report['id']} generated: {title}",
                "level": "INFO",
            }
        )
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ═══════════════════════════════════════════════════════════

if page == "🏠 Dashboard":
    st.markdown(
        """
    <div style="text-align:center; margin-bottom:1.5rem;">
        <h1 style="color:#00f0ff; text-shadow:0 0 20px #00f0ff55; font-size:2.2rem;">
            🛡️ HACKBOARD
        </h1>
        <p style="color:#888; font-size:1rem; margin-top:-0.5rem;">
            AI Cybersecurity Operations Center + Ethical Hacking Toolkit + Threat Intelligence Platform
        </p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # Top metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Threat Level", "MONITORING", "+2 alerts")
    with col2:
        st.metric(
            "Active Scans",
            len([r for r in st.session_state.reports if r.get("type") == "scan"]),
            "+0",
        )
    with col3:
        st.metric(
            "Domains Analyzed",
            len([r for r in st.session_state.reports if r.get("type") == "domain"]),
            "+0",
        )
    with col4:
        st.metric(
            "Files Scanned",
            len([r for r in st.session_state.reports if r.get("type") == "file"]),
            "+0",
        )
    with col5:
        st.metric("System Status", "OPTIMAL", "-0.2%")

    st.markdown("<hr style='border-color:#1a1a1a;'>", unsafe_allow_html=True)

    col_left, col_right = st.columns([2, 1])

    with col_left:
        st.subheader("📊 Cyber Analytics Overview")

        # Threat radar
        try:
            fig = create_threat_radar({})
            st.plotly_chart(fig, use_container_width=True, key="dash_threat_radar")
        except Exception as e:
            st.error(f"Chart error: {e}")

        # Attack chain
        try:
            fig2 = create_attack_chain_graph()
            st.plotly_chart(fig2, use_container_width=True, key="dash_attack_chain")
        except Exception as e:
            st.error(f"Chart error: {e}")

    with col_right:
        st.subheader("🖥️ System Telemetry")
        try:
            sys_data = get_system_monitor_data()
            if "error" not in sys_data:
                cpu = sys_data.get("cpu", {}).get("percent", 0)
                mem = sys_data.get("memory", {}).get("percent", 0)
                disk = sys_data.get("disk", {}).get("percent", 0)
                fig_gauges = create_system_gauges(cpu, mem, disk)
                st.plotly_chart(
                    fig_gauges, use_container_width=True, key="dash_sys_gauges"
                )
            else:
                st.info("System monitor requires psutil")
        except Exception as e:
            st.error(f"System monitor error: {e}")

        st.subheader("📝 Quick Actions")
        render_glow_card(
            "Network Scan",
            "Scan localhost or custom IPs for open ports and services",
            "🔍",
        )
        render_glow_card(
            "Domain Intel", "Analyze WHOIS, DNS, and SSL certificate data", "🌐"
        )
        render_glow_card(
            "File Analysis", "Upload and analyze file security metrics", "📁"
        )
        render_glow_card(
            "Password Check", "Evaluate password strength and entropy", "🔐"
        )

    st.markdown("<hr style='border-color:#1a1a1a;'>", unsafe_allow_html=True)

    # Bottom: Threat timeline + recent reports
    col_tl, col_rep = st.columns([2, 1])
    with col_tl:
        st.subheader("📈 24h Threat Activity Timeline")
        try:
            fig_tl = create_threat_timeline()
            st.plotly_chart(fig_tl, use_container_width=True, key="dash_threat_tl")
        except Exception as e:
            st.error(f"Timeline error: {e}")

    with col_rep:
        st.subheader("📋 Recent Reports")
        if st.session_state.reports:
            for r in reversed(st.session_state.reports[-5:]):
                st.markdown(
                    f"""
                <div style="font-size:0.8rem; color:#e0e0e0; border-left:2px solid #00f0ff; padding-left:6px; margin-bottom:4px;">
                    <span style="color:#00f0ff;">{r['id']}</span> {r['title']}<br>
                    <span style="color:#666; font-size:0.7rem;">{r['timestamp'][:19]}</span>
                </div>
                """,
                    unsafe_allow_html=True,
                )
        else:
            st.info("No reports generated yet")


# ═══════════════════════════════════════════════════════════
# PAGE: ADVANCED NETWORK SCANNER
# ═══════════════════════════════════════════════════════════

elif page == "🔍 Advanced Network Scanner":
    st.header("🔍 Advanced Network Scanner")
    st.markdown(
        "<p style='color:#888;'>Safe educational TCP port scanner with risk scoring and topology visualization.</p>",
        unsafe_allow_html=True,
    )

    col_input, col_opts = st.columns([2, 1])

    with col_input:
        target_ip = st.text_input(
            "Target IP Address",
            value="127.0.0.1",
            placeholder="e.g., 127.0.0.1 or 192.168.1.1",
        )

    with col_opts:
        port_option = st.selectbox(
            "Port Range",
            [
                "Common Ports (Top 20)",
                "Web Services (80,443,8080,8443)",
                "Database Ports (3306,5432,27017,6379,9200)",
                "Remote Access (21,22,23,3389,5900)",
                "Custom Range",
            ],
        )

    if port_option == "Custom Range":
        custom_ports = st.text_input("Custom Ports (comma-separated)", "80,443,22")
    else:
        custom_ports = ""

    scan_cols = st.columns([1, 1, 2])
    with scan_cols[0]:
        timeout = st.slider("Timeout (s)", 0.5, 5.0, 1.0, 0.5)
    with scan_cols[1]:
        workers = st.slider("Max Workers", 10, 100, 50, 10)

    if st.button("🚀 INITIATE SCAN", use_container_width=True):
        if not validate_ip(target_ip):
            render_alert("error", f"Invalid IP address: {target_ip}")
        else:
            with st.spinner("Scanning target..."):
                if port_option == "Common Ports (Top 20)":
                    ports = list(COMMON_PORTS.keys())
                elif port_option == "Web Services (80,443,8080,8443)":
                    ports = [80, 443, 8080, 8443]
                elif port_option == "Database Ports (3306,5432,27017,6379,9200)":
                    ports = [3306, 5432, 27017, 6379, 9200, 11211]
                elif port_option == "Remote Access (21,22,23,3389,5900)":
                    ports = [21, 22, 23, 3389, 5900]
                else:
                    try:
                        ports = [
                            int(p.strip())
                            for p in custom_ports.split(",")
                            if p.strip().isdigit()
                        ]
                    except Exception:
                        ports = [80, 443]

                results = scan_ports(
                    target_ip, ports, max_workers=workers, timeout=timeout
                )
                st.session_state.scan_results = results
                add_report(f"Network Scan: {target_ip}", results, "scan")

            st.success(
                f"Scan complete! Duration: {results.get('scan_duration_ms', 0)}ms"
            )

    # Display results
    if st.session_state.scan_results:
        results = st.session_state.scan_results
        if "error" in results:
            render_alert("error", results["error"])
        else:
            st.markdown("<hr style='border-color:#1a1a1a;'>", unsafe_allow_html=True)

            # Summary metrics
            m1, m2, m3, m4 = st.columns(4)
            with m1:
                st.metric("Ports Scanned", results.get("ports_scanned", 0))
            with m2:
                st.metric("Open Ports", len(results.get("open_ports", [])))
            with m3:
                st.metric("Filtered", len(results.get("filtered_ports", [])))
            with m4:
                st.metric("Risk Score", f"{results.get('risk_score', 0)}/100")

            # Risk gauge
            try:
                fig_gauge = create_risk_gauge(
                    results.get("risk_score", 0), "Network Risk Score"
                )
                st.plotly_chart(
                    fig_gauge, use_container_width=True, key="net_risk_gauge"
                )
            except Exception as e:
                st.error(f"Gauge error: {e}")

            # Tabs for different views
            tab1, tab2, tab3, tab4 = st.tabs(
                ["📋 Results Table", "🔥 Port Heatmap", "🌐 Topology", "⚠️ High Risk"]
            )

            with tab1:
                df_data = []
                for r in results.get("all_results", []):
                    df_data.append(
                        {
                            "Port": r["port"],
                            "Service": r.get("service", "Unknown"),
                            "State": r["state"].upper(),
                            "Severity": r.get("severity", "info").upper(),
                            "Latency (ms)": r.get("latency_ms", "N/A"),
                            "Banner": (r.get("banner", "") or "")[:50],
                        }
                    )
                if df_data:
                    df = pd.DataFrame(df_data)
                    st.dataframe(df, use_container_width=True)
                else:
                    st.info("No results to display")

            with tab2:
                try:
                    fig_hm = create_port_heatmap(results)
                    st.plotly_chart(fig_hm, use_container_width=True, key="net_port_hm")
                except Exception as e:
                    st.error(f"Heatmap error: {e}")

            with tab3:
                try:
                    fig_topo = create_network_topology_graph(results)
                    st.plotly_chart(fig_topo, use_container_width=True, key="net_topo")
                except Exception as e:
                    st.error(f"Topology error: {e}")

            with tab4:
                high_risk = results.get("high_risk_ports", [])
                if high_risk:
                    for hr in high_risk:
                        render_alert(
                            "critical",
                            f"Port {hr['port']} ({hr.get('service', 'Unknown')}) - {hr['state'].upper()} - Severity: {hr.get('severity', 'info').upper()}",
                        )
                else:
                    render_alert("safe", "No high-risk ports detected in this scan.")

            # AI Insight
            st.markdown("<hr style='border-color:#1a1a1a;'>", unsafe_allow_html=True)
            st.subheader("🤖 AI Security Insight")
            insight = generate_ai_insight(
                "network",
                {
                    "open_ports": results.get("open_ports", []),
                    "risk_score": results.get("risk_score", 0),
                },
            )
            render_glow_card("Network Analysis", insight, "🧠")

            # Download
            st.markdown("<hr style='border-color:#1a1a1a;'>", unsafe_allow_html=True)
            col_dl1, col_dl2, col_dl3 = st.columns(3)
            with col_dl1:
                st.download_button(
                    "📥 Download CSV",
                    generate_csv_report(df_data),
                    f"scan_{target_ip}.csv",
                    "text/csv",
                )
            with col_dl2:
                st.download_button(
                    "📥 Download JSON",
                    generate_json_report(results),
                    f"scan_{target_ip}.json",
                    "application/json",
                )
            with col_dl3:
                report_txt = generate_security_report(
                    f"Network Scan: {target_ip}",
                    df_data,
                    [
                        "Review open ports and close unnecessary services.",
                        "Apply firewall rules to restrict access.",
                    ],
                    {
                        "target": target_ip,
                        "ports_scanned": results.get("ports_scanned", 0),
                    },
                )
                st.download_button(
                    "📥 Download Report",
                    generate_txt_report(report_txt),
                    f"scan_report_{target_ip}.txt",
                    "text/plain",
                )


# ═══════════════════════════════════════════════════════════
# PAGE: DOMAIN INTELLIGENCE
# ═══════════════════════════════════════════════════════════

elif page == "🌐 Domain Intelligence":
    st.header("🌐 Domain Intelligence")
    st.markdown(
        "<p style='color:#888;'>WHOIS lookup, DNS analysis, SSL certificate inspection, and domain reputation.</p>",
        unsafe_allow_html=True,
    )

    domain_input = st.text_input("Domain Name", placeholder="e.g., example.com")

    col_btn1, col_btn2, col_btn3 = st.columns(3)
    with col_btn1:
        whois_btn = st.button("🔍 WHOIS Lookup", use_container_width=True)
    with col_btn2:
        ssl_btn = st.button("🔒 SSL Certificate", use_container_width=True)
    with col_btn3:
        rep_btn = st.button("📊 Reputation", use_container_width=True)

    if whois_btn or ssl_btn or rep_btn:
        if not validate_domain(domain_input):
            render_alert("error", "Invalid domain format")
        else:
            with st.spinner("Gathering intelligence..."):
                if whois_btn:
                    result = whois_lookup(domain_input)
                    st.session_state.domain_results = result
                    add_report(f"WHOIS: {domain_input}", result, "domain")
                elif ssl_btn:
                    result = ssl_certificate_info(domain_input)
                    st.session_state.domain_results = result
                    add_report(f"SSL: {domain_input}", result, "domain")
                elif rep_btn:
                    result = domain_reputation_simulation(domain_input)
                    st.session_state.domain_results = result
                    add_report(f"Reputation: {domain_input}", result, "domain")

    if st.session_state.domain_results:
        res = st.session_state.domain_results
        st.markdown("<hr style='border-color:#1a1a1a;'>", unsafe_allow_html=True)

        if "error" in res and res["error"]:
            render_alert("error", str(res["error"]))

        # Display based on result type
        if "registrar" in res:
            st.subheader("📋 WHOIS Information")
            col1, col2 = st.columns(2)
            with col1:
                render_glow_card("Registrar", res.get("registrar") or "N/A", "🏢")
                render_glow_card("Organization", res.get("org") or "N/A", "🏛️")
                render_glow_card("Country", res.get("country") or "N/A", "🌍")
            with col2:
                render_glow_card(
                    "Creation Date", str(res.get("creation_date"))[:50] or "N/A", "📅"
                )
                render_glow_card(
                    "Expiration", str(res.get("expiration_date"))[:50] or "N/A", "⏰"
                )
                age = res.get("age_days")
                if age is not None:
                    render_glow_card("Domain Age", f"{age} days", "📆")

            if res.get("name_servers"):
                st.markdown(
                    "<p style='color:#00f0ff; font-size:0.9rem; margin-top:1rem;'>🖥️ Name Servers</p>",
                    unsafe_allow_html=True,
                )
                for ns in res["name_servers"]:
                    st.markdown(
                        f'<div class="alert-info">{ns}</div>', unsafe_allow_html=True
                    )

            # AI Insight
            insight = generate_ai_insight(
                "domain", {"age_days": res.get("age_days", 999)}
            )
            render_glow_card("AI Insight", insight, "🧠")

        elif "has_ssl" in res:
            st.subheader("🔒 SSL Certificate Analysis")
            if res.get("has_ssl"):
                render_glow_card("SSL Version", res.get("version") or "N/A", "🔐")
                render_glow_card("Cipher", res.get("cipher") or "N/A", "🗝️")
                render_glow_card(
                    "Serial Number", res.get("serial_number") or "N/A", "🔢"
                )
                if "days_until_expiry" in res:
                    days = res["days_until_expiry"]
                    if days < 30:
                        render_alert("warning", f"Certificate expires in {days} days!")
                    else:
                        render_alert("safe", f"Certificate valid for {days} more days.")
            else:
                render_alert(
                    "error", "No SSL certificate detected or connection failed."
                )

        elif "reputation_score" in res:
            st.subheader("📊 Domain Reputation (Simulated)")
            st.info(
                "Note: Reputation data is simulated for educational visualization only."
            )

            m1, m2, m3, m4 = st.columns(4)
            with m1:
                st.metric("Reputation", f"{res.get('reputation_score', 0)}/100")
            with m2:
                st.metric("Malware Score", f"{res.get('malware_score_simulated', 0)}")
            with m3:
                st.metric("Phishing Score", f"{res.get('phishing_score_simulated', 0)}")
            with m4:
                st.metric("Risk Level", res.get("risk_level", "Unknown"))

            try:
                fig = create_radar_chart(
                    ["Reputation", "Malware", "Phishing", "Spam"],
                    [
                        100 - res.get("reputation_score", 0),
                        res.get("malware_score_simulated", 0),
                        res.get("phishing_score_simulated", 0),
                        res.get("spam_score_simulated", 0),
                    ],
                    "Domain Threat Profile",
                    CYBER_COLORS["danger"],
                )
                st.plotly_chart(fig, use_container_width=True, key="domain_radar")
            except Exception as e:
                st.error(f"Radar error: {e}")


# ═══════════════════════════════════════════════════════════
# PAGE: SUBDOMAIN INTELLIGENCE
# ═══════════════════════════════════════════════════════════

elif page == "📡 Subdomain Intelligence":
    st.header("📡 Subdomain Intelligence")
    st.markdown(
        "<p style='color:#888;'>Enumerate and visualize subdomains with DNS resolution mapping.</p>",
        unsafe_allow_html=True,
    )

    domain_input = st.text_input("Target Domain", placeholder="e.g., example.com")
    max_subs = st.slider("Max Subdomains to Test", 10, 100, 50)

    if st.button("🚀 Enumerate Subdomains", use_container_width=True):
        if not validate_domain(domain_input):
            render_alert("error", "Invalid domain")
        else:
            with st.spinner("Resolving subdomains..."):
                result = subdomain_enumeration(domain_input, max_subs=max_subs)
                st.session_state.subdomain_results = result
                add_report(f"Subdomain Enum: {domain_input}", result, "domain")

    if st.session_state.subdomain_results:
        res = st.session_state.subdomain_results
        st.markdown("<hr style='border-color:#1a1a1a;'>", unsafe_allow_html=True)

        st.metric("Subdomains Found", res.get("found_count", 0))

        tab1, tab2 = st.tabs(["📋 List", "🌐 Graph"])

        with tab1:
            subs = res.get("subdomains", [])
            if subs:
                df = pd.DataFrame(subs)
                st.dataframe(df, use_container_width=True)
            else:
                st.info("No subdomains resolved")

        with tab2:
            try:
                fig = create_subdomain_graph(res)
                st.plotly_chart(fig, use_container_width=True, key="subdomain_graph")
            except Exception as e:
                st.error(f"Graph error: {e}")

        # Download
        if res.get("subdomains"):
            st.download_button(
                "📥 Export JSON",
                generate_json_report(res),
                f"subdomains_{domain_input}.json",
                "application/json",
            )


# ═══════════════════════════════════════════════════════════
# PAGE: PASSWORD ANALYZER
# ═══════════════════════════════════════════════════════════

elif page == "🔐 Password Analyzer":
    st.header("🔐 Password Strength AI Analyzer")
    st.markdown(
        "<p style='color:#888;'>Analyze entropy, complexity, patterns, and receive AI recommendations.</p>",
        unsafe_allow_html=True,
    )

    password = st.text_input(
        "Enter Password", type="password", placeholder="Type a password to analyze..."
    )

    if password:
        with st.spinner("Analyzing password security..."):
            result = analyze_password(password)
            st.session_state.password_results = result
            add_report("Password Analysis", result, "analysis")

        st.markdown("<hr style='border-color:#1a1a1a;'>", unsafe_allow_html=True)

        # Score display
        score = result.get("score", 0)
        label = result.get("strength_label", "Unknown")
        color = (
            CYBER_COLORS["secondary"]
            if score >= 80
            else CYBER_COLORS["warning"] if score >= 40 else CYBER_COLORS["danger"]
        )

        col1, col2 = st.columns([1, 2])
        with col1:
            st.markdown(
                f"""
            <div style="text-align:center; padding:1rem; background:#111; border-radius:8px; border:1px solid {color}44;">
                <div style="font-size:3rem; color:{color}; font-weight:bold;">{score}</div>
                <div style="font-size:1.2rem; color:{color};">{label}</div>
                <div style="font-size:0.8rem; color:#888;">/100</div>
            </div>
            """,
                unsafe_allow_html=True,
            )

            try:
                fig = create_entropy_gauge(
                    result.get("entropy_bits", 0), max_entropy=128
                )
                st.plotly_chart(fig, use_container_width=True, key="pass_entropy")
            except Exception as e:
                st.error(f"Gauge error: {e}")

        with col2:
            st.subheader("🔍 Complexity Analysis")
            comp = result.get("complexity", {})
            checks = [
                ("Lowercase (a-z)", comp.get("has_lower", False)),
                ("Uppercase (A-Z)", comp.get("has_upper", False)),
                ("Digits (0-9)", comp.get("has_digit", False)),
                ("Special Chars", comp.get("has_special", False)),
                ("Spaces", comp.get("has_space", False)),
            ]
            for name, check in checks:
                icon = "✅" if check else "❌"
                color = CYBER_COLORS["secondary"] if check else CYBER_COLORS["danger"]
                st.markdown(
                    f'<div style="color:{color}; font-size:0.9rem;">{icon} {name}</div>',
                    unsafe_allow_html=True,
                )

            st.markdown(
                f"<p style='color:#00f0ff; margin-top:0.5rem;'>📏 Length: {result.get('password_length', 0)} characters</p>",
                unsafe_allow_html=True,
            )
            st.markdown(
                f"<p style='color:#00f0ff;'>🔢 Entropy: {result.get('entropy_bits', 0)} bits</p>",
                unsafe_allow_html=True,
            )

        # Patterns
        patterns = result.get("patterns_found", [])
        if patterns:
            st.subheader("⚠️ Patterns Detected")
            for p in patterns:
                render_alert("warning", p)

        if result.get("common_password_match"):
            render_alert(
                "critical", "This password appears in common password dictionaries!"
            )

        # Recommendations
        recs = result.get("recommendations", [])
        if recs:
            st.subheader("💡 AI Recommendations")
            for rec in recs:
                render_alert("info", rec)

        # AI Insight
        insight = generate_ai_insight(
            "password", {"score": score, "entropy": result.get("entropy_bits", 0)}
        )
        render_glow_card("AI Security Insight", insight, "🧠")


# ═══════════════════════════════════════════════════════════
# PAGE: HASHING LABORATORY
# ═══════════════════════════════════════════════════════════

elif page == "🧪 Hashing Laboratory":
    st.header("🧪 Advanced Hashing Laboratory")
    st.markdown(
        "<p style='color:#888;'>Text hashing, file hashing, integrity verification, and hash comparison.</p>",
        unsafe_allow_html=True,
    )

    tab_hash, tab_file, tab_verify = st.tabs(
        ["📝 Text Hash", "📁 File Hash", "✅ Verify Hash"]
    )

    with tab_hash:
        text_input = st.text_area(
            "Input Text", placeholder="Enter text to hash...", height=100
        )
        algo = st.selectbox(
            "Algorithm",
            [
                "MD5",
                "SHA1",
                "SHA256",
                "SHA512",
                "SHA3-256",
                "SHA3-512",
                "BLAKE2b",
                "BLAKE2s",
            ],
        )

        if st.button("🔐 Generate Hash", use_container_width=True):
            if text_input:
                result = hash_text(text_input, algo)
                st.session_state.hash_results = result
                add_report(f"Hash: {algo}", result, "analysis")

                st.markdown(
                    "<hr style='border-color:#1a1a1a;'>", unsafe_allow_html=True
                )
                render_glow_card("Algorithm", result.get("algorithm", algo), "🔧")
                render_glow_card("Hash Value", f"`{result.get('hash', 'N/A')}`", "🔑")
                render_glow_card("Digest Size", f"{result.get('length', 0)} bits", "📏")

                st.download_button(
                    "📥 Copy Hash",
                    generate_txt_report(result.get("hash", "")),
                    "hash.txt",
                    "text/plain",
                )
            else:
                render_alert("warning", "Please enter text to hash")

    with tab_file:
        uploaded_file = st.file_uploader("Upload File", type=None)
        algo_file = st.selectbox(
            "File Algorithm", ["SHA256", "MD5", "SHA1", "SHA512"], key="file_algo"
        )

        if uploaded_file and st.button(
            "🔐 Hash File", use_container_width=True, key="hash_file_btn"
        ):
            bytes_data = uploaded_file.getvalue()
            result = hash_file(bytes_data, algo_file)
            st.session_state.hash_results = result
            add_report(f"File Hash: {uploaded_file.name}", result, "analysis")

            st.markdown("<hr style='border-color:#1a1a1a;'>", unsafe_allow_html=True)
            render_glow_card("Filename", uploaded_file.name, "📄")
            render_glow_card("Algorithm", result.get("algorithm", algo_file), "🔧")
            render_glow_card("Hash", f"`{result.get('hash', 'N/A')}`", "🔑")
            render_glow_card(
                "File Size", format_bytes(result.get("size_bytes", 0)), "📏"
            )

    with tab_verify:
        verify_text = st.text_area(
            "Data to Verify",
            placeholder="Enter text or upload file...",
            height=80,
            key="verify_text",
        )
        verify_algo = st.selectbox(
            "Algorithm", ["SHA256", "MD5", "SHA1", "SHA512"], key="verify_algo"
        )
        expected_hash = st.text_input(
            "Expected Hash", placeholder="Paste expected hash here..."
        )

        if st.button("✅ Verify Integrity", use_container_width=True):
            if verify_text and expected_hash:
                result = verify_hash(verify_text, verify_algo, expected_hash)
                st.session_state.hash_results = result

                st.markdown(
                    "<hr style='border-color:#1a1a1a;'>", unsafe_allow_html=True
                )
                if result.get("match"):
                    render_alert("safe", "✅ HASH MATCH - Integrity verified!")
                else:
                    render_alert(
                        "critical",
                        "❌ HASH MISMATCH - Data may be corrupted or tampered!",
                    )

                render_glow_card("Expected", result.get("expected_hash", "N/A"), "📋")
                render_glow_card("Actual", result.get("actual_hash", "N/A"), "🔍")
            else:
                render_alert("warning", "Please provide both data and expected hash")


# ═══════════════════════════════════════════════════════════
# PAGE: FILE SECURITY ANALYZER
# ═══════════════════════════════════════════════════════════

elif page == "📁 File Security Analyzer":
    st.header("📁 File Security Analyzer")
    st.markdown(
        "<p style='color:#888;'>Upload files for suspicious extension detection, entropy analysis, metadata extraction, and hash generation.</p>",
        unsafe_allow_html=True,
    )

    uploaded_file = st.file_uploader(
        "Upload File for Analysis", type=None, key="file_analyzer"
    )

    if uploaded_file:
        with st.spinner("Analyzing file security..."):
            bytes_data = uploaded_file.getvalue()
            result = analyze_file_security(bytes_data, uploaded_file.name)
            st.session_state.file_results = result
            add_report(f"File Analysis: {uploaded_file.name}", result, "file")

        st.markdown("<hr style='border-color:#1a1a1a;'>", unsafe_allow_html=True)

        # Risk badge
        risk_level = result.get("risk_level", "Low")
        risk_color = severity_color(risk_level.lower())
        st.markdown(
            f"""
        <div style="text-align:center; margin-bottom:1rem;">
            <span style="background-color:{risk_color}33; color:{risk_color}; border:2px solid {risk_color}; border-radius:8px; padding:0.5rem 1.5rem; font-size:1.3rem; font-weight:bold;">
                RISK LEVEL: {risk_level.upper()}
            </span>
        </div>
        """,
            unsafe_allow_html=True,
        )

        col1, col2 = st.columns(2)
        with col1:
            render_glow_card("Filename", result.get("filename", "N/A"), "📄")
            render_glow_card("Size", format_bytes(result.get("size_bytes", 0)), "📏")
            render_glow_card(
                "Extension",
                (
                    f".{result.get('extension', 'N/A')}"
                    if result.get("extension")
                    else "N/A"
                ),
                "🔖",
            )
            render_glow_card("MIME Guess", result.get("mime_guess") or "Unknown", "🎯")
        with col2:
            render_glow_card("MD5", result.get("md5", "N/A"), "🔑")
            render_glow_card("SHA1", result.get("sha1", "N/A"), "🔑")
            render_glow_card("SHA256", result.get("sha256", "N/A"), "🔑")
            render_glow_card("Entropy", f"{result.get('entropy', 0)} bits", "📊")

        if result.get("magic_bytes"):
            render_glow_card("Magic Bytes", result["magic_bytes"], "✨")

        # Warnings
        warnings = result.get("warnings", [])
        if warnings:
            st.subheader("⚠️ Security Warnings")
            for w in warnings:
                render_alert("warning", w)

        if result.get("suspicious"):
            render_alert(
                "critical",
                "File flagged as suspicious based on static analysis. Do not execute.",
            )

        # Recommendations
        recs = result.get("recommendations", [])
        if recs:
            st.subheader("💡 Recommendations")
            for rec in recs:
                render_alert("info", rec)

        # AI Insight
        insight = generate_ai_insight(
            "file", {"suspicious": result.get("suspicious", False)}
        )
        render_glow_card("AI Security Insight", insight, "🧠")

        # Download
        st.download_button(
            "📥 Download Analysis JSON",
            generate_json_report(result),
            f"file_analysis_{uploaded_file.name}.json",
            "application/json",
        )


# ═══════════════════════════════════════════════════════════
# PAGE: VULNERABILITY INTELLIGENCE
# ═══════════════════════════════════════════════════════════

elif page == "⚠️ Vulnerability Intelligence":
    st.header("⚠️ Vulnerability Assessment Simulation")
    st.markdown(
        "<p style='color:#888;'>SAFE simulated vulnerability detection based on scan results. Generates CVSS-style scoring and defensive recommendations.</p>",
        unsafe_allow_html=True,
    )

    st.info(
        "This module requires a network scan result. Run a scan first, or use simulated data."
    )

    use_simulated = st.checkbox("Use Simulated Scan Data", value=False)

    if use_simulated:
        sim_scan = {
            "ip": "192.168.1.100",
            "ports_scanned": 20,
            "open_ports": [
                {"port": 22, "service": "SSH", "state": "open", "severity": "low"},
                {"port": 80, "service": "HTTP", "state": "open", "severity": "medium"},
                {"port": 445, "service": "SMB", "state": "open", "severity": "high"},
                {"port": 3389, "service": "RDP", "state": "open", "severity": "high"},
                {
                    "port": 5900,
                    "service": "VNC",
                    "state": "open",
                    "severity": "critical",
                },
            ],
            "all_results": [
                {"port": 22, "service": "SSH", "state": "open", "severity": "low"},
                {"port": 80, "service": "HTTP", "state": "open", "severity": "medium"},
                {"port": 445, "service": "SMB", "state": "open", "severity": "high"},
                {"port": 3389, "service": "RDP", "state": "open", "severity": "high"},
                {
                    "port": 5900,
                    "service": "VNC",
                    "state": "open",
                    "severity": "critical",
                },
                {"port": 443, "service": "HTTPS", "state": "closed", "severity": "low"},
            ],
            "risk_score": 75,
        }
        st.session_state.scan_results = sim_scan

    if st.session_state.scan_results:
        if st.button("🔍 Run Vulnerability Assessment", use_container_width=True):
            with st.spinner("Simulating vulnerability assessment..."):
                vuln_result = simulate_vulnerability_assessment(
                    st.session_state.scan_results
                )
                st.session_state.vuln_results = vuln_result
                add_report(
                    f"Vuln Assessment: {vuln_result.get('target', 'unknown')}",
                    vuln_result,
                    "scan",
                )

    if st.session_state.vuln_results:
        res = st.session_state.vuln_results
        st.markdown("<hr style='border-color:#1a1a1a;'>", unsafe_allow_html=True)

        # Summary
        summary = res.get("summary", {})
        c1, c2, c3, c4, c5 = st.columns(5)
        with c1:
            st.metric("Critical", summary.get("critical", 0))
        with c2:
            st.metric("High", summary.get("high", 0))
        with c3:
            st.metric("Medium", summary.get("medium", 0))
        with c4:
            st.metric("Low", summary.get("low", 0))
        with c5:
            st.metric("Overall CVSS", res.get("overall_cvss", 0))

        # Risk gauge
        risk_map = {"Critical": 95, "High": 75, "Medium": 50, "Low": 25, "Info": 10}
        risk_val = risk_map.get(res.get("risk_level", "Low"), 25)
        try:
            fig = create_risk_gauge(risk_val, "Vulnerability Risk")
            st.plotly_chart(fig, use_container_width=True, key="vuln_risk")
        except Exception as e:
            st.error(f"Gauge error: {e}")

        # Vulnerability table
        vulns = res.get("vulnerabilities", [])
        if vulns:
            st.subheader("📋 Vulnerability Findings")
            try:
                fig_table = create_vulnerability_summary_table(vulns)
                st.plotly_chart(fig_table, use_container_width=True, key="vuln_table")
            except Exception as e:
                st.error(f"Table error: {e}")

        # Recommendations
        recs = res.get("recommendations", [])
        if recs:
            st.subheader("🛡️ Defensive Recommendations")
            for i, rec in enumerate(recs, 1):
                render_alert("info", f"{i}. {rec}")

        # AI Insight
        insight = generate_ai_insight(
            "vulnerability", {"count": summary.get("total", 0)}
        )
        render_glow_card("AI Security Insight", insight, "🧠")

        # Download
        st.download_button(
            "📥 Export Vuln Report",
            generate_json_report(res),
            "vulnerability_report.json",
            "application/json",
        )
    else:
        st.info(
            "Run a network scan or enable simulated data to perform vulnerability assessment."
        )


# ═══════════════════════════════════════════════════════════
# PAGE: PACKET ANALYTICS
# ═══════════════════════════════════════════════════════════

elif page == "📊 Packet Analytics":
    st.header("📊 Packet Analytics Visualization")
    st.markdown(
        "<p style='color:#888;'>Safe educational network traffic analytics. Uses system network statistics for visualization.</p>",
        unsafe_allow_html=True,
    )

    if st.button("🔄 Refresh Analytics", use_container_width=True):
        with st.spinner("Gathering network telemetry..."):
            result = get_packet_analytics()
            st.session_state.packet_results = result
            add_report("Packet Analytics", result, "analysis")

    if not st.session_state.packet_results:
        with st.spinner("Gathering network telemetry..."):
            result = get_packet_analytics()
            st.session_state.packet_results = result

    if st.session_state.packet_results:
        res = st.session_state.packet_results
        st.markdown("<hr style='border-color:#1a1a1a;'>", unsafe_allow_html=True)

        if "error" in res and res["error"]:
            st.warning(res["error"])

        # Protocol distribution
        proto_dist = res.get("protocol_distribution", {})
        if not proto_dist:
            proto_dist = res.get("packet_simulation", {}).get(
                "protocol_distribution", {"TCP": 65, "UDP": 25, "ICMP": 8, "Other": 2}
            )

        col1, col2 = st.columns(2)
        with col1:
            try:
                fig = create_protocol_distribution(proto_dist)
                st.plotly_chart(fig, use_container_width=True, key="packet_proto")
            except Exception as e:
                st.error(f"Pie chart error: {e}")

        with col2:
            traffic = res.get("traffic_stats", {})
            if traffic:
                render_glow_card(
                    "Bytes Sent", format_bytes(traffic.get("bytes_sent", 0)), "📤"
                )
                render_glow_card(
                    "Bytes Received", format_bytes(traffic.get("bytes_recv", 0)), "📥"
                )
                render_glow_card(
                    "Packets Sent", f"{traffic.get('packets_sent', 0):,}", "📦"
                )
                render_glow_card(
                    "Packets Received", f"{traffic.get('packets_recv', 0):,}", "📦"
                )
            else:
                sim = res.get("packet_simulation", {})
                if sim:
                    render_glow_card(
                        "Bandwidth",
                        f"{sim.get('bandwidth_mbps', 0)} Mbps (simulated)",
                        "🌐",
                    )
                    render_glow_card("Note", sim.get("note", ""), "ℹ️")

        # Interfaces
        interfaces = res.get("interfaces", [])
        if interfaces:
            st.subheader("🖥️ Network Interfaces")
            df = pd.DataFrame(interfaces)
            st.dataframe(df, use_container_width=True)

        # Connections
        if "connections" in res and res["connections"]:
            st.subheader("🔗 Active Connections")
            df_conns = pd.DataFrame(res["connections"])
            st.dataframe(df_conns, use_container_width=True)
        elif "connections_error" in res:
            st.warning(res["connections_error"])


# ═══════════════════════════════════════════════════════════
# PAGE: SYSTEM MONITOR
# ═══════════════════════════════════════════════════════════

elif page == "💻 System Monitor":
    st.header("💻 System Monitor")
    st.markdown(
        "<p style='color:#888;'>Real-time CPU, RAM, disk, network, and process monitoring.</p>",
        unsafe_allow_html=True,
    )

    if st.button("🔄 Refresh Metrics", use_container_width=True):
        with st.spinner("Gathering system metrics..."):
            result = get_system_monitor_data()
            st.session_state.system_results = result

    if not st.session_state.system_results:
        with st.spinner("Gathering system metrics..."):
            result = get_system_monitor_data()
            st.session_state.system_results = result

    if st.session_state.system_results:
        res = st.session_state.system_results

        if "error" in res and res["error"]:
            st.error(res["error"])
            st.info("Install psutil: pip install psutil")
        else:
            st.markdown("<hr style='border-color:#1a1a1a;'>", unsafe_allow_html=True)

            # Gauges
            cpu = res.get("cpu", {}).get("percent", 0)
            mem = res.get("memory", {}).get("percent", 0)
            disk = res.get("disk", {}).get("percent", 0)

            try:
                fig = create_system_gauges(cpu, mem, disk)
                st.plotly_chart(fig, use_container_width=True, key="sys_gauges")
            except Exception as e:
                st.error(f"Gauge error: {e}")

            # Details
            col1, col2, col3 = st.columns(3)
            with col1:
                st.subheader("🖥️ CPU")
                cpu_data = res.get("cpu", {})
                st.markdown(
                    f"<p style='color:#00f0ff;'>Physical Cores: {cpu_data.get('count_physical', 'N/A')}</p>",
                    unsafe_allow_html=True,
                )
                st.markdown(
                    f"<p style='color:#00f0ff;'>Logical Cores: {cpu_data.get('count_logical', 'N/A')}</p>",
                    unsafe_allow_html=True,
                )
                per_cpu = cpu_data.get("per_cpu", [])
                if per_cpu:
                    cpu_labels = [f"Core {i}" for i in range(len(per_cpu))]
                    fig_cpu = go.Figure(
                        go.Bar(
                            x=cpu_labels,
                            y=per_cpu,
                            marker=dict(color=CYBER_COLORS["primary"]),
                        )
                    )
                    fig_cpu.update_layout(
                        paper_bgcolor=CYBER_COLORS["dark"],
                        plot_bgcolor=CYBER_COLORS["panel"],
                        font=dict(
                            color=CYBER_COLORS["text"], family="Courier New, monospace"
                        ),
                        margin=dict(l=20, r=20, t=30, b=20),
                        height=250,
                        xaxis=dict(
                            tickfont=dict(color=CYBER_COLORS["text"]),
                            gridcolor=CYBER_COLORS["grid"],
                        ),
                        yaxis=dict(
                            tickfont=dict(color=CYBER_COLORS["text"]),
                            gridcolor=CYBER_COLORS["grid"],
                            title="Usage %",
                        ),
                    )
                    st.plotly_chart(
                        fig_cpu, use_container_width=True, key="sys_cpu_bar"
                    )

            with col2:
                st.subheader("🧠 Memory")
                mem_data = res.get("memory", {})
                st.markdown(
                    f"<p style='color:#00f0ff;'>Total: {format_bytes(mem_data.get('total', 0))}</p>",
                    unsafe_allow_html=True,
                )
                st.markdown(
                    f"<p style='color:#00f0ff;'>Available: {format_bytes(mem_data.get('available', 0))}</p>",
                    unsafe_allow_html=True,
                )
                st.markdown(
                    f"<p style='color:#00f0ff;'>Used: {format_bytes(mem_data.get('used', 0))}</p>",
                    unsafe_allow_html=True,
                )

            with col3:
                st.subheader("💾 Disk")
                disk_data = res.get("disk", {})
                st.markdown(
                    f"<p style='color:#00f0ff;'>Total: {format_bytes(disk_data.get('total', 0))}</p>",
                    unsafe_allow_html=True,
                )
                st.markdown(
                    f"<p style='color:#00f0ff;'>Used: {format_bytes(disk_data.get('used', 0))}</p>",
                    unsafe_allow_html=True,
                )
                st.markdown(
                    f"<p style='color:#00f0ff;'>Free: {format_bytes(disk_data.get('free', 0))}</p>",
                    unsafe_allow_html=True,
                )

            # Processes
            procs = res.get("processes", [])
            if procs:
                st.subheader("⚙️ Top Processes")
                df = pd.DataFrame(procs)
                st.dataframe(df, use_container_width=True)

            # Boot time
            if res.get("boot_time"):
                st.markdown(
                    f"<p style='color:#888; font-size:0.8rem;'>System Boot: {res['boot_time']}</p>",
                    unsafe_allow_html=True,
                )


# ═══════════════════════════════════════════════════════════
# PAGE: UPLOAD CENTER
# ═══════════════════════════════════════════════════════════

elif page == "📂 Upload Center":
    st.header("📂 Upload Center")
    st.markdown(
        "<p style='color:#888;'>Upload threat logs, CSV data, or PCAP simulation files for analysis and visualization.</p>",
        unsafe_allow_html=True,
    )

    uploaded = st.file_uploader(
        "Upload Files",
        type=["txt", "csv", "json", "log", "pcap", "pcapng"],
        accept_multiple_files=True,
        key="upload_center",
    )

    if uploaded:
        for idx, file in enumerate(uploaded):
            bytes_data = file.getvalue()
            st.session_state.uploaded_files.append(
                {
                    "name": file.name,
                    "size": len(bytes_data),
                    "type": file.type,
                    "timestamp": datetime.datetime.now().isoformat(),
                }
            )

            st.markdown(f"<hr style='border-color:#1a1a1a;'>", unsafe_allow_html=True)
            st.markdown(
                f"<h4 style='color:#00f0ff;'>📄 {file.name}</h4>",
                unsafe_allow_html=True,
            )

            # Parse based on extension
            ext = file.name.split(".")[-1].lower()

            if ext == "csv":
                try:
                    df = pd.read_csv(io.BytesIO(bytes_data))
                    st.dataframe(df, use_container_width=True)

                    # Auto chart if numeric columns exist
                    numeric_cols = df.select_dtypes(
                        include=[np.number]
                    ).columns.tolist()
                    if numeric_cols:
                        fig_upload = go.Figure()
                        for col in numeric_cols[:3]:
                            fig_upload.add_trace(
                                go.Bar(
                                    x=df.index.astype(str),
                                    y=df[col],
                                    name=col,
                                    marker=dict(color=CYBER_COLORS["primary"]),
                                )
                            )
                        fig_upload.update_layout(
                            paper_bgcolor=CYBER_COLORS["dark"],
                            plot_bgcolor=CYBER_COLORS["panel"],
                            font=dict(
                                color=CYBER_COLORS["text"],
                                family="Courier New, monospace",
                            ),
                            barmode="group",
                            margin=dict(l=20, r=20, t=30, b=20),
                            height=300,
                            showlegend=True,
                            legend=dict(
                                font=dict(color=CYBER_COLORS["text"]),
                                bgcolor=CYBER_COLORS["panel"],
                            ),
                            xaxis=dict(
                                tickfont=dict(color=CYBER_COLORS["text"]),
                                gridcolor=CYBER_COLORS["grid"],
                            ),
                            yaxis=dict(
                                tickfont=dict(color=CYBER_COLORS["text"]),
                                gridcolor=CYBER_COLORS["grid"],
                            ),
                        )
                        st.plotly_chart(
                            fig_upload,
                            use_container_width=True,
                            key=f"upload_bar_{idx}",
                        )
                except Exception as e:
                    st.error(f"CSV parse error: {e}")

            elif ext == "json":
                try:
                    data = json.loads(bytes_data.decode("utf-8"))
                    st.json(data)
                except Exception as e:
                    st.error(f"JSON parse error: {e}")

            elif ext in ["txt", "log"]:
                text = bytes_data.decode("utf-8", errors="ignore")
                render_terminal_box(text[:3000], height=250)

            else:
                st.info(
                    f"File uploaded ({format_bytes(len(bytes_data))}). Use File Security Analyzer for deep inspection."
                )

        add_report(
            f"Upload Center: {len(uploaded)} files",
            st.session_state.uploaded_files,
            "file",
        )

    if st.session_state.uploaded_files:
        st.markdown("<hr style='border-color:#1a1a1a;'>", unsafe_allow_html=True)
        st.subheader("📋 Upload History")
        df = pd.DataFrame(st.session_state.uploaded_files)
        st.dataframe(df, use_container_width=True)


# ═══════════════════════════════════════════════════════════
# PAGE: DOWNLOAD CENTER
# ═══════════════════════════════════════════════════════════

elif page == "📥 Download Center":
    st.header("📥 Download Center")
    st.markdown(
        "<p style='color:#888;'>Export reports, analytics, and generated security intelligence in multiple formats.</p>",
        unsafe_allow_html=True,
    )

    if not st.session_state.reports:
        st.info(
            "No reports available. Run scans and analyses to generate downloadable reports."
        )
    else:
        st.subheader("📋 Generated Reports")

        for r in reversed(st.session_state.reports):
            with st.expander(f"{r['id']} - {r['title']} ({r['timestamp'][:19]})"):
                st.markdown(f"**Type:** {r['type']}")
                st.markdown(f"**Timestamp:** {r['timestamp']}")

                col1, col2, col3 = st.columns(3)
                with col1:
                    st.download_button(
                        "📄 JSON",
                        generate_json_report(r["data"]),
                        f"{r['id']}_{r['type']}.json",
                        "application/json",
                        key=f"dl_json_{r['id']}",
                    )
                with col2:
                    if isinstance(r["data"], list):
                        st.download_button(
                            "📊 CSV",
                            generate_csv_report(r["data"]),
                            f"{r['id']}_{r['type']}.csv",
                            "text/csv",
                            key=f"dl_csv_{r['id']}",
                        )
                with col3:
                    txt_content = generate_security_report(
                        r["title"],
                        r["data"] if isinstance(r["data"], list) else [],
                        ["See JSON export for full structured data."],
                        {"report_id": r["id"], "type": r["type"]},
                    )
                    st.download_button(
                        "📝 TXT",
                        generate_txt_report(txt_content),
                        f"{r['id']}_{r['type']}.txt",
                        "text/plain",
                        key=f"dl_txt_{r['id']}",
                    )

    # Bulk export
    st.markdown("<hr style='border-color:#1a1a1a;'>", unsafe_allow_html=True)
    st.subheader("📦 Bulk Export")

    if st.session_state.reports:
        all_data = {
            "platform": "HackBoard",
            "developer": "issu321",
            "github": "https://github.com/issu321/hackboard",
            "export_timestamp": datetime.datetime.now().isoformat(),
            "reports": st.session_state.reports,
        }
        st.download_button(
            "📥 Export All Reports (JSON)",
            generate_json_report(all_data),
            "all_reports.json",
            "application/json",
            use_container_width=True,
        )


# ═══════════════════════════════════════════════════════════
# PAGE: CYBER ANALYTICS
# ═══════════════════════════════════════════════════════════

elif page == "📈 Cyber Analytics":
    st.header("📈 Cyber Analytics")
    st.markdown(
        "<p style='color:#888;'>Advanced visualization engine with benchmark analytics and custom chart generation.</p>",
        unsafe_allow_html=True,
    )

    chart_type = st.selectbox("Chart Type", ["Radar", "Bar", "Pie", "Line", "Heatmap"])

    if chart_type == "Radar":
        categories = st.text_input(
            "Categories (comma-separated)",
            "Speed,Security,Reliability,Scalability,Usability",
        )
        values = st.text_input("Values (comma-separated, 0-100)", "85,70,90,65,80")
        if st.button("Generate Radar Chart", use_container_width=True):
            cats = [c.strip() for c in categories.split(",")]
            vals = [float(v.strip()) for v in values.split(",")]
            if len(cats) == len(vals):
                try:
                    fig = create_radar_chart(
                        cats, vals, "Custom Radar", CYBER_COLORS["primary"]
                    )
                    st.plotly_chart(fig, use_container_width=True, key="custom_radar")
                except Exception as e:
                    st.error(f"Chart error: {e}")
            else:
                render_alert("error", "Categories and values count must match")

    elif chart_type == "Bar":
        data_input = st.text_area(
            "Data (JSON array of objects)",
            '[{"name":"A","value":30},{"name":"B","value":50}]',
        )
        x_key = st.text_input("X Key", "name")
        y_key = st.text_input("Y Key", "value")
        if st.button("Generate Bar Chart", use_container_width=True):
            try:
                data = json.loads(data_input)
                fig = create_bar_chart(data, x_key, y_key, "Custom Bar Chart")
                st.plotly_chart(fig, use_container_width=True, key="custom_bar")
            except Exception as e:
                st.error(f"Chart error: {e}")

    elif chart_type == "Pie":
        labels = st.text_input("Labels (comma-separated)", "A,B,C,D")
        values = st.text_input("Values (comma-separated)", "30,25,25,20")
        if st.button("Generate Pie Chart", use_container_width=True):
            labs = [l.strip() for l in labels.split(",")]
            vals = [float(v.strip()) for v in values.split(",")]
            if len(labs) == len(vals):
                try:
                    fig = create_pie_chart(labs, vals, "Custom Pie Chart")
                    st.plotly_chart(fig, use_container_width=True, key="custom_pie")
                except Exception as e:
                    st.error(f"Chart error: {e}")
            else:
                render_alert("error", "Labels and values count must match")

    elif chart_type == "Line":
        x_vals = st.text_input("X Values (comma-separated)", "1,2,3,4,5")
        y_vals = st.text_input("Y Values (comma-separated)", "10,25,15,30,20")
        if st.button("Generate Line Chart", use_container_width=True):
            x = [v.strip() for v in x_vals.split(",")]
            y = [float(v.strip()) for v in y_vals.split(",")]
            if len(x) == len(y):
                try:
                    fig = create_line_chart(x, y, "Custom Line Chart")
                    st.plotly_chart(fig, use_container_width=True, key="custom_line")
                except Exception as e:
                    st.error(f"Chart error: {e}")
            else:
                render_alert("error", "X and Y values count must match")

    elif chart_type == "Heatmap":
        st.info(
            "Use Threat Intelligence page for pre-configured heatmaps, or generate custom data via Upload Center."
        )


# ═══════════════════════════════════════════════════════════
# PAGE: DNS INTELLIGENCE
# ═══════════════════════════════════════════════════════════

elif page == "🌍 DNS Intelligence":
    st.header("🌍 DNS Intelligence")
    st.markdown(
        "<p style='color:#888;'>Multi-record DNS lookup with visualization of DNS infrastructure.</p>",
        unsafe_allow_html=True,
    )

    domain = st.text_input("Domain", placeholder="e.g., google.com", key="dns_domain")
    record_types = st.multiselect(
        "Record Types",
        ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR"],
        default=["A", "MX", "NS", "TXT"],
    )

    if st.button("🔍 Resolve DNS", use_container_width=True):
        if not validate_domain(domain):
            render_alert("error", "Invalid domain")
        else:
            with st.spinner("Querying DNS records..."):
                result = dns_lookup(domain, record_types)
                st.session_state.domain_results = result
                add_report(f"DNS: {domain}", result, "domain")

            st.markdown("<hr style='border-color:#1a1a1a;'>", unsafe_allow_html=True)

            if "error" in result and result["error"]:
                st.warning(result["error"])

            records = result.get("records", {})
            if records:
                for rtype, values in records.items():
                    with st.expander(f"📋 {rtype} Records ({len(values)})"):
                        for v in values:
                            st.markdown(
                                f'<div class="alert-info">{v}</div>',
                                unsafe_allow_html=True,
                            )

                # DNS chart
                labels = list(records.keys())
                counts = [len(v) for v in records.values()]
                try:
                    fig = create_bar_chart(
                        [
                            {"type": l, "count": c, "color": CYBER_COLORS["primary"]}
                            for l, c in zip(labels, counts)
                        ],
                        "type",
                        "count",
                        "DNS Record Distribution",
                    )
                    st.plotly_chart(fig, use_container_width=True, key="dns_bar")
                except Exception as e:
                    st.error(f"Chart error: {e}")
            else:
                st.info("No DNS records found")


# ═══════════════════════════════════════════════════════════
# PAGE: NETWORK TOPOLOGY
# ═══════════════════════════════════════════════════════════

elif page == "🛰️ Network Topology":
    st.header("🛰️ Network Topology")
    st.markdown(
        "<p style='color:#888;'>Visualize network scan results as interactive node graphs.</p>",
        unsafe_allow_html=True,
    )

    if st.session_state.scan_results:
        try:
            fig = create_network_topology_graph(st.session_state.scan_results)
            st.plotly_chart(fig, use_container_width=True, key="topo_main")
        except Exception as e:
            st.error(f"Topology error: {e}")

        st.info(
            "Run a network scan in 'Advanced Network Scanner' to populate this topology view."
        )
    else:
        st.info("No scan data available. Run a network scan to generate topology.")

        # Show example topology with simulated data
        if st.checkbox("Show Example Topology"):
            sim = {
                "ip": "192.168.1.1",
                "all_results": [
                    {"port": 80, "service": "HTTP", "state": "open", "severity": "low"},
                    {
                        "port": 443,
                        "service": "HTTPS",
                        "state": "open",
                        "severity": "low",
                    },
                    {"port": 22, "service": "SSH", "state": "open", "severity": "low"},
                    {
                        "port": 3389,
                        "service": "RDP",
                        "state": "open",
                        "severity": "high",
                    },
                    {
                        "port": 21,
                        "service": "FTP",
                        "state": "closed",
                        "severity": "medium",
                    },
                ],
            }
            try:
                fig = create_network_topology_graph(sim)
                st.plotly_chart(fig, use_container_width=True, key="topo_example")
            except Exception as e:
                st.error(f"Example topology error: {e}")


# ═══════════════════════════════════════════════════════════
# PAGE: REPORTS CENTER
# ═══════════════════════════════════════════════════════════

elif page == "📋 Reports Center":
    st.header("📋 Reports Center")
    st.markdown(
        "<p style='color:#888;'>View, manage, and export all generated security reports and intelligence.</p>",
        unsafe_allow_html=True,
    )

    if not st.session_state.reports:
        st.info(
            "No reports generated yet. Use the platform tools to create security reports."
        )
    else:
        # Filter
        report_types = list(set(r["type"] for r in st.session_state.reports))
        filter_type = st.selectbox("Filter by Type", ["All"] + report_types)

        filtered = [
            r
            for r in st.session_state.reports
            if filter_type == "All" or r["type"] == filter_type
        ]

        st.markdown(
            f"<p style='color:#00f0ff;'>Showing {len(filtered)} reports</p>",
            unsafe_allow_html=True,
        )

        for r in reversed(filtered):
            with st.expander(f"{r['id']} | {r['title']} | {r['timestamp'][:19]}"):
                st.json(r["data"])

        # Clear button
        if st.button("🗑️ Clear All Reports", use_container_width=True):
            st.session_state.reports = []
            st.rerun()


# ═══════════════════════════════════════════════════════════
# PAGE: AI SECURITY INSIGHTS
# ═══════════════════════════════════════════════════════════

elif page == "🤖 AI Security Insights":
    st.header("🤖 AI Security Insights")
    st.markdown(
        "<p style='color:#888;'>AI-like security analysis engine generating contextual insights across all platform data.</p>",
        unsafe_allow_html=True,
    )

    # Aggregate all available data for insights
    insights = []

    if st.session_state.scan_results:
        scan = st.session_state.scan_results
        insights.append(
            {
                "context": "Network Scan",
                "insight": generate_ai_insight(
                    "network",
                    {
                        "open_ports": scan.get("open_ports", []),
                        "risk_score": scan.get("risk_score", 0),
                    },
                ),
                "data": f"Target: {scan.get('ip', 'unknown')}, Risk: {scan.get('risk_score', 0)}",
            }
        )

    if st.session_state.password_results:
        pwd = st.session_state.password_results
        insights.append(
            {
                "context": "Password Analysis",
                "insight": generate_ai_insight(
                    "password",
                    {
                        "score": pwd.get("score", 0),
                        "entropy": pwd.get("entropy_bits", 0),
                    },
                ),
                "data": f"Score: {pwd.get('score', 0)}/100, Entropy: {pwd.get('entropy_bits', 0)} bits",
            }
        )

    if st.session_state.file_results:
        file_res = st.session_state.file_results
        insights.append(
            {
                "context": "File Analysis",
                "insight": generate_ai_insight(
                    "file", {"suspicious": file_res.get("suspicious", False)}
                ),
                "data": f"File: {file_res.get('filename', 'unknown')}, Risk: {file_res.get('risk_level', 'Low')}",
            }
        )

    if st.session_state.vuln_results:
        vuln = st.session_state.vuln_results
        insights.append(
            {
                "context": "Vulnerability Assessment",
                "insight": generate_ai_insight(
                    "vulnerability", {"count": vuln.get("summary", {}).get("total", 0)}
                ),
                "data": f"Total: {vuln.get('summary', {}).get('total', 0)}, Level: {vuln.get('risk_level', 'Low')}",
            }
        )

    if not insights:
        st.info(
            "No analysis data available. Run scans and analyses to generate AI insights."
        )
        render_glow_card(
            "Tip",
            "Use the Network Scanner, Password Analyzer, or File Security Analyzer to populate data for AI insights.",
            "💡",
        )
    else:
        for ins in insights:
            render_glow_card(f"{ins['context']} - {ins['data']}", ins["insight"], "🧠")

        # Cross-domain correlation
        if len(insights) > 1:
            st.markdown("<hr style='border-color:#1a1a1a;'>", unsafe_allow_html=True)
            st.subheader("🔗 Cross-Domain Correlation")

            correlation = "Multiple security vectors analyzed. "
            risk_count = sum(
                1
                for i in insights
                if "high" in i["insight"].lower() or "critical" in i["insight"].lower()
            )
            if risk_count >= 2:
                correlation += f"Concerning correlation detected: {risk_count} modules report elevated risk. Compound attack probability increases when multiple weaknesses coexist. Recommend immediate defense hardening."
                render_alert("critical", correlation)
            else:
                correlation += "No critical cross-domain correlations detected. Maintain standard monitoring and periodic reassessment."
                render_alert("safe", correlation)

    # Platform health summary
    st.markdown("<hr style='border-color:#1a1a1a;'>", unsafe_allow_html=True)
    st.subheader("📊 Platform Health Summary")

    health_metrics = {
        "Reports Generated": len(st.session_state.reports),
        "Scans Completed": len(
            [r for r in st.session_state.reports if r["type"] == "scan"]
        ),
        "Files Analyzed": len(
            [r for r in st.session_state.reports if r["type"] == "file"]
        ),
        "Domains Intel": len(
            [r for r in st.session_state.reports if r["type"] == "domain"]
        ),
        "Platform Uptime": "Active",
        "AI Engine": "Online",
    }

    cols = st.columns(3)
    for i, (k, v) in enumerate(health_metrics.items()):
        with cols[i % 3]:
            st.metric(k, v)


# ═══════════════════════════════════════════════════════════
# FOOTER (All pages)
# ═══════════════════════════════════════════════════════════

st.markdown(
    """
<div class="footer">
    <p>
        🛡️ <strong>HackBoard</strong> — Security Intelligence Platform v1.0.0<br>
        Developed by <span style="color:#00f0ff;">issu321</span> | 
        <a href="https://github.com/issu321/hackboard" style="color:#00f0ff; text-decoration:none;">GitHub Repository</a><br>
        <span style="color:#444;">Strictly Educational • Defensive • Ethical Hacking Oriented</span>
    </p>
</div>
""",
    unsafe_allow_html=True,
)
