
"""
HackBoard — Analytics & Visualization Engine
==============================================

Advanced charts, heatmaps, node graphs, radar charts, benchmark analytics,
and reporting systems. All visualizations use a cyberpunk dark theme.

Author: issu321
License: MIT
"""

import math
import random
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from hackboard.utils import (
    export_to_csv,
    export_to_json,
    export_to_txt,
    format_bytes,
    generate_security_report,
    severity_color,
)

# Optional networkx
try:
    import networkx as nx
    NETWORKX_AVAILABLE: bool = True
except ImportError:
    NETWORKX_AVAILABLE = False


# ═══════════════════════════════════════════════════════════
# COLOR UTILITIES
# ═══════════════════════════════════════════════════════════


def hex_to_rgba(hex_color: str, alpha: float = 1.0) -> str:
    """Convert a 6-digit hex color to an rgba string for Plotly.

    Args:
        hex_color: Hex color string (e.g., "#00f0ff").
        alpha: Alpha transparency value (0.0-1.0).

    Returns:
        rgba() CSS string.
    """
    hex_color = hex_color.lstrip("#")
    if len(hex_color) == 3:
        hex_color = "".join([c * 2 for c in hex_color])
    r = int(hex_color[0:2], 16)
    g = int(hex_color[2:4], 16)
    b = int(hex_color[4:6], 16)
    return f"rgba({r},{g},{b},{alpha})"


# ═══════════════════════════════════════════════════════════
# COLOR PALETTES
# ═══════════════════════════════════════════════════════════

CYBER_COLORS: Dict[str, str] = {
    "primary": "#00f0ff",
    "secondary": "#00ff41",
    "accent": "#ff00ff",
    "warning": "#ffaa00",
    "danger": "#ff0040",
    "dark": "#0a0a0a",
    "panel": "#111111",
    "text": "#e0e0e0",
    "grid": "#222222"
}

CYBER_PALETTE: List[str] = [
    "#00f0ff", "#00ff41", "#ff00ff", "#ffaa00",
    "#ff0040", "#7b2cbf", "#3a86ff", "#fb5607"
]


# ═══════════════════════════════════════════════════════════
# RADAR CHARTS
# ═══════════════════════════════════════════════════════════


def create_radar_chart(
    categories: List[str],
    values: List[float],
    title: str = "Security Radar",
    fill_color: str = "#00f0ff"
) -> go.Figure:
    """Create a cyberpunk-styled radar chart.

    Args:
        categories: List of category labels.
        values: List of values (0-100) matching categories.
        title: Chart title.
        fill_color: Fill color hex string.

    Returns:
        Plotly Figure object.
    """
    fig = go.Figure()

    fig.add_trace(go.Scatterpolar(
        r=values + [values[0]],  # Close the shape
        theta=categories + [categories[0]],
        fill="toself",
        fillcolor=hex_to_rgba(fill_color, 0.2),
        line=dict(color=fill_color, width=2),
        marker=dict(size=6, color=fill_color),
        name="Score"
    ))

    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 100],
                tickfont=dict(color=CYBER_COLORS["text"], size=10),
                gridcolor=CYBER_COLORS["grid"],
                linecolor=CYBER_COLORS["grid"]
            ),
            angularaxis=dict(
                tickfont=dict(color=CYBER_COLORS["text"], size=11),
                gridcolor=CYBER_COLORS["grid"],
                linecolor=CYBER_COLORS["grid"]
            ),
            bgcolor=CYBER_COLORS["panel"]
        ),
        paper_bgcolor=CYBER_COLORS["dark"],
        plot_bgcolor=CYBER_COLORS["dark"],
        font=dict(color=CYBER_COLORS["text"], family="Courier New, monospace"),
        title=dict(
            text=title,
            font=dict(color=CYBER_COLORS["primary"], size=16),
            x=0.5
        ),
        margin=dict(l=60, r=60, t=60, b=40),
        showlegend=False
    )
    return fig


# ═══════════════════════════════════════════════════════════
# HEATMAPS
# ═══════════════════════════════════════════════════════════


def create_heatmap(
    data: List[List[float]],
    x_labels: List[str],
    y_labels: List[str],
    title: str = "Threat Heatmap",
    colorscale: str = "Viridis"
) -> go.Figure:
    """Create a cyberpunk-styled heatmap.

    Args:
        data: 2D list of float values.
        x_labels: X-axis labels.
        y_labels: Y-axis labels.
        title: Chart title.
        colorscale: Plotly colorscale name.

    Returns:
        Plotly Figure object.
    """
    fig = go.Figure(data=go.Heatmap(
        z=data,
        x=x_labels,
        y=y_labels,
        colorscale=colorscale,
        hoverongaps=False,
        colorbar=dict(
            tickfont=dict(color=CYBER_COLORS["text"]),
            title=dict(text="Intensity", font=dict(color=CYBER_COLORS["text"]))
        )
    ))

    fig.update_layout(
        paper_bgcolor=CYBER_COLORS["dark"],
        plot_bgcolor=CYBER_COLORS["dark"],
        font=dict(color=CYBER_COLORS["text"], family="Courier New, monospace"),
        title=dict(
            text=title,
            font=dict(color=CYBER_COLORS["primary"], size=16),
            x=0.5
        ),
        xaxis=dict(tickfont=dict(color=CYBER_COLORS["text"]), gridcolor=CYBER_COLORS["grid"]),
        yaxis=dict(tickfont=dict(color=CYBER_COLORS["text"]), gridcolor=CYBER_COLORS["grid"]),
        margin=dict(l=80, r=40, t=60, b=60)
    )
    return fig


def create_port_heatmap(scan_results: Dict[str, Any]) -> go.Figure:
    """Create a port scan heatmap from scan results.

    Args:
        scan_results: Dictionary from scan_ports().

    Returns:
        Plotly Figure object.
    """
    all_results = scan_results.get("all_results", [])
    if not all_results:
        return create_heatmap([[0]], ["N/A"], ["N/A"], "No Scan Data")

    states = [r["state"] for r in all_results]
    severities = [r.get("severity", "info") for r in all_results]

    state_map = {"open": 3, "filtered": 2, "closed": 1, "error": 0}
    z = [[state_map.get(s, 0)] for s in states]

    fig = go.Figure(data=go.Heatmap(
        z=z,
        x=[str(r["port"]) for r in all_results],
        y=["Status"],
        colorscale=[[0, "#333"], [0.5, "#ffaa00"], [1, "#ff0040"]],
        showscale=False,
        text=[[s.upper() for s in states]],
        texttemplate="%{text}",
        textfont=dict(size=10, color="white")
    ))

    fig.update_layout(
        paper_bgcolor=CYBER_COLORS["dark"],
        plot_bgcolor=CYBER_COLORS["dark"],
        font=dict(color=CYBER_COLORS["text"], family="Courier New, monospace"),
        title=dict(
            text="Port Status Heatmap",
            font=dict(color=CYBER_COLORS["primary"], size=16),
            x=0.5
        ),
        xaxis=dict(tickfont=dict(color=CYBER_COLORS["text"], size=9), title="Port"),
        yaxis=dict(showticklabels=False),
        margin=dict(l=40, r=20, t=60, b=60),
        height=250
    )
    return fig


# ═══════════════════════════════════════════════════════════
# NODE / NETWORK GRAPHS
# ═══════════════════════════════════════════════════════════


def create_network_topology_graph(scan_results: Dict[str, Any]) -> go.Figure:
    """Create a network topology node graph from scan results.

    Args:
        scan_results: Dictionary from scan_ports().

    Returns:
        Plotly Figure object with interactive node graph.
    """
    all_results = scan_results.get("all_results", [])

    if not all_results:
        fig = go.Figure()
        fig.add_annotation(
            text="No scan data available",
            xref="paper", yref="paper",
            showarrow=False,
            font=dict(size=16, color=CYBER_COLORS["warning"])
        )
        return fig

    if NETWORKX_AVAILABLE:
        G = nx.Graph()
        target_ip = scan_results.get("ip", "Target")
        G.add_node(target_ip, type="target")

        for r in all_results:
            port = r["port"]
            service = r.get("service", "Unknown")
            state = r["state"]
            node_id = f"{port}:{service}"
            G.add_node(node_id, type=state, port=port, service=service)
            weight = 2 if state == "open" else 0.5
            G.add_edge(target_ip, node_id, weight=weight)

        pos = nx.spring_layout(G, seed=42, k=2)

        edge_x, edge_y = [], []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        node_x, node_y, node_color, node_text, node_size = [], [], [], [], []
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            attrs = G.nodes[node]
            if attrs.get("type") == "target":
                node_color.append(CYBER_COLORS["primary"])
                node_text.append(f"🎯 {node}")
                node_size.append(30)
            elif attrs.get("type") == "open":
                node_color.append(CYBER_COLORS["danger"])
                node_text.append(f"🔓 {node}")
                node_size.append(20)
            else:
                node_color.append(CYBER_COLORS["grid"])
                node_text.append(f"🔒 {node}")
                node_size.append(12)
    else:
        # Fallback without networkx
        node_x, node_y = [0], [0]
        node_color = [CYBER_COLORS["primary"]]
        node_text = ["Target"]
        node_size = [30]
        edge_x, edge_y = [], []

        angle_step = 2 * math.pi / max(len(all_results), 1)
        for i, r in enumerate(all_results):
            angle = i * angle_step
            radius = 1.5
            x = radius * math.cos(angle)
            y = radius * math.sin(angle)
            node_x.append(x)
            node_y.append(y)
            if r["state"] == "open":
                node_color.append(CYBER_COLORS["danger"])
            else:
                node_color.append(CYBER_COLORS["grid"])
            node_text.append(f"{r['port']}:{r.get('service', '?')}")
            node_size.append(15 if r["state"] == "open" else 8)
            edge_x.extend([0, x, None])
            edge_y.extend([0, y, None])

    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=edge_x, y=edge_y,
        mode="lines",
        line=dict(color=CYBER_COLORS["grid"], width=1),
        hoverinfo="none",
        showlegend=False
    ))

    fig.add_trace(go.Scatter(
        x=node_x, y=node_y,
        mode="markers+text",
        marker=dict(
            size=node_size,
            color=node_color,
            line=dict(width=2, color=CYBER_COLORS["dark"])
        ),
        text=node_text,
        textposition="top center",
        textfont=dict(size=9, color=CYBER_COLORS["text"]),
        hoverinfo="text",
        showlegend=False
    ))

    fig.update_layout(
        paper_bgcolor=CYBER_COLORS["dark"],
        plot_bgcolor=CYBER_COLORS["dark"],
        font=dict(color=CYBER_COLORS["text"], family="Courier New, monospace"),
        title=dict(
            text="Network Topology",
            font=dict(color=CYBER_COLORS["primary"], size=16),
            x=0.5
        ),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        margin=dict(l=20, r=20, t=60, b=20),
        height=500
    )
    return fig


def create_subdomain_graph(subdomain_data: Dict[str, Any]) -> go.Figure:
    """Create a subdomain relationship graph.

    Args:
        subdomain_data: Dictionary from subdomain_enumeration().

    Returns:
        Plotly Figure object with subdomain node graph.
    """
    subs = subdomain_data.get("subdomains", [])
    domain = subdomain_data.get("domain", "domain")

    if not subs:
        fig = go.Figure()
        fig.add_annotation(
            text="No subdomains found",
            xref="paper", yref="paper",
            showarrow=False,
            font=dict(size=16, color=CYBER_COLORS["warning"])
        )
        return fig

    if NETWORKX_AVAILABLE:
        G = nx.Graph()
        G.add_node(domain, type="root")
        for s in subs:
            sub = s.get("subdomain", "")
            ip = s.get("ip", "")
            G.add_node(sub, type="sub", ip=ip)
            G.add_edge(domain, sub)

        pos = nx.spring_layout(G, seed=42, k=1.5)

        edge_x, edge_y = [], []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        node_x, node_y, node_color, node_text, node_size = [], [], [], [], []
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            if node == domain:
                node_color.append(CYBER_COLORS["primary"])
                node_text.append(f"🌐 {node}")
                node_size.append(25)
            else:
                node_color.append(CYBER_COLORS["secondary"])
                ip = G.nodes[node].get("ip", "")
                node_text.append(f"📡 {node}\\n{ip}")
                node_size.append(15)
    else:
        node_x, node_y = [0], [0]
        node_color = [CYBER_COLORS["primary"]]
        node_text = [domain]
        node_size = [25]
        edge_x, edge_y = [], []

        angle_step = 2 * math.pi / max(len(subs), 1)
        for i, s in enumerate(subs):
            angle = i * angle_step
            radius = 1.5
            x = radius * math.cos(angle)
            y = radius * math.sin(angle)
            node_x.append(x)
            node_y.append(y)
            node_color.append(CYBER_COLORS["secondary"])
            node_text.append(f"{s.get('subdomain', '')}\\n{s.get('ip', '')}")
            node_size.append(12)
            edge_x.extend([0, x, None])
            edge_y.extend([0, y, None])

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=edge_x, y=edge_y,
        mode="lines",
        line=dict(color=CYBER_COLORS["grid"], width=1),
        hoverinfo="none", showlegend=False
    ))
    fig.add_trace(go.Scatter(
        x=node_x, y=node_y,
        mode="markers+text",
        marker=dict(
            size=node_size, color=node_color,
            line=dict(width=2, color=CYBER_COLORS["dark"])
        ),
        text=node_text,
        textposition="top center",
        textfont=dict(size=9, color=CYBER_COLORS["text"]),
        hoverinfo="text", showlegend=False
    ))

    fig.update_layout(
        paper_bgcolor=CYBER_COLORS["dark"],
        plot_bgcolor=CYBER_COLORS["dark"],
        font=dict(color=CYBER_COLORS["text"], family="Courier New, monospace"),
        title=dict(
            text="Subdomain Map",
            font=dict(color=CYBER_COLORS["primary"], size=16),
            x=0.5
        ),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        margin=dict(l=20, r=20, t=60, b=20),
        height=500
    )
    return fig


# ═══════════════════════════════════════════════════════════
# GAUGE / INDICATOR CHARTS
# ═══════════════════════════════════════════════════════════


def create_risk_gauge(value: float, title: str = "Risk Score") -> go.Figure:
    """Create a cyberpunk risk gauge.

    Args:
        value: Risk value (0-100).
        title: Gauge title.

    Returns:
        Plotly Figure object.
    """
    color = (
        CYBER_COLORS["secondary"] if value < 30
        else CYBER_COLORS["warning"] if value < 70
        else CYBER_COLORS["danger"]
    )

    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=value,
        number=dict(font=dict(size=28, color=CYBER_COLORS["text"]), suffix="%"),
        title=dict(text=title, font=dict(size=14, color=CYBER_COLORS["primary"])),
        gauge=dict(
            axis=dict(
                range=[0, 100],
                tickfont=dict(color=CYBER_COLORS["text"]),
                tickcolor=CYBER_COLORS["grid"]
            ),
            bar=dict(color=color, thickness=0.6),
            bgcolor=CYBER_COLORS["panel"],
            borderwidth=2,
            bordercolor=CYBER_COLORS["grid"],
            steps=[
                dict(range=[0, 30], color=hex_to_rgba(CYBER_COLORS["secondary"], 0.13)),
                dict(range=[30, 70], color=hex_to_rgba(CYBER_COLORS["warning"], 0.13)),
                dict(range=[70, 100], color=hex_to_rgba(CYBER_COLORS["danger"], 0.13))
            ],
            threshold=dict(
                line=dict(color=CYBER_COLORS["danger"], width=3),
                thickness=0.8,
                value=70
            )
        )
    ))

    fig.update_layout(
        paper_bgcolor=CYBER_COLORS["dark"],
        font=dict(color=CYBER_COLORS["text"], family="Courier New, monospace"),
        margin=dict(l=30, r=30, t=50, b=20),
        height=280
    )
    return fig


def create_entropy_gauge(entropy: float, max_entropy: float = 128) -> go.Figure:
    """Create an entropy gauge for password analysis.

    Args:
        entropy: Entropy value in bits.
        max_entropy: Maximum entropy for scaling (default 128).

    Returns:
        Plotly Figure object.
    """
    pct = min(100, (entropy / max_entropy) * 100)
    return create_risk_gauge(pct, "Entropy Score")


# ═══════════════════════════════════════════════════════════
# BAR / PIE / LINE CHARTS
# ═══════════════════════════════════════════════════════════


def create_bar_chart(
    data: Union[List[Dict[str, Any]], Dict[str, Any]],
    x_key: str,
    y_key: str,
    title: str = "Bar Chart",
    color_key: Optional[str] = None
) -> go.Figure:
    """Create a cyberpunk bar chart.

    Args:
        data: List of dictionaries or dict with "data" key.
        x_key: Key for x-axis values.
        y_key: Key for y-axis values.
        title: Chart title.
        color_key: Optional key for bar colors.

    Returns:
        Plotly Figure object.
    """
    df_data = data if isinstance(data, list) else data.get("data", [])
    if not df_data:
        fig = go.Figure()
        fig.add_annotation(
            text="No data", xref="paper", yref="paper", showarrow=False
        )
        return fig

    x_vals = [d.get(x_key, "") for d in df_data]
    y_vals = [d.get(y_key, 0) for d in df_data]
    if color_key:
        colors = [d.get(color_key, CYBER_COLORS["primary"]) for d in df_data]
    else:
        colors = [CYBER_COLORS["primary"]] * len(df_data)

    fig = go.Figure(data=[go.Bar(
        x=x_vals,
        y=y_vals,
        marker=dict(
            color=colors,
            line=dict(color=CYBER_COLORS["dark"], width=1)
        ),
        text=y_vals,
        textposition="outside",
        textfont=dict(color=CYBER_COLORS["text"], size=10)
    )])

    fig.update_layout(
        paper_bgcolor=CYBER_COLORS["dark"],
        plot_bgcolor=CYBER_COLORS["panel"],
        font=dict(color=CYBER_COLORS["text"], family="Courier New, monospace"),
        title=dict(
            text=title,
            font=dict(color=CYBER_COLORS["primary"], size=16),
            x=0.5
        ),
        xaxis=dict(tickfont=dict(color=CYBER_COLORS["text"]), gridcolor=CYBER_COLORS["grid"]),
        yaxis=dict(tickfont=dict(color=CYBER_COLORS["text"]), gridcolor=CYBER_COLORS["grid"]),
        margin=dict(l=50, r=20, t=60, b=60)
    )
    return fig


def create_pie_chart(
    labels: List[str],
    values: List[float],
    title: str = "Distribution",
    hole: float = 0.4
) -> go.Figure:
    """Create a cyberpunk pie/donut chart.

    Args:
        labels: Slice labels.
        values: Slice values.
        title: Chart title.
        hole: Hole size for donut (0.0-1.0).

    Returns:
        Plotly Figure object.
    """
    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=hole,
        marker=dict(
            colors=CYBER_PALETTE[:len(labels)],
            line=dict(color=CYBER_COLORS["dark"], width=2)
        ),
        textfont=dict(color=CYBER_COLORS["text"], size=11),
        hovertemplate="%{label}: %{value} (%{percent})<extra></extra>"
    )])

    fig.update_layout(
        paper_bgcolor=CYBER_COLORS["dark"],
        font=dict(color=CYBER_COLORS["text"], family="Courier New, monospace"),
        title=dict(
            text=title,
            font=dict(color=CYBER_COLORS["primary"], size=16),
            x=0.5
        ),
        margin=dict(l=20, r=20, t=60, b=20),
        showlegend=True,
        legend=dict(
            font=dict(color=CYBER_COLORS["text"]),
            bgcolor=CYBER_COLORS["panel"]
        )
    )
    return fig


def create_line_chart(
    x: List[Any],
    y: List[float],
    title: str = "Trend",
    line_color: str = CYBER_COLORS["primary"]
) -> go.Figure:
    """Create a cyberpunk line chart.

    Args:
        x: X-axis values.
        y: Y-axis values.
        title: Chart title.
        line_color: Line color hex string.

    Returns:
        Plotly Figure object.
    """
    fig = go.Figure(data=[go.Scatter(
        x=x,
        y=y,
        mode="lines+markers",
        line=dict(color=line_color, width=2),
        marker=dict(
            size=6,
            color=line_color,
            line=dict(color=CYBER_COLORS["dark"], width=1)
        ),
        fill="tozeroy",
        fillcolor=hex_to_rgba(line_color, 0.08)
    )])

    fig.update_layout(
        paper_bgcolor=CYBER_COLORS["dark"],
        plot_bgcolor=CYBER_COLORS["panel"],
        font=dict(color=CYBER_COLORS["text"], family="Courier New, monospace"),
        title=dict(
            text=title,
            font=dict(color=CYBER_COLORS["primary"], size=16),
            x=0.5
        ),
        xaxis=dict(tickfont=dict(color=CYBER_COLORS["text"]), gridcolor=CYBER_COLORS["grid"]),
        yaxis=dict(tickfont=dict(color=CYBER_COLORS["text"]), gridcolor=CYBER_COLORS["grid"]),
        margin=dict(l=50, r=20, t=60, b=60)
    )
    return fig


# ═══════════════════════════════════════════════════════════
# THREAT INTELLIGENCE VISUALIZATIONS
# ═══════════════════════════════════════════════════════════


def create_threat_radar(threat_data: Dict[str, Any]) -> go.Figure:
    """Create a threat intelligence radar chart.

    Args:
        threat_data: Dictionary with threat category values.

    Returns:
        Plotly Figure object.
    """
    categories = [
        "Malware", "Phishing", "DDoS", "Intrusion",
        "Data Exfil", "Insider"
    ]
    values = [
        threat_data.get("malware", random.randint(10, 80)),
        threat_data.get("phishing", random.randint(10, 80)),
        threat_data.get("ddos", random.randint(10, 80)),
        threat_data.get("intrusion", random.randint(10, 80)),
        threat_data.get("exfil", random.randint(10, 80)),
        threat_data.get("insider", random.randint(10, 80)),
    ]
    return create_radar_chart(
        categories, values, "Threat Vector Analysis", CYBER_COLORS["danger"]
    )


def create_attack_chain_graph() -> go.Figure:
    """Create a simulated cyber kill chain flow diagram.

    Returns:
        Plotly Figure object.
    """
    stages = ["Recon", "Weaponize", "Deliver", "Exploit", "Install", "C2", "Action"]
    colors = [
        CYBER_COLORS["primary"], CYBER_COLORS["warning"], CYBER_COLORS["warning"],
        CYBER_COLORS["danger"], CYBER_COLORS["danger"],
        CYBER_COLORS["accent"], CYBER_COLORS["accent"]
    ]

    fig = go.Figure()

    for i, (stage, color) in enumerate(zip(stages, colors)):
        fig.add_trace(go.Scatter(
            x=[i],
            y=[0],
            mode="markers+text",
            marker=dict(
                size=30,
                color=color,
                line=dict(width=2, color=CYBER_COLORS["dark"])
            ),
            text=[stage],
            textposition="bottom center",
            textfont=dict(size=11, color=CYBER_COLORS["text"]),
            hoverinfo="text",
            showlegend=False
        ))

    # Add arrows between stages
    for i in range(len(stages) - 1):
        fig.add_annotation(
            x=i, y=0,
            ax=i + 1, ay=0,
            xref="x", yref="y", axref="x", ayref="y",
            showarrow=True,
            arrowhead=2,
            arrowsize=1,
            arrowwidth=2,
            arrowcolor=CYBER_COLORS["grid"]
        )

    fig.update_layout(
        paper_bgcolor=CYBER_COLORS["dark"],
        plot_bgcolor=CYBER_COLORS["dark"],
        font=dict(color=CYBER_COLORS["text"], family="Courier New, monospace"),
        title=dict(
            text="Cyber Kill Chain",
            font=dict(color=CYBER_COLORS["primary"], size=16),
            x=0.5
        ),
        xaxis=dict(
            showgrid=False, zeroline=False, showticklabels=False,
            range=[-0.5, len(stages) - 0.5]
        ),
        yaxis=dict(
            showgrid=False, zeroline=False, showticklabels=False,
            range=[-1, 1]
        ),
        margin=dict(l=20, r=20, t=60, b=80),
        height=250
    )
    return fig


def create_protocol_distribution(protocol_data: Dict[str, int]) -> go.Figure:
    """Create a protocol distribution pie chart.

    Args:
        protocol_data: Dictionary mapping protocol names to counts.

    Returns:
        Plotly Figure object.
    """
    labels = list(protocol_data.keys())
    values = list(protocol_data.values())
    return create_pie_chart(labels, values, "Protocol Distribution", hole=0.35)


# ═══════════════════════════════════════════════════════════
# SYSTEM MONITOR CHARTS
# ═══════════════════════════════════════════════════════════


def create_system_gauges(cpu: float, memory: float, disk: float) -> go.Figure:
    """Create system resource gauges (CPU, RAM, Disk).

    Args:
        cpu: CPU usage percentage.
        memory: Memory usage percentage.
        disk: Disk usage percentage.

    Returns:
        Plotly Figure with three gauge indicators.
    """
    fig = make_subplots(
        rows=1, cols=3,
        specs=[[{"type": "indicator"}, {"type": "indicator"}, {"type": "indicator"}]]
    )

    fig.add_trace(go.Indicator(
        mode="gauge+number",
        value=cpu,
        title=dict(text="CPU", font=dict(color=CYBER_COLORS["primary"])),
        number=dict(suffix="%", font=dict(color=CYBER_COLORS["text"])),
        gauge=dict(
            axis=dict(range=[0, 100], tickfont=dict(color=CYBER_COLORS["text"])),
            bar=dict(color=CYBER_COLORS["primary"]),
            bgcolor=CYBER_COLORS["panel"],
            steps=[
                dict(range=[0, 50], color=hex_to_rgba(CYBER_COLORS["secondary"], 0.13)),
                dict(range=[50, 80], color=hex_to_rgba(CYBER_COLORS["warning"], 0.13)),
                dict(range=[80, 100], color=hex_to_rgba(CYBER_COLORS["danger"], 0.13))
            ]
        )
    ), row=1, col=1)

    fig.add_trace(go.Indicator(
        mode="gauge+number",
        value=memory,
        title=dict(text="RAM", font=dict(color=CYBER_COLORS["accent"])),
        number=dict(suffix="%", font=dict(color=CYBER_COLORS["text"])),
        gauge=dict(
            axis=dict(range=[0, 100], tickfont=dict(color=CYBER_COLORS["text"])),
            bar=dict(color=CYBER_COLORS["accent"]),
            bgcolor=CYBER_COLORS["panel"],
            steps=[
                dict(range=[0, 50], color=hex_to_rgba(CYBER_COLORS["secondary"], 0.13)),
                dict(range=[50, 80], color=hex_to_rgba(CYBER_COLORS["warning"], 0.13)),
                dict(range=[80, 100], color=hex_to_rgba(CYBER_COLORS["danger"], 0.13))
            ]
        )
    ), row=1, col=2)

    fig.add_trace(go.Indicator(
        mode="gauge+number",
        value=disk,
        title=dict(text="Disk", font=dict(color=CYBER_COLORS["warning"])),
        number=dict(suffix="%", font=dict(color=CYBER_COLORS["text"])),
        gauge=dict(
            axis=dict(range=[0, 100], tickfont=dict(color=CYBER_COLORS["text"])),
            bar=dict(color=CYBER_COLORS["warning"]),
            bgcolor=CYBER_COLORS["panel"],
            steps=[
                dict(range=[0, 50], color=hex_to_rgba(CYBER_COLORS["secondary"], 0.13)),
                dict(range=[50, 80], color=hex_to_rgba(CYBER_COLORS["warning"], 0.13)),
                dict(range=[80, 100], color=hex_to_rgba(CYBER_COLORS["danger"], 0.13))
            ]
        )
    ), row=1, col=3)

    fig.update_layout(
        paper_bgcolor=CYBER_COLORS["dark"],
        font=dict(color=CYBER_COLORS["text"], family="Courier New, monospace"),
        margin=dict(l=20, r=20, t=50, b=20),
        height=250
    )
    return fig


# ═══════════════════════════════════════════════════════════
# REPORTING SYSTEMS
# ═══════════════════════════════════════════════════════════


def generate_csv_report(data: List[Dict[str, Any]]) -> bytes:
    """Generate CSV report bytes.

    Args:
        data: List of dictionaries.

    Returns:
        CSV data as bytes.
    """
    return export_to_csv(data)


def generate_json_report(data: Any) -> bytes:
    """Generate JSON report bytes.

    Args:
        data: Any serializable data.

    Returns:
        JSON data as bytes.
    """
    return export_to_json(data)


def generate_txt_report(content: str) -> bytes:
    """Generate TXT report bytes.

    Args:
        content: Text content.

    Returns:
        Text data as bytes.
    """
    return export_to_txt(content)


def create_vulnerability_summary_table(vulns: List[Dict[str, Any]]) -> go.Figure:
    """Create an interactive vulnerability findings table.

    Args:
        vulns: List of vulnerability dictionaries.

    Returns:
        Plotly Figure with formatted table.
    """
    if not vulns:
        fig = go.Figure()
        fig.add_annotation(
            text="No vulnerabilities to display",
            xref="paper", yref="paper", showarrow=False
        )
        return fig

    severities = [v.get("severity", "info").upper() for v in vulns]

    fig = go.Figure(data=[go.Table(
        header=dict(
            values=["ID", "Name", "Severity", "CVSS", "Port", "Recommendation"],
            fill_color=CYBER_COLORS["panel"],
            align="left",
            font=dict(color=CYBER_COLORS["primary"], size=12),
            line=dict(color=CYBER_COLORS["grid"], width=1)
        ),
        cells=dict(
            values=[
                [v.get("id", "") for v in vulns],
                [v.get("name", "") for v in vulns],
                severities,
                [str(v.get("cvss_simulated", "N/A")) for v in vulns],
                [str(v.get("port", "N/A")) for v in vulns],
                [v.get("recommendation", "") for v in vulns]
            ],
            fill_color=[CYBER_COLORS["dark"]] * len(vulns),
            align="left",
            font=dict(color=CYBER_COLORS["text"], size=10),
            line=dict(color=CYBER_COLORS["grid"], width=1),
            height=30
        )
    )])

    fig.update_layout(
        paper_bgcolor=CYBER_COLORS["dark"],
        font=dict(color=CYBER_COLORS["text"], family="Courier New, monospace"),
        title=dict(
            text="Vulnerability Findings",
            font=dict(color=CYBER_COLORS["primary"], size=16),
            x=0.5
        ),
        margin=dict(l=10, r=10, t=50, b=10),
        height=min(400, 100 + len(vulns) * 35)
    )
    return fig


def create_threat_timeline() -> go.Figure:
    """Create a simulated 24-hour threat activity timeline.

    Returns:
        Plotly Figure with detected vs mitigated threat lines.
    """
    hours = [f"{h:02d}:00" for h in range(24)]
    threats = [random.randint(0, 20) for _ in range(24)]
    mitigated = [random.randint(0, t) for t in threats]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=hours, y=threats,
        mode="lines+markers",
        name="Detected",
        line=dict(color=CYBER_COLORS["danger"], width=2),
        marker=dict(size=5),
        fill="tozeroy",
        fillcolor=hex_to_rgba(CYBER_COLORS["danger"], 0.08)
    ))
    fig.add_trace(go.Scatter(
        x=hours, y=mitigated,
        mode="lines+markers",
        name="Mitigated",
        line=dict(color=CYBER_COLORS["secondary"], width=2),
        marker=dict(size=5),
        fill="tozeroy",
        fillcolor=hex_to_rgba(CYBER_COLORS["secondary"], 0.08)
    ))

    fig.update_layout(
        paper_bgcolor=CYBER_COLORS["dark"],
        plot_bgcolor=CYBER_COLORS["panel"],
        font=dict(color=CYBER_COLORS["text"], family="Courier New, monospace"),
        title=dict(
            text="24h Threat Activity",
            font=dict(color=CYBER_COLORS["primary"], size=16),
            x=0.5
        ),
        xaxis=dict(
            tickfont=dict(color=CYBER_COLORS["text"]),
            gridcolor=CYBER_COLORS["grid"]
        ),
        yaxis=dict(
            tickfont=dict(color=CYBER_COLORS["text"]),
            gridcolor=CYBER_COLORS["grid"],
            title="Events"
        ),
        legend=dict(
            font=dict(color=CYBER_COLORS["text"]),
            bgcolor=CYBER_COLORS["panel"]
        ),
        margin=dict(l=50, r=20, t=60, b=60),
        height=350
    )
    return fig
