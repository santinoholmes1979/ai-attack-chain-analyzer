import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import networkx as nx

from src.loader import load_events
from src.normalizer import normalize_events
from src.chain_builder import build_attack_chain
from src.summarizer import summarize_chain
from src.attack_scorer import score_attack_chain, confidence_label
from src.reasoner import reason_about_chain
from src.attack_graph import build_attack_graph
from src.graph_visualizer import visualize_graph


def build_report_text(filtered_chain, filtered_df, score, label, reasoning, summary):

    lines = []
    lines.append("AI Attack Chain Analyzer Report")
    lines.append("=" * 40)
    lines.append("")

    lines.append(f"Attack Confidence: {label} ({score})")
    lines.append(f"Threat Model: {reasoning['threat_model']}")
    lines.append("")

    lines.append("Analyst Summary:")
    lines.append(summary)
    lines.append("")

    lines.append("Key Findings:")
    if reasoning["findings"]:
        for finding in reasoning["findings"]:
            lines.append(f"- {finding}")
    else:
        lines.append("- No additional findings generated.")

    lines.append("")
    lines.append("Attack Chain Progression:")

    if filtered_chain:
        for i, event in enumerate(filtered_chain, start=1):
            lines.append(
                f"{i}. {event.get('timestamp')} | "
                f"{event.get('attack_stage')} | "
                f"{event.get('technique_name')} | "
                f"Severity: {event.get('severity')}"
            )

    return "\n".join(lines)

st.set_page_config(page_title="AI Attack Chain Analyzer", layout="wide")

st.title("AI Attack Chain Analyzer")
st.caption("AI-assisted SOC investigation dashboard")

def render_attack_graph(filtered_chain):
    if not filtered_chain:
        return None

    graph = build_attack_graph(filtered_chain)

    short_labels = {}
    node_colors = []

    for node, data in graph.nodes(data=True):
        label = data.get("label", "Unknown")
        severity = "medium"

        if node < len(filtered_chain):
            event = filtered_chain[node]
            severity = event.get("severity", "medium")

            stage = event.get("attack_stage", "Unknown")
            technique = event.get("technique_name", "Unknown")

            short_labels[node] = f"{stage}\n{technique}"
        else:
            short_labels[node] = label

        if severity == "critical":
            node_colors.append("#7f1d1d")
        elif severity == "high":
            node_colors.append("#991b1b")
        elif severity == "medium":
            node_colors.append("#92400e")
        elif severity == "low":
            node_colors.append("#1e3a8a")
        else:
            node_colors.append("#475569")

    pos = nx.spring_layout(graph, seed=42)

    fig, ax = plt.subplots(figsize=(12, 6))
    nx.draw(
        graph,
        pos,
        ax=ax,
        labels=short_labels,
        with_labels=True,
        node_size=3200,
        font_size=8,
        node_color=node_colors,
        font_color="white"
    )
    ax.set_title("Attack Chain Relationship Graph")
    return fig

def render_attack_timeline_chart(filtered_df):
    if filtered_df.empty:
        return None

    timeline_df = filtered_df.sort_values("timestamp").reset_index(drop=True).copy()

    severity_colors = {
        "critical": "#7f1d1d",
        "high": "#991b1b",
        "medium": "#92400e",
        "low": "#1e3a8a"
    }

    fig, ax = plt.subplots(figsize=(12, 4))

    x_positions = list(range(len(timeline_df)))
    y_positions = [1] * len(timeline_df)

    colors = [
        severity_colors.get(sev, "#475569")
        for sev in timeline_df["severity"]
    ]

    ax.scatter(x_positions, y_positions, s=300, c=colors)

    for i, row in timeline_df.iterrows():
        label = f"{row['attack_stage']}\n{row['technique_name']}"
        ax.text(
            x_positions[i],
            y_positions[i] + 0.08,
            label,
            ha="center",
            va="bottom",
            fontsize=8
        )
        ax.text(
            x_positions[i],
            y_positions[i] - 0.12,
            row["timestamp"],
            ha="center",
            va="top",
            fontsize=7
        )

    for i in range(len(x_positions) - 1):
        ax.plot(
            [x_positions[i], x_positions[i + 1]],
            [y_positions[i], y_positions[i + 1]],
            color="gray",
            linewidth=1.5
        )

    ax.set_title("Attack Timeline Visualization")
    ax.set_xticks([])
    ax.set_yticks([])
    ax.set_ylim(0.7, 1.3)

    for spine in ax.spines.values():
        spine.set_visible(False)

    plt.tight_layout()
    return fig    

# Scenario selection
scenario_map = {
    "Phishing Intrusion": "data/sample_attack_chain.json",
    "Credential Theft Campaign": "data/credential_theft_chain.json",
    "Ransomware Precursor Activity": "data/ransomware_precursor_chain.json",
    "Insider Misuse": "data/insider_misuse_chain.json"
}

st.sidebar.header("Scenario Selection")
selected_scenario = st.sidebar.selectbox(
    "Choose Investigation Scenario",
    list(scenario_map.keys())
)

events = load_events(scenario_map[selected_scenario])
normalized = normalize_events(events)
chain = build_attack_chain(normalized)

df = pd.DataFrame(chain)

# Sidebar filters
st.sidebar.header("Investigation Filters")

severity_options = ["All"] + sorted(df["severity"].dropna().unique().tolist())
selected_severity = st.sidebar.selectbox("Filter by Severity", severity_options)

host_options = ["All"] + sorted(df["host"].dropna().unique().tolist())
selected_host = st.sidebar.selectbox("Filter by Host", host_options)

stage_options = ["All"] + sorted(df["attack_stage"].dropna().unique().tolist())
selected_stage = st.sidebar.selectbox("Filter by Attack Stage", stage_options)

filtered_df = df.copy()

if selected_severity != "All":
    filtered_df = filtered_df[filtered_df["severity"] == selected_severity]

if selected_host != "All":
    filtered_df = filtered_df[filtered_df["host"] == selected_host]

if selected_stage != "All":
    filtered_df = filtered_df[filtered_df["attack_stage"] == selected_stage]

filtered_chain = filtered_df.to_dict(orient="records")

summary = summarize_chain(filtered_chain)
score = score_attack_chain(filtered_chain) if filtered_chain else 0.0
label = confidence_label(score) if filtered_chain else "LOW"
reasoning = reason_about_chain(filtered_chain) if filtered_chain else {
    "threat_model": "No events match the selected filters.",
    "findings": [],
    "scenario_type": "generic"
}

report_text = build_report_text(
    filtered_chain=filtered_chain,
    filtered_df=filtered_df,
    score=score,
    label=label,
    reasoning=reasoning,
    summary=summary
)

def highlight_severity(val):
    if val == "critical":
        return "background-color: #7f1d1d; color: white;"
    if val == "high":
        return "background-color: #991b1b; color: white;"
    if val == "medium":
        return "background-color: #92400e; color: white;"
    if val == "low":
        return "background-color: #1e3a8a; color: white;"
    return ""


def get_verdict(score, scenario_type):

    if scenario_type == "insider_misuse":
        if score >= 0.60:
            return "Potential insider-driven collection and exfiltration activity detected. Review user intent and data access immediately.", "warning"
        return "Low-confidence insider misuse indicators observed. Continue monitoring user activity.", "success"

    if scenario_type == "ransomware_precursor":
        if score >= 0.60:
            return "Likely ransomware precursor behavior. Immediate containment and host review recommended.", "error"
        return "Possible ransomware staging indicators observed. Investigate promptly.", "warning"

    if scenario_type == "credential_theft":
        if score >= 0.60:
            return "Credential theft indicators observed with possible follow-on attacker movement. Immediate investigation recommended.", "error"
        return "Low-confidence credential access indicators observed. Continue investigation.", "warning"

    if score >= 0.85:
        return "Likely active multi-stage intrusion. Immediate analyst review recommended.", "error"

    if score >= 0.60:
        return "Suspicious correlated activity detected. Investigate promptly.", "warning"

    return "Low-confidence suspicious activity. Continue monitoring.", "success"

def get_case_badge(scenario_type):
    if scenario_type == "ransomware_precursor":
        return "RANSOMWARE PRECURSOR", "#7f1d1d"
    if scenario_type == "credential_theft":
        return "CREDENTIAL THEFT", "#991b1b"
    if scenario_type == "insider_misuse":
        return "INSIDER MISUSE", "#92400e"
    if scenario_type == "phishing_intrusion":
        return "PHISHING INTRUSION", "#1d4ed8"
    return "GENERIC SUSPICIOUS ACTIVITY", "#475569"    

def chain_completeness(filtered_chain):
    if not filtered_chain:
        return "No Chain"

    observed_stages = {e.get("attack_stage") for e in filtered_chain}
    expected_stages = {
        "Initial Access",
        "Execution",
        "Command and Control",
        "Credential Access",
        "Lateral Movement",
        "Persistence"
    }

    ratio = len(observed_stages.intersection(expected_stages)) / len(expected_stages)

    if ratio >= 0.8:
        return "Well-Developed"
    if ratio >= 0.5:
        return "Partial"
    return "Early/Fragmented"  

case_label, case_color = get_case_badge(reasoning.get("scenario_type", "generic"))     

# Top metrics
col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric("Attack Confidence", f"{label} ({score})")

with col2:
    st.metric("Events in View", len(filtered_chain))

with col3:
    host_value = filtered_chain[0].get("host", "Unknown") if filtered_chain else "N/A"
    st.metric("Host", host_value)

with col4:
    st.metric("Chain Completeness", chain_completeness(filtered_chain))

with col5:
    st.metric("Scenario", selected_scenario)

st.divider()

st.markdown(
    f"""
<div style="
    background-color: {case_color};
    padding: 0.8rem 1rem;
    border-radius: 0.6rem;
    color: white;
    font-weight: 700;
    font-size: 1rem;
    margin-top: 0.5rem;
    margin-bottom: 0.5rem;
">
Case Type: {case_label}
</div>
""",
    unsafe_allow_html=True
)

st.caption(f"Reasoning profile: {reasoning.get('scenario_type', 'generic')}")
st.divider()

# Analyst verdict
st.subheader("Analyst Verdict")

verdict_text, verdict_type = get_verdict(score, reasoning.get("scenario_type", "generic"))

if verdict_type == "error":
    st.error(verdict_text)
elif verdict_type == "warning":
    st.warning(verdict_text)
else:
    st.success(verdict_text)

st.divider()

st.subheader("Export Analyst Report")

st.download_button(
    label="Download Filtered Analyst Report",
    data=report_text,
    file_name="attack_chain_report.txt",
    mime="text/plain"
)

st.divider()

st.subheader("Executive Summary")

ex1, ex2, ex3 = st.columns(3)

with ex1:
    st.markdown("**Likely Objective**")
    st.info(reasoning.get("likely_objective", "No objective identified."))

with ex2:
    st.markdown("**Likely Impact**")
    st.warning(reasoning.get("likely_impact", "No impact identified."))

with ex3:
    st.markdown("**Recommended Response**")
    st.success(reasoning.get("recommended_response", "No response recommendation available."))

st.divider()

# MITRE technique summary
st.subheader("MITRE ATT&CK Techniques Observed in Current View")

if filtered_chain:
    mitre_df = filtered_df[["technique_id", "technique_name", "attack_stage"]].drop_duplicates().copy()
    mitre_df = mitre_df.sort_values(by=["attack_stage", "technique_id"])
    st.dataframe(mitre_df, use_container_width=True)
else:
    st.write("No MITRE techniques available for the selected filters.")

st.divider()

# Threat model and summary
left, right = st.columns([1, 1])


with left:
    st.subheader("Threat Model")
    st.info(reasoning["threat_model"])

with right:
    st.subheader("Analyst Summary")
    st.text(summary)

st.divider()

st.divider()

# Evidence summary
st.subheader("Evidence Summary")

if filtered_chain:
    unique_users = sorted(filtered_df["user"].dropna().unique().tolist()) if "user" in filtered_df.columns else []
    unique_hosts = sorted(filtered_df["host"].dropna().unique().tolist()) if "host" in filtered_df.columns else []
    unique_processes = sorted(filtered_df["process_name"].dropna().unique().tolist()) if "process_name" in filtered_df.columns else []

    e1, e2, e3 = st.columns(3)

    with e1:
        st.markdown("**Users Observed**")
        if unique_users:
            for user in unique_users:
                st.write(f"- {user}")
        else:
            st.write("No users found.")

    with e2:
        st.markdown("**Hosts Observed**")
        if unique_hosts:
            for host in unique_hosts:
                st.write(f"- {host}")
        else:
            st.write("No hosts found.")

    with e3:
        st.markdown("**Processes Observed**")
        if unique_processes:
            for proc in unique_processes:
                st.write(f"- {proc}")
        else:
            st.write("No processes found.")
else:
    st.write("No evidence available for the selected filters.")

# Key findings
st.subheader("Key Findings")

if reasoning["findings"]:
    for finding in reasoning["findings"]:
        st.write(f"- {finding}")
else:
    st.write("No additional findings generated for the current filter selection.")

st.divider()

def build_report_text(filtered_chain, filtered_df, score, label, reasoning, summary):
    lines = []
    lines.append("AI Attack Chain Analyzer Report")
    lines.append("=" * 40)
    lines.append("")

    lines.append(f"Attack Confidence: {label} ({score})")
    lines.append(f"Threat Model: {reasoning['threat_model']}")
    lines.append("")

    lines.append("Analyst Summary:")
    lines.append(summary)
    lines.append("")

    lines.append("Key Findings:")
    if reasoning["findings"]:
        for finding in reasoning["findings"]:
            lines.append(f"- {finding}")
    else:
        lines.append("- No additional findings generated.")
    lines.append("")

    lines.append("MITRE ATT&CK Techniques Observed:")
    if filtered_chain:
        mitre_rows = (
            filtered_df[["technique_id", "technique_name", "attack_stage"]]
            .drop_duplicates()
            .sort_values(by=["attack_stage", "technique_id"])
            .to_dict(orient="records")
        )
        for row in mitre_rows:
            lines.append(
                f"- {row.get('technique_id', 'N/A')} | "
                f"{row.get('technique_name', 'N/A')} | "
                f"{row.get('attack_stage', 'N/A')}"
            )
    else:
        lines.append("- No MITRE techniques available.")
    lines.append("")

    lines.append("Attack Chain Progression:")
    if filtered_chain:
        for i, event in enumerate(filtered_chain, start=1):
            lines.append(
                f"{i}. {event.get('timestamp', 'Unknown Time')} | "
                f"{event.get('attack_stage', 'Unknown Stage')} | "
                f"{event.get('technique_name', 'Unknown Technique')} | "
                f"Severity: {event.get('severity', 'unknown')}"
            )
    else:
        lines.append("No attack chain progression available.")
    lines.append("")

    lines.append("Evidence Summary:")
    if filtered_chain:
        unique_users = sorted(filtered_df["user"].dropna().unique().tolist()) if "user" in filtered_df.columns else []
        unique_hosts = sorted(filtered_df["host"].dropna().unique().tolist()) if "host" in filtered_df.columns else []
        unique_processes = sorted(filtered_df["process_name"].dropna().unique().tolist()) if "process_name" in filtered_df.columns else []

        lines.append(f"Users Observed: {', '.join(unique_users) if unique_users else 'None'}")
        lines.append(f"Hosts Observed: {', '.join(unique_hosts) if unique_hosts else 'None'}")
        lines.append(f"Processes Observed: {', '.join(unique_processes) if unique_processes else 'None'}")
    else:
        lines.append("No evidence available for the selected filters.")

    return "\n".join(lines)

# Severity overview
st.subheader("Severity Overview")

if not filtered_df.empty:
    sev1, sev2, sev3, sev4 = st.columns(4)

    critical_count = int((filtered_df["severity"] == "critical").sum())
    high_count = int((filtered_df["severity"] == "high").sum())
    medium_count = int((filtered_df["severity"] == "medium").sum())
    low_count = int((filtered_df["severity"] == "low").sum())

    sev1.metric("Critical", critical_count)
    sev2.metric("High", high_count)
    sev3.metric("Medium", medium_count)
    sev4.metric("Low", low_count)
else:
    st.write("No severity data available for the selected filters.")

st.divider()

# Attack progression cards
st.subheader("Attack Chain Progression")

if filtered_chain:
    for i, event in enumerate(filtered_chain, start=1):
        with st.container():
            c1, c2 = st.columns([1, 3])

            with c1:
                st.markdown(f"### Step {i}")
                st.markdown(f"**Severity:** {event.get('severity', 'unknown')}")
                st.markdown(f"**Time:** {event.get('timestamp', 'Unknown Time')}")

            with c2:
                st.markdown(f"**Stage:** {event.get('attack_stage', 'Unknown Stage')}")
                st.markdown(f"**Technique:** {event.get('technique_name', 'Unknown Technique')}")
                st.markdown(f"**Event Type:** {event.get('event_type', 'Unknown Event')}")
                st.markdown(f"**Process:** {event.get('process_name', 'Unknown Process')}")
                st.markdown(f"**User:** {event.get('user', 'Unknown User')}")
                st.markdown(f"**Host:** {event.get('host', 'Unknown Host')}")

            st.markdown("---")

            if i < len(filtered_chain):
                st.markdown("### ⬇️")
else:
    st.warning("No attack chain progression available for the selected filters.")

st.divider()

st.divider()

# Attack graph view
st.subheader("Attack Graph View")

if filtered_chain:
    graph_fig = render_attack_graph(filtered_chain)
    st.pyplot(graph_fig)
    st.caption("Severity colors: Critical = dark red, High = red, Medium = amber, Low = blue")
else:
    st.warning("No attack graph available for the selected filters.")

# ATT&CK stage chart
st.subheader("ATT&CK Stage Coverage")

if not filtered_df.empty:
    stage_counts = filtered_df["attack_stage"].value_counts().sort_index()

    fig, ax = plt.subplots(figsize=(10, 4))
    ax.bar(stage_counts.index, stage_counts.values)
    ax.set_title("Events by ATT&CK Stage")
    ax.set_xlabel("ATT&CK Stage")
    ax.set_ylabel("Event Count")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()

    st.pyplot(fig)
else:
    st.warning("No stage coverage to display for the selected filters.")

st.divider()

# Attack timeline visualization
st.subheader("Attack Timeline Visualization")

if not filtered_df.empty:
    timeline_fig = render_attack_timeline_chart(filtered_df)
    st.pyplot(timeline_fig)
    st.caption("Timeline colors follow severity: Critical = dark red, High = red, Medium = amber, Low = blue")
else:
    st.warning("No timeline visualization available for the selected filters.")

# Timeline
st.subheader("Attack Timeline")

if not filtered_df.empty:
    timeline_df = filtered_df.sort_values("timestamp")[[
        "timestamp",
        "attack_stage",
        "technique_name",
        "severity",
        "host",
        "user"
    ]].copy()

    styled_timeline = timeline_df.style.map(highlight_severity, subset=["severity"])
    st.dataframe(styled_timeline, use_container_width=True)
else:
    st.warning("No events match the selected filters.")

st.divider()

# Full event data
st.subheader("Full Event Data")

if not filtered_df.empty:
    styled_full = filtered_df.style.map(highlight_severity, subset=["severity"])
    st.dataframe(styled_full, use_container_width=True)
else:
    st.dataframe(filtered_df, use_container_width=True)