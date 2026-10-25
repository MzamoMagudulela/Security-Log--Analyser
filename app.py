"""
Security Log Analyser - Interactive Streamlit Application.

A professional cybersecurity triage and telemetry dashboard that parses Linux
authentication logs, executes configurable rule-based security detections,
visualizes events, and generates incident reports.
"""

import os
from datetime import datetime
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

import config
from src.log_parser import parse_log_content
from src.detection_engine import SecurityDetectionEngine
from src.report_generator import (
    export_events_to_csv,
    export_alerts_to_csv,
    generate_executive_summary_text,
    generate_pdf_report,
    REPORTLAB_AVAILABLE
)

# -----------------------------------------------------------------------------
# Streamlit Page Setup & Custom CSS
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="Security Log Analyser",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

CUSTOM_CSS = """
<style>
    /* Metric Card Styling */
    .metric-card {
        background: linear-gradient(135deg, #1A202C 0%, #2D3748 100%);
        border: 1px solid #4A5568;
        border-radius: 8px;
        padding: 16px 20px;
        color: #F7FAFC;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        margin-bottom: 12px;
    }
    .metric-label {
        font-size: 0.85rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #A0AEC0;
        margin-bottom: 6px;
    }
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        color: #FFFFFF;
        line-height: 1.1;
    }
    .metric-subtitle {
        font-size: 0.75rem;
        color: #CBD5E0;
        margin-top: 4px;
    }

    /* Severity Badges */
    .badge-high {
        background-color: #FED7D7;
        color: #C53030;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .badge-medium {
        background-color: #FEEBC8;
        color: #C05621;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .badge-low {
        background-color: #FEFCBF;
        color: #B7791F;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .badge-info {
        background-color: #BEE3F8;
        color: #2B6CB0;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }

    /* Report Banner */
    .status-banner {
        border-left: 4px solid #3182CE;
        background-color: #EBF8FF;
        color: #2B6CB0;
        padding: 10px 14px;
        border-radius: 4px;
        margin-bottom: 16px;
        font-size: 0.9rem;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Data Ingestion Helpers
# -----------------------------------------------------------------------------
@st.cache_data(show_spinner=False)
def load_sample_log_content() -> str:
    """Reads synthetic sample auth log from disk."""
    if not os.path.exists(config.SAMPLE_LOG_PATH):
        return ""
    with open(config.SAMPLE_LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def main():
    # Application Title & Subheading
    st.markdown("## 🛡️ Security Log Analyser")
    st.caption(
        "Automated Incident Detection, Forensic Log Parser & Threat Telemetry Dashboard | "
        "Final-Year ICT Portfolio Demonstration"
    )

    # -------------------------------------------------------------------------
    # Sidebar Controls
    # -------------------------------------------------------------------------
    st.sidebar.header("📁 Ingestion & Configuration")

    mode = st.sidebar.radio(
        "Data Source Mode",
        ["🚀 Demo Mode (Synthetic Logs)", "📂 Upload Custom Log (.log, .txt)"],
        index=0,
        help="Demo mode instantly populates the dashboard with realistic synthetic authentication attack scenarios."
    )

    log_content = ""
    source_name = "Synthetic Sample Data"

    if mode == "🚀 Demo Mode (Synthetic Logs)":
        log_content = load_sample_log_content()
        source_name = "data/sample_auth.log (Synthetic Dataset)"
        st.sidebar.info("💡 **Demo Mode Active**: Preloaded with brute-force, burst, and credential compromise scenarios.")
    else:
        uploaded_file = st.sidebar.file_uploader(
            "Upload Log File",
            type=["log", "txt"],
            help=f"Accepts Linux auth.log or text files up to {config.MAX_UPLOAD_SIZE_MB}MB."
        )

        if uploaded_file is not None:
            # File validation
            file_name = uploaded_file.name
            file_size = uploaded_file.size
            ext = os.path.splitext(file_name)[1].lower()

            if ext not in config.ALLOWED_EXTENSIONS:
                st.sidebar.error(f"❌ Unsupported file extension '{ext}'. Only .log and .txt files are accepted.")
                st.stop()

            if file_size > config.MAX_UPLOAD_SIZE_BYTES:
                st.sidebar.error(f"❌ File exceeds limit of {config.MAX_UPLOAD_SIZE_MB}MB ({file_size / (1024*1024):.1f}MB).")
                st.stop()

            if file_size == 0:
                st.sidebar.error("❌ Uploaded file is empty.")
                st.stop()

            # Read content safely in memory (never written or executed)
            raw_bytes = uploaded_file.read()
            log_content = raw_bytes.decode("utf-8", errors="replace")
            source_name = f"Uploaded File: {file_name} ({len(log_content.splitlines())} lines)"
        else:
            st.info("👋 Please upload a supported Linux authentication log file (`.log` or `.txt`) or switch to **Demo Mode** in the sidebar.")
            # Format Guidance Notice
            with st.expander("ℹ️ Supported Log Formats & System Scope", expanded=True):
                st.markdown("""
                **Supported Input Formats:**
                - Standard Linux Syslog / RFC 3164 (e.g., Debian/Ubuntu `/var/log/auth.log`, RHEL/CentOS `/var/log/secure`).
                - Systemd Journald & ISO 8601 exports (`%Y-%m-%dT%H:%M:%S%z`).
                - SSH daemon (`sshd`) authentication events, PAM session audits, and sudo command invocations.

                **Windows Event Log Note:**
                - Binary Windows `.evtx` files are **not natively parsed** directly in this tier-1 Linux auth parser. To analyse Windows events, convert or export security events to text/syslog format prior to upload.
                """)
            st.stop()

    # -------------------------------------------------------------------------
    # Detection Engine Threshold Configuration
    # -------------------------------------------------------------------------
    with st.sidebar.expander("⚙️ Detection Rule Thresholds", expanded=False):
        st.markdown("**Rule 1: Repeated Failed Logins**")
        r1_threshold = st.slider("Failed Attempts Threshold", min_value=3, max_value=20, value=config.RULE1_FAILED_LOGIN_THRESHOLD)
        r1_window_mins = st.slider("Window (Minutes)", min_value=1, max_value=30, value=config.RULE1_WINDOW_SECONDS // 60)

        st.markdown("**Rule 2: Success After Failures**")
        r2_fail_count = st.slider("Preceding Failures Required", min_value=2, max_value=15, value=config.RULE2_PREVIOUS_FAIL_COUNT)
        r2_window_mins = st.slider("Preceding Window (Minutes)", min_value=1, max_value=30, value=config.RULE2_WINDOW_SECONDS // 60)

        st.markdown("**Rule 3: Unusual Event Bursts**")
        r3_burst_count = st.slider("Burst Event Threshold", min_value=5, max_value=50, value=config.RULE3_BURST_EVENT_COUNT)
        r3_window_mins = st.slider("Burst Window (Minutes)", min_value=1, max_value=30, value=config.RULE3_WINDOW_SECONDS // 60)

        st.markdown("**Rule 4: Dataset-Wide Frequent Failures**")
        r4_dataset_fails = st.slider("Cumulative Failures Threshold", min_value=3, max_value=30, value=config.RULE4_DATASET_FAIL_THRESHOLD)

    # -------------------------------------------------------------------------
    # Parse Logs & Run Detections
    # -------------------------------------------------------------------------
    df_raw, parse_stats = parse_log_content(log_content)

    if df_raw.empty:
        st.warning("⚠️ No valid log lines were extracted from the input data.")
        st.stop()

    # Instantiate Detection Engine with user thresholds
    engine = SecurityDetectionEngine(
        rule1_threshold=r1_threshold,
        rule1_window_sec=r1_window_mins * 60,
        rule2_fail_count=r2_fail_count,
        rule2_window_sec=r2_window_mins * 60,
        rule3_burst_count=r3_burst_count,
        rule3_window_sec=r3_window_mins * 60,
        rule4_dataset_fails=r4_dataset_fails
    )
    df_alerts = engine.run_all_detections(df_raw)

    # -------------------------------------------------------------------------
    # Ingestion Status Banner & Telemetry
    # -------------------------------------------------------------------------
    col_t1, col_t2 = st.columns([3, 1])
    with col_t1:
        st.markdown(f"**Target Source:** `{source_name}`")
    with col_t2:
        st.markdown(
            f"**Parsing Quality:** `{parse_stats['parsed_lines']}/{parse_stats['total_lines']} Lines "
            f"({parse_stats['parse_success_rate_pct']}%)`"
        )

    if parse_stats["unparsed_lines"] > 0:
        with st.expander(f"⚠️ Notice: {parse_stats['unparsed_lines']} unparsed or malformed lines preserved for audit", expanded=False):
            st.caption("These entries did not match standard syslog headers. They are preserved for manual inspection without falsely classifying them as attacks.")
            unparsed_df = df_raw[df_raw["is_parsed"] == False][["line_number", "raw_log", "error_reason"]]
            st.dataframe(unparsed_df, use_container_width=True, hide_index=True)

    # -------------------------------------------------------------------------
    # Interactive Search & Filters (Sidebar)
    # -------------------------------------------------------------------------
    st.sidebar.header("🔍 Search & Filters")

    search_query = st.sidebar.text_input("Search Logs & Alerts", placeholder="IP, username, command, process...")

    # Filter: Event Types
    all_event_types = sorted(list(df_raw["event_type"].dropna().unique()))
    selected_event_types = st.sidebar.multiselect("Event Type", all_event_types, default=all_event_types)

    # Filter: Login Outcome
    outcome_option = st.sidebar.selectbox("Login Outcome", ["All Outcomes", "Success Only", "Failure Only", "N/A Only"])

    # Filter: Source IP
    available_ips = sorted([ip for ip in df_raw["source_ip"].dropna().unique() if ip])
    selected_ips = st.sidebar.multiselect("Filter by Source IP", available_ips, default=[])

    # Filter: Alert Severity
    all_severities = config.SEVERITY_LEVELS
    selected_severities = st.sidebar.multiselect("Alert Severity Filter", all_severities, default=all_severities)

    # Filter: Date & Time Range
    valid_ts = df_raw["timestamp"].dropna()
    min_time = valid_ts.min() if not valid_ts.empty else None
    max_time = valid_ts.max() if not valid_ts.empty else None

    selected_time_range = None
    if min_time is not None and max_time is not None and min_time < max_time:
        selected_time_range = st.sidebar.slider(
            "Timestamp Range",
            min_value=min_time.to_pydatetime(),
            max_value=max_time.to_pydatetime(),
            value=(min_time.to_pydatetime(), max_time.to_pydatetime()),
            format="MM-DD HH:mm"
        )

    # Apply Filters to Event DataFrame
    filtered_events = df_raw.copy()

    if selected_event_types:
        filtered_events = filtered_events[filtered_events["event_type"].isin(selected_event_types)]

    if outcome_option == "Success Only":
        filtered_events = filtered_events[filtered_events["login_outcome"] == "Success"]
    elif outcome_option == "Failure Only":
        filtered_events = filtered_events[filtered_events["login_outcome"] == "Failure"]
    elif outcome_option == "N/A Only":
        filtered_events = filtered_events[filtered_events["login_outcome"] == "N/A"]

    if selected_ips:
        filtered_events = filtered_events[filtered_events["source_ip"].isin(selected_ips)]

    if selected_time_range:
        t_start, t_end = selected_time_range
        filtered_events = filtered_events[
            filtered_events["timestamp"].isna() |
            ((filtered_events["timestamp"] >= t_start) & (filtered_events["timestamp"] <= t_end))
        ]

    if search_query.strip():
        q = search_query.strip().lower()
        filtered_events = filtered_events[
            filtered_events["raw_log"].str.lower().str.contains(q, na=False) |
            filtered_events["username"].str.lower().str.contains(q, na=False) |
            filtered_events["source_ip"].str.lower().str.contains(q, na=False) |
            filtered_events["description"].str.lower().str.contains(q, na=False)
        ]

    # Apply Filters to Alerts DataFrame
    filtered_alerts = df_alerts.copy()
    if not filtered_alerts.empty:
        if selected_severities:
            filtered_alerts = filtered_alerts[filtered_alerts["severity"].isin(selected_severities)]
        if selected_ips:
            filtered_alerts = filtered_alerts[filtered_alerts["source_ip"].isin(selected_ips)]
        if selected_time_range:
            t_start, t_end = selected_time_range
            filtered_alerts = filtered_alerts[
                filtered_alerts["timestamp"].isna() |
                ((filtered_alerts["timestamp"] >= t_start) & (filtered_alerts["timestamp"] <= t_end))
            ]
        if search_query.strip():
            q = search_query.strip().lower()
            filtered_alerts = filtered_alerts[
                filtered_alerts["explanation"].str.lower().str.contains(q, na=False) |
                filtered_alerts["source_ip"].str.lower().str.contains(q, na=False) |
                filtered_alerts["rule_name"].str.lower().str.contains(q, na=False) |
                filtered_alerts["username"].str.lower().str.contains(q, na=False)
            ]

    # -------------------------------------------------------------------------
    # Dashboard KPI Metric Cards
    # -------------------------------------------------------------------------
    total_events = len(filtered_events)
    successful_logins = int((filtered_events["login_outcome"] == "Success").sum()) if not filtered_events.empty else 0
    failed_logins = int((filtered_events["login_outcome"] == "Failure").sum()) if not filtered_events.empty else 0
    total_alerts = len(filtered_alerts)
    unique_ips = int(filtered_events["source_ip"].dropna().nunique()) if not filtered_events.empty else 0

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.markdown(
            f"""<div class="metric-card">
                <div class="metric-label">Events Analysed</div>
                <div class="metric-value">{total_events}</div>
                <div class="metric-subtitle">Filtered activity records</div>
            </div>""",
            unsafe_allow_html=True
        )
    with m2:
        st.markdown(
            f"""<div class="metric-card">
                <div class="metric-label">Successful Logins</div>
                <div class="metric-value" style="color: #68D391;">{successful_logins}</div>
                <div class="metric-subtitle">Authorized authentications</div>
            </div>""",
            unsafe_allow_html=True
        )
    with m3:
        st.markdown(
            f"""<div class="metric-card">
                <div class="metric-label">Failed Logins</div>
                <div class="metric-value" style="color: #F56565;">{failed_logins}</div>
                <div class="metric-subtitle">Authentication rejections</div>
            </div>""",
            unsafe_allow_html=True
        )
    with m4:
        st.markdown(
            f"""<div class="metric-card">
                <div class="metric-label">Security Alerts</div>
                <div class="metric-value" style="color: {'#E53E3E' if total_alerts > 0 else '#4FD1C5'};">{total_alerts}</div>
                <div class="metric-subtitle">Heuristic rule anomalies</div>
            </div>""",
            unsafe_allow_html=True
        )
    with m5:
        st.markdown(
            f"""<div class="metric-card">
                <div class="metric-label">Unique Source IPs</div>
                <div class="metric-value">{unique_ips}</div>
                <div class="metric-subtitle">Identified network sources</div>
            </div>""",
            unsafe_allow_html=True
        )

    # -------------------------------------------------------------------------
    # Visualizations (Plotly Charts)
    # -------------------------------------------------------------------------
    st.markdown("### 📊 Security Visualizations & Telemetry")

    if filtered_events.empty:
        st.info("ℹ️ No log records match the current filter criteria.")
    else:
        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            # 1. Timeline Histogram of Events over Time
            ts_data = filtered_events.dropna(subset=["timestamp"]).copy()
            if not ts_data.empty:
                fig_timeline = px.histogram(
                    ts_data,
                    x="timestamp",
                    color="login_outcome",
                    title="<b>Event Activity Timeline</b>",
                    labels={"timestamp": "Time", "login_outcome": "Outcome", "count": "Events"},
                    color_discrete_map={
                        "Success": "#48BB78",
                        "Failure": "#F56565",
                        "N/A": "#4299E1"
                    },
                    template="plotly_dark"
                )
                fig_timeline.update_layout(
                    height=320,
                    margin=dict(l=20, r=20, t=40, b=20),
                    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
                )
                st.plotly_chart(fig_timeline, use_container_width=True)
            else:
                st.info("No valid timestamps available for timeline chart.")

        with chart_col2:
            # 2. Alert Severity Distribution Donut Chart
            if not filtered_alerts.empty:
                sev_counts = filtered_alerts["severity"].value_counts().reset_index()
                sev_counts.columns = ["Severity", "Count"]
                fig_sev = px.pie(
                    sev_counts,
                    names="Severity",
                    values="Count",
                    title="<b>Alert Severity Distribution</b>",
                    hole=0.45,
                    color="Severity",
                    color_discrete_map=config.SEVERITY_COLORS,
                    template="plotly_dark"
                )
                fig_sev.update_layout(height=320, margin=dict(l=20, r=20, t=40, b=20))
                st.plotly_chart(fig_sev, use_container_width=True)
            else:
                st.markdown(
                    "<div style='height: 320px; display: flex; align-items: center; justify-content: center; background: #1A202C; border-radius: 8px; border: 1px dashed #4A5568;'>"
                    "<span style='color: #68D391;'>✅ No active security alerts detected in filtered view</span></div>",
                    unsafe_allow_html=True
                )

        chart_col3, chart_col4 = st.columns(2)

        with chart_col3:
            # 3. Top Source IP Addresses
            ip_data = filtered_events.dropna(subset=["source_ip"])
            if not ip_data.empty:
                top_ips = ip_data["source_ip"].value_counts().head(10).reset_index()
                top_ips.columns = ["Source IP", "Event Count"]
                fig_ips = px.bar(
                    top_ips,
                    x="Event Count",
                    y="Source IP",
                    orientation="h",
                    title="<b>Top 10 Most Frequent Source IPs</b>",
                    color="Event Count",
                    color_continuous_scale="Reds",
                    template="plotly_dark"
                )
                fig_ips.update_layout(
                    height=320,
                    margin=dict(l=20, r=20, t=40, b=20),
                    yaxis=dict(autorange="reversed")
                )
                st.plotly_chart(fig_ips, use_container_width=True)
            else:
                st.info("No source IP addresses available in current records.")

        with chart_col4:
            # 4. Event Type Distribution
            etype_counts = filtered_events["event_type"].value_counts().reset_index()
            etype_counts.columns = ["Event Type", "Count"]
            fig_etype = px.bar(
                etype_counts,
                x="Event Type",
                y="Count",
                title="<b>Event Type Distribution</b>",
                color="Event Type",
                color_discrete_sequence=px.colors.qualitative.Safe,
                template="plotly_dark"
            )
            fig_etype.update_layout(
                height=320,
                margin=dict(l=20, r=20, t=40, b=20),
                showlegend=False
            )
            st.plotly_chart(fig_etype, use_container_width=True)

    # -------------------------------------------------------------------------
    # Security Alerts Triage Section
    # -------------------------------------------------------------------------
    st.markdown("---")
    st.markdown(f"### 🚨 Detected Security Alerts ({len(filtered_alerts)})")

    if filtered_alerts.empty:
        st.success("✅ Clean baseline: No suspicious anomalies or attack patterns detected.")
    else:
        st.caption("Review triggered threat detection heuristics, affected accounts, and evidence explanations.")
        alert_display_cols = ["alert_id", "severity", "rule_name", "timestamp", "source_ip", "username", "event_count"]
        st.dataframe(
            filtered_alerts[alert_display_cols],
            use_container_width=True,
            hide_index=True,
            column_config={
                "alert_id": st.column_config.TextColumn("Alert ID", width="small"),
                "severity": st.column_config.TextColumn("Severity", width="small"),
                "rule_name": st.column_config.TextColumn("Rule Name", width="medium"),
                "timestamp": st.column_config.DatetimeColumn("Trigger Time", format="YYYY-MM-DD HH:mm:ss"),
                "source_ip": st.column_config.TextColumn("Source IP", width="medium"),
                "username": st.column_config.TextColumn("Target Account(s)", width="medium"),
                "event_count": st.column_config.NumberColumn("Event Count", width="small")
            }
        )

        # Expandable Forensic Evidence Details
        with st.expander("🔎 View Plain-English Forensic Explanations for Alerts", expanded=False):
            for _, alert in filtered_alerts.iterrows():
                badge_class = f"badge-{alert['severity'].lower()}"
                st.markdown(
                    f"**{alert['alert_id']}** | "
                    f"<span class='{badge_class}'>{alert['severity']}</span> | "
                    f"**{alert['rule_name']}** | IP: `{alert['source_ip']}` | Time: `{alert['timestamp']}`",
                    unsafe_allow_html=True
                )
                st.markdown(f"> **Evidence:** {alert['explanation']}")
                st.markdown("")

    # -------------------------------------------------------------------------
    # Event Log Investigation Table
    # -------------------------------------------------------------------------
    st.markdown("---")
    st.markdown(f"### 📋 Forensic Event Investigation ({len(filtered_events)} Events)")

    if filtered_events.empty:
        st.info("No events match the selected filters.")
    else:
        event_cols = [
            "line_number", "timestamp", "hostname", "process",
            "event_type", "login_outcome", "username", "source_ip", "description"
        ]
        st.dataframe(
            filtered_events[event_cols],
            use_container_width=True,
            hide_index=True,
            column_config={
                "line_number": st.column_config.NumberColumn("Line #", width="small"),
                "timestamp": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss"),
                "hostname": st.column_config.TextColumn("Host", width="small"),
                "process": st.column_config.TextColumn("Process", width="small"),
                "event_type": st.column_config.TextColumn("Event Type", width="medium"),
                "login_outcome": st.column_config.TextColumn("Outcome", width="small"),
                "username": st.column_config.TextColumn("Username", width="medium"),
                "source_ip": st.column_config.TextColumn("Source IP", width="medium"),
                "description": st.column_config.TextColumn("Description", width="large"),
            }
        )

    # -------------------------------------------------------------------------
    # Report Export Section
    # -------------------------------------------------------------------------
    st.markdown("---")
    st.markdown("### 📥 Incident Reporting & Exports")
    st.caption("Download forensic audit trails matching current filters.")

    exp_col1, exp_col2, exp_col3, exp_col4 = st.columns(4)

    # 1. Filtered Events CSV
    events_csv = export_events_to_csv(filtered_events)
    with exp_col1:
        st.download_button(
            label="📄 Export Filtered Events (CSV)",
            data=events_csv,
            file_name=f"security_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True,
            disabled=filtered_events.empty
        )

    # 2. Detected Alerts CSV
    alerts_csv = export_alerts_to_csv(filtered_alerts)
    with exp_col2:
        st.download_button(
            label="🚨 Export Security Alerts (CSV)",
            data=alerts_csv,
            file_name=f"security_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True,
            disabled=filtered_alerts.empty
        )

    # 3. Executive Text Summary
    summary_text = generate_executive_summary_text(filtered_events, filtered_alerts, parse_stats)
    with exp_col3:
        st.download_button(
            label="📝 Export Executive Summary (TXT)",
            data=summary_text,
            file_name=f"executive_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
            use_container_width=True
        )

    # 4. Professional Incident PDF Report
    with exp_col4:
        if REPORTLAB_AVAILABLE:
            pdf_data = generate_pdf_report(filtered_events, filtered_alerts, parse_stats)
            st.download_button(
                label="📊 Export Incident Report (PDF)",
                data=pdf_data if pdf_data else b"",
                file_name=f"security_incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf",
                use_container_width=True,
                disabled=pdf_data is None
            )
        else:
            st.button("PDF Export Unavailable (ReportLab)", disabled=True, use_container_width=True)

    # Footer
    st.markdown("<br><hr>", unsafe_allow_html=True)
    st.caption(
        "🔒 **Security & Privacy Guarantee:** Log files are processed in-memory locally. "
        "No network transmission, external scanning, or automated host blocking is performed. "
        "Built for ICT internship demonstration."
    )


if __name__ == "__main__":
    main()
