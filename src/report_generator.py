"""
Report Generation Engine for Security Log Analyser.

Generates CSV exports for events and alerts, plain-text/markdown executive summaries,
and formatted PDF incident summary reports using ReportLab.
"""

import io
from datetime import datetime
from typing import Dict, Any, Optional
import pandas as pd

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


def export_events_to_csv(df: pd.DataFrame) -> str:
    """Exports log events DataFrame to CSV string."""
    if df.empty:
        return ""
    # Export relevant security analysis columns
    cols_to_export = [
        col for col in [
            "line_number", "timestamp", "hostname", "process", "event_type",
            "login_outcome", "username", "source_ip", "port", "description"
        ] if col in df.columns
    ]
    export_df = df[cols_to_export] if cols_to_export else df
    return export_df.to_csv(index=False)


def export_alerts_to_csv(alerts_df: pd.DataFrame) -> str:
    """Exports detected security alerts DataFrame to CSV string."""
    if alerts_df.empty:
        return ""
    cols = [
        col for col in [
            "alert_id", "rule_id", "rule_name", "severity",
            "timestamp", "source_ip", "username", "event_count", "explanation"
        ] if col in alerts_df.columns
    ]
    export_df = alerts_df[cols] if cols else alerts_df
    return export_df.to_csv(index=False)


def generate_executive_summary_text(
    df: pd.DataFrame, alerts_df: pd.DataFrame, stats: Dict[str, Any]
) -> str:
    """
    Constructs a plain-text/markdown executive summary of the security analysis.
    """
    total_events = len(df) if not df.empty else 0
    total_alerts = len(alerts_df) if not alerts_df.empty else 0

    success_count = 0
    failure_count = 0
    unique_ips = 0

    if not df.empty:
        if "login_outcome" in df.columns:
            success_count = int((df["login_outcome"] == "Success").sum())
            failure_count = int((df["login_outcome"] == "Failure").sum())
        if "source_ip" in df.columns:
            unique_ips = int(df["source_ip"].dropna().nunique())

    severity_counts = {}
    if not alerts_df.empty and "severity" in alerts_df.columns:
        severity_counts = alerts_df["severity"].value_counts().to_dict()

    high_sev = severity_counts.get("High", 0)
    med_sev = severity_counts.get("Medium", 0)
    low_sev = severity_counts.get("Low", 0)
    info_sev = severity_counts.get("Informational", 0)

    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    summary = f"""# SECURITY LOG ANALYSIS EXECUTIVE REPORT
Generated: {timestamp_str}
============================================================

1. PARSING & INGESTION METRICS
------------------------------------------------------------
- Total Lines Processed:     {stats.get('total_lines', total_events)}
- Successfully Parsed:       {stats.get('parsed_lines', total_events)}
- Malformed / Unparsed:      {stats.get('unparsed_lines', 0)}
- Parse Success Rate:        {stats.get('parse_success_rate_pct', 100.0)}%

2. LOG EVENT TELEMETRY
------------------------------------------------------------
- Total Filtered Events:     {total_events}
- Successful Logins:         {success_count}
- Failed Logins:             {failure_count}
- Unique Source IPs:         {unique_ips}

3. THREAT DETECTION SUMMARY
------------------------------------------------------------
- Total Alerts Generated:    {total_alerts}
  * High Severity:           {high_sev}
  * Medium Severity:         {med_sev}
  * Low Severity:            {low_sev}
  * Informational:           {info_sev}

4. KEY SECURITY FINDINGS & RECOMMENDATIONS
------------------------------------------------------------
"""
    if total_alerts == 0:
        summary += "- No anomalous activity or brute-force patterns detected in the analysed dataset.\n"
    else:
        for idx, row in alerts_df.head(10).iterrows():
            summary += (
                f"[{row.get('severity', 'UNKNOWN')}] {row.get('alert_id', 'ALT')} - "
                f"{row.get('rule_name', 'Rule')} ({row.get('timestamp')})\n"
                f"  Target: {row.get('username', 'N/A')} | Source IP: {row.get('source_ip', 'N/A')}\n"
                f"  Evidence: {row.get('explanation', '')}\n\n"
            )

    summary += """============================================================
NOTE: This analysis report is generated based on automated rule-based
heuristics. Identified anomalies represent candidates for investigation
rather than confirmed breaches.
"""
    return summary


def generate_pdf_report(
    df: pd.DataFrame, alerts_df: pd.DataFrame, stats: Dict[str, Any]
) -> Optional[bytes]:
    """
    Builds a professional PDF Security Log Analysis Report using ReportLab.
    Returns bytes of the PDF or None if ReportLab is unavailable.
    """
    if not REPORTLAB_AVAILABLE:
        return None

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#1A365D'),
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#718096'),
        spaceAfter=14
    )
    heading2_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#2B6CB0'),
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#2D3748')
    )
    table_cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#1A202C')
    )

    story = []

    # Title & Header
    story.append(Paragraph("SECURITY LOG ANALYSER - INCIDENT REPORT", title_style))
    story.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | ICT Security Portfolio Assessment",
        subtitle_style
    ))
    story.append(Spacer(1, 8))

    # Ingestion & Telemetry Metrics Table
    story.append(Paragraph("1. Ingestion & Event Telemetry", heading2_style))

    total_events = len(df) if not df.empty else 0
    total_alerts = len(alerts_df) if not alerts_df.empty else 0
    success_count = int((df["login_outcome"] == "Success").sum()) if not df.empty and "login_outcome" in df.columns else 0
    failure_count = int((df["login_outcome"] == "Failure").sum()) if not df.empty and "login_outcome" in df.columns else 0
    unique_ips = int(df["source_ip"].dropna().nunique()) if not df.empty and "source_ip" in df.columns else 0

    metric_data = [
        ["Metric", "Value", "Metric", "Value"],
        ["Total Processed Lines", str(stats.get('total_lines', total_events)), "Filtered Events Analysed", str(total_events)],
        ["Successfully Parsed", str(stats.get('parsed_lines', total_events)), "Successful Logins", str(success_count)],
        ["Parse Success Rate", f"{stats.get('parse_success_rate_pct', 100.0)}%", "Failed Login Attempts", str(failure_count)],
        ["Unique Source IPs", str(unique_ips), "Total Security Alerts", str(total_alerts)],
    ]
    metric_table = Table(metric_data, colWidths=[150, 110, 150, 110])
    metric_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E2E8F0')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#1A365D')),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E0')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(metric_table)
    story.append(Spacer(1, 12))

    # Alert Findings
    story.append(Paragraph(f"2. Security Detection Alerts ({total_alerts} detected)", heading2_style))

    if alerts_df.empty:
        story.append(Paragraph("No security alerts detected under current detection criteria.", body_style))
    else:
        alert_rows = [["ID", "Severity", "Rule Name", "Source IP", "Account", "Explanation"]]
        for _, row in alerts_df.head(15).iterrows():
            alert_rows.append([
                Paragraph(str(row.get("alert_id", "")), table_cell_style),
                Paragraph(f"<b>{row.get('severity', '')}</b>", table_cell_style),
                Paragraph(str(row.get("rule_name", "")), table_cell_style),
                Paragraph(str(row.get("source_ip", "")), table_cell_style),
                Paragraph(str(row.get("username", "")), table_cell_style),
                Paragraph(str(row.get("explanation", "")), table_cell_style),
            ])

        alert_table = Table(alert_rows, colWidths=[45, 55, 110, 75, 65, 170])
        alert_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2D3748')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 7.5),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F7FAFC')]),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(alert_table)

    story.append(Spacer(1, 14))

    # Disclaimer note
    story.append(Paragraph(
        "<b>Notice:</b> This automated security log report is generated using rule-based behavioral "
        "heuristics. Alerts indicate suspicious anomalies warranting tier-1 triage and do not constitute "
        "forensic confirmation of compromise.",
        subtitle_style
    ))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
