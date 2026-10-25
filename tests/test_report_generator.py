"""
Automated unit tests for Report Generator module.
"""

from datetime import datetime
import pandas as pd
import pytest

from src.report_generator import (
    export_events_to_csv,
    export_alerts_to_csv,
    generate_executive_summary_text,
    generate_pdf_report,
    REPORTLAB_AVAILABLE
)


@pytest.fixture
def sample_events_df():
    return pd.DataFrame([
        {
            "line_number": 1,
            "timestamp": datetime(2026, 10, 25, 10, 0, 0),
            "hostname": "srv-01",
            "process": "sshd",
            "event_type": "Login Success",
            "login_outcome": "Success",
            "username": "alice",
            "source_ip": "192.168.1.50",
            "port": 22,
            "description": "Successful login"
        },
        {
            "line_number": 2,
            "timestamp": datetime(2026, 10, 25, 10, 1, 0),
            "hostname": "srv-01",
            "process": "sshd",
            "event_type": "Login Failure",
            "login_outcome": "Failure",
            "username": "root",
            "source_ip": "203.0.113.45",
            "port": 22,
            "description": "Failed password attempt"
        }
    ])


@pytest.fixture
def sample_alerts_df():
    return pd.DataFrame([
        {
            "alert_id": "ALT-0001",
            "rule_id": "RULE_1",
            "rule_name": "Repeated Failed Logins",
            "severity": "High",
            "timestamp": datetime(2026, 10, 25, 10, 5, 0),
            "source_ip": "203.0.113.45",
            "username": "root, admin",
            "event_count": 5,
            "explanation": "5 failed logins detected in 5 minutes."
        }
    ])


class TestCSVExport:
    """Tests CSV export generation."""

    def test_export_events_csv_contains_headers_and_rows(self, sample_events_df):
        csv_str = export_events_to_csv(sample_events_df)
        assert "timestamp" in csv_str
        assert "alice" in csv_str
        assert "203.0.113.45" in csv_str

    def test_export_events_csv_empty(self):
        empty_df = pd.DataFrame()
        assert export_events_to_csv(empty_df) == ""

    def test_export_alerts_csv(self, sample_alerts_df):
        csv_str = export_alerts_to_csv(sample_alerts_df)
        assert "ALT-0001" in csv_str
        assert "High" in csv_str
        assert "Repeated Failed Logins" in csv_str

    def test_export_alerts_csv_empty(self):
        assert export_alerts_to_csv(pd.DataFrame()) == ""


class TestExecutiveSummaryText:
    """Tests executive text summary report."""

    def test_summary_with_alerts(self, sample_events_df, sample_alerts_df):
        stats = {
            "total_lines": 2,
            "parsed_lines": 2,
            "unparsed_lines": 0,
            "parse_success_rate_pct": 100.0
        }
        text = generate_executive_summary_text(sample_events_df, sample_alerts_df, stats)
        assert "SECURITY LOG ANALYSIS EXECUTIVE REPORT" in text
        assert "Total Filtered Events:     2" in text
        assert "Total Alerts Generated:    1" in text
        assert "ALT-0001" in text

    def test_summary_without_alerts(self, sample_events_df):
        stats = {"total_lines": 1, "parsed_lines": 1, "unparsed_lines": 0, "parse_success_rate_pct": 100.0}
        text = generate_executive_summary_text(sample_events_df, pd.DataFrame(), stats)
        assert "No anomalous activity or brute-force patterns detected" in text


class TestPDFReport:
    """Tests PDF report generation."""

    def test_pdf_generation_bytes(self, sample_events_df, sample_alerts_df):
        if not REPORTLAB_AVAILABLE:
            pytest.skip("ReportLab not installed")

        stats = {
            "total_lines": 2,
            "parsed_lines": 2,
            "unparsed_lines": 0,
            "parse_success_rate_pct": 100.0
        }
        pdf_bytes = generate_pdf_report(sample_events_df, sample_alerts_df, stats)
        assert pdf_bytes is not None
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF")
