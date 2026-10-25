"""
Automated unit tests for Log Parser module.
"""

from datetime import datetime
import pandas as pd
import pytest

from src.log_parser import (
    validate_ip,
    parse_timestamp,
    parse_log_line,
    parse_log_content
)
import config


class TestValidateIP:
    """Tests IP address validation logic."""

    def test_valid_ipv4(self):
        assert validate_ip("192.168.1.1") == "192.168.1.1"
        assert validate_ip("10.0.0.254") == "10.0.0.254"
        assert validate_ip(" 172.16.0.5 ") == "172.16.0.5"

    def test_valid_ipv6(self):
        assert validate_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "2001:db8:85a3::8a2e:370:7334"
        assert validate_ip("::1") == "::1"

    def test_invalid_ip(self):
        assert validate_ip("999.999.999.999") is None
        assert validate_ip("not_an_ip") is None
        assert validate_ip("192.168.1.500") is None

    def test_empty_and_none(self):
        assert validate_ip(None) is None
        assert validate_ip("") is None
        assert validate_ip("   ") is None


class TestParseTimestamp:
    """Tests timestamp parsing across formats and edge cases."""

    def test_bsd_syslog_format(self):
        dt = parse_timestamp("Oct 25 10:14:02", default_year=2026)
        assert dt is not None
        assert dt.year == 2026
        assert dt.month == 10
        assert dt.day == 25
        assert dt.hour == 10
        assert dt.minute == 14
        assert dt.second == 2

    def test_bsd_syslog_single_digit_day(self):
        dt = parse_timestamp("Oct  5 08:05:00", default_year=2026)
        assert dt is not None
        assert dt.day == 5

    def test_iso8601_format(self):
        dt = parse_timestamp("2026-10-25T14:30:00+00:00")
        assert dt is not None
        assert dt.year == 2026
        assert dt.month == 10
        assert dt.day == 25
        assert dt.hour == 14
        assert dt.minute == 30

    def test_invalid_timestamp(self):
        assert parse_timestamp("Invalid Date String") is None
        assert parse_timestamp("") is None
        assert parse_timestamp(None) is None


class TestParseLogLine:
    """Tests parsing individual log lines and event extraction."""

    def test_successful_password_login(self):
        line = "Oct 25 10:00:00 srv-01 sshd[1234]: Accepted password for alice from 192.168.1.50 port 54122 ssh2"
        rec = parse_log_line(line, line_number=1, default_year=2026)
        assert rec["is_parsed"] is True
        assert rec["event_type"] == config.EVENT_TYPE_LOGIN_SUCCESS
        assert rec["login_outcome"] == "Success"
        assert rec["username"] == "alice"
        assert rec["source_ip"] == "192.168.1.50"
        assert rec["port"] == 54122
        assert rec["hostname"] == "srv-01"

    def test_failed_password_login(self):
        line = "Oct 25 10:01:05 srv-01 sshd[2101]: Failed password for invalid user admin from 203.0.113.45 port 39120 ssh2"
        rec = parse_log_line(line, line_number=2, default_year=2026)
        assert rec["is_parsed"] is True
        assert rec["event_type"] == config.EVENT_TYPE_LOGIN_FAILURE
        assert rec["login_outcome"] == "Failure"
        assert rec["username"] == "admin"
        assert rec["source_ip"] == "203.0.113.45"
        assert rec["port"] == 39120

    def test_session_disconnect(self):
        line = "Oct 25 10:05:00 srv-01 sshd[2136]: Connection closed by 203.0.113.45 port 39150 [preauth]"
        rec = parse_log_line(line, line_number=3, default_year=2026)
        assert rec["is_parsed"] is True
        assert rec["event_type"] == config.EVENT_TYPE_SSH_DISCONNECT
        assert rec["source_ip"] == "203.0.113.45"

    def test_sudo_execution(self):
        line = "Oct 25 10:06:00 srv-01 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls"
        rec = parse_log_line(line, line_number=4, default_year=2026)
        assert rec["is_parsed"] is True
        assert rec["event_type"] == config.EVENT_TYPE_SYSTEM_EVENT
        assert rec["username"] == "alice"

    def test_invalid_ip_in_log_handled_safely(self):
        line = "Oct 25 10:10:00 srv-01 sshd[99]: Failed password for root from 999.999.999.999 port 22 ssh2"
        rec = parse_log_line(line, line_number=5, default_year=2026)
        assert rec["is_parsed"] is True
        assert rec["source_ip"] is None  # Invalid IP rejected safely without crash

    def test_malformed_unrecognized_line(self):
        line = "THIS IS NOT A VALID SYSLOG HEADER CORRUPT ENTRY"
        rec = parse_log_line(line, line_number=6)
        assert rec["is_parsed"] is False
        assert rec["event_type"] == config.EVENT_TYPE_UNRECOGNIZED
        assert rec["error_reason"] is not None

    def test_empty_line(self):
        rec = parse_log_line("   ", line_number=7)
        assert rec["is_parsed"] is False
        assert rec["error_reason"] == "Empty line"


class TestParseLogContent:
    """Tests parsing multi-line log documents and stats generation."""

    def test_empty_content(self):
        df, stats = parse_log_content("")
        assert df.empty
        assert stats["total_lines"] == 0
        assert stats["parsed_lines"] == 0
        assert stats["parse_success_rate_pct"] == 0.0

    def test_mixed_log_batch(self):
        content = """Oct 25 10:00:00 srv-01 sshd[1]: Accepted password for bob from 10.0.0.1 port 22 ssh2
Oct 25 10:01:00 srv-01 sshd[2]: Failed password for bob from 10.0.0.1 port 22 ssh2
SOME MALFORMED RECORD LINE
Oct 25 10:02:00 srv-01 sudo:   bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/cat /etc/hosts
"""
        df, stats = parse_log_content(content, default_year=2026)
        assert len(df) == 4
        assert stats["total_lines"] == 4
        assert stats["parsed_lines"] == 3
        assert stats["unparsed_lines"] == 1
        assert stats["parse_success_rate_pct"] == 75.0
        assert (df["login_outcome"] == "Success").sum() == 1
        assert (df["login_outcome"] == "Failure").sum() == 1
