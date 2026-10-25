"""
Log Parsing Engine for Security Log Analyser.

Parses supported Linux authentication log formats (e.g., auth.log, secure),
extracts key security fields, validates IP addresses using python's `ipaddress`
module, handles malformed or unrecognized lines safely, and returns a
normalized Pandas DataFrame along with parsing metrics.
"""

import re
import ipaddress
import logging
from datetime import datetime
from typing import Dict, Any, Tuple, List, Optional
import pandas as pd

import config

logger = logging.getLogger(__name__)

# Pre-compiled regular expressions for standard syslog authentication logs
# 1. Syslog RFC 3164 timestamp: "Oct 25 14:02:11"
# 2. Syslog ISO 8601 timestamp: "2026-10-25T14:02:11.123456+00:00" or "2026-10-25 14:02:11"
SYSLOG_LINE_REGEX = re.compile(
    r"^(?P<timestamp>(?:[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})|(?:\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?))\s+"
    r"(?P<hostname>[\w\.\-]+)\s+"
    r"(?P<process>[\w\.\-\(\)]+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

# Common SSH / Auth message patterns
RE_FAILED_PASSWORD = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)",
    re.IGNORECASE
)
RE_ACCEPTED_PASSWORD = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)",
    re.IGNORECASE
)
RE_INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\S+)(?: port (?P<port>\d+))?",
    re.IGNORECASE
)
RE_DISCONNECTED = re.compile(
    r"(?:Disconnected from (?:authenticating|invalid)?\s*user (?P<user>\S+) )?(?P<ip>\S+) port (?P<port>\d+)|Connection closed by (?:authenticating user (?P<user2>\S+) )?(?P<ip2>\S+) port (?P<port2>\d+)",
    re.IGNORECASE
)
RE_SESSION_OPENED = re.compile(
    r"pam_unix\([^:]+\): session opened for user (?P<user>\S+)(?: by \(uid=\d+\))?",
    re.IGNORECASE
)
RE_SESSION_CLOSED = re.compile(
    r"pam_unix\([^:]+\): session closed for user (?P<user>\S+)",
    re.IGNORECASE
)
RE_SUDO_COMMAND = re.compile(
    r"\s*(?P<user>\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(?P<runas>\S+)\s*;\s*COMMAND=(?P<command>.*)",
    re.IGNORECASE
)


def validate_ip(ip_str: Optional[str]) -> Optional[str]:
    """
    Validate that an IP string is a valid IPv4 or IPv6 address.
    Returns the valid IP string, or None if invalid or missing.
    """
    if not ip_str:
        return None
    ip_str = ip_str.strip("[](), \"'")
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return str(ip_obj)
    except ValueError:
        return None


def parse_timestamp(ts_str: str, default_year: Optional[int] = None) -> Optional[datetime]:
    """
    Parses timestamps from syslog or ISO 8601 strings.
    If the year is missing (standard BSD syslog), uses default_year or current year.
    Returns a datetime object or None if invalid.
    """
    if not ts_str:
        return None
    ts_str = ts_str.strip()
    if default_year is None:
        default_year = datetime.now().year

    # Try ISO formats first
    iso_formats = [
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f"
    ]
    for fmt in iso_formats:
        try:
            # Handle possible trailing Z
            cleaned_ts = ts_str.replace("Z", "+00:00")
            dt = datetime.strptime(cleaned_ts, fmt)
            # Normalize to naive UTC/local for consistent dataframe comparisons
            if dt.tzinfo is not None:
                dt = dt.replace(tzinfo=None)
            return dt
        except ValueError:
            continue

    # Try BSD Syslog format: "Oct 25 14:02:11" or "Oct  5 14:02:11" (single space or multiple)
    bsd_regex = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})$", ts_str)
    if bsd_regex:
        month, day, time_part = bsd_regex.groups()
        normalized_str = f"{month} {int(day):02d} {time_part} {default_year}"
        try:
            return datetime.strptime(normalized_str, "%b %d %H:%M:%S %Y")
        except ValueError:
            return None

    return None


def parse_log_line(line: str, line_number: int = 1, default_year: Optional[int] = None) -> Dict[str, Any]:
    """
    Parses a single log line into a standardized record.
    Preserves unparsed / malformed lines safely with is_parsed=False.
    """
    raw_line = line.rstrip("\r\n")
    if not raw_line.strip():
        return {
            "line_number": line_number,
            "raw_log": raw_line,
            "is_parsed": False,
            "error_reason": "Empty line",
            "timestamp": None,
            "raw_timestamp": None,
            "hostname": None,
            "process": None,
            "pid": None,
            "event_type": config.EVENT_TYPE_UNRECOGNIZED,
            "login_outcome": "N/A",
            "username": None,
            "source_ip": None,
            "port": None,
            "description": "Empty line",
        }

    match = SYSLOG_LINE_REGEX.match(raw_line)
    if not match:
        # Check if line at least has some recognizable content or is completely malformed
        return {
            "line_number": line_number,
            "raw_log": raw_line,
            "is_parsed": False,
            "error_reason": "Header format unrecognized (expected standard syslog / ISO format)",
            "timestamp": None,
            "raw_timestamp": None,
            "hostname": None,
            "process": None,
            "pid": None,
            "event_type": config.EVENT_TYPE_UNRECOGNIZED,
            "login_outcome": "N/A",
            "username": None,
            "source_ip": None,
            "port": None,
            "description": f"Malformed or non-syslog line: {raw_line[:60]}...",
        }

    raw_ts = match.group("timestamp")
    parsed_dt = parse_timestamp(raw_ts, default_year=default_year)
    hostname = match.group("hostname")
    process = match.group("process")
    pid = match.group("pid")
    message = match.group("message")

    # Default extracted fields
    event_type = config.EVENT_TYPE_SYSTEM_EVENT
    login_outcome = "N/A"
    username = None
    source_ip = None
    port = None
    description = message

    # Check for Failed Password
    fail_match = RE_FAILED_PASSWORD.search(message)
    if fail_match:
        event_type = config.EVENT_TYPE_LOGIN_FAILURE
        login_outcome = "Failure"
        username = fail_match.group("user")
        source_ip = validate_ip(fail_match.group("ip"))
        port = int(fail_match.group("port")) if fail_match.group("port") else None
        description = f"Failed password attempt for user '{username}' from {source_ip or 'unknown IP'}"

    # Check for Accepted Password / Public Key
    elif (accept_match := RE_ACCEPTED_PASSWORD.search(message)):
        event_type = config.EVENT_TYPE_LOGIN_SUCCESS
        login_outcome = "Success"
        username = accept_match.group("user")
        source_ip = validate_ip(accept_match.group("ip"))
        port = int(accept_match.group("port")) if accept_match.group("port") else None
        description = f"Successful authentication for user '{username}' from {source_ip or 'unknown IP'}"

    # Check for Invalid User
    elif (inv_match := RE_INVALID_USER.search(message)):
        event_type = config.EVENT_TYPE_LOGIN_FAILURE
        login_outcome = "Failure"
        username = inv_match.group("user")
        source_ip = validate_ip(inv_match.group("ip"))
        port = int(inv_match.group("port")) if inv_match.group("port") else None
        description = f"Authentication attempt with invalid username '{username}' from {source_ip or 'unknown IP'}"

    # Check for Session Opened
    elif (sess_open := RE_SESSION_OPENED.search(message)):
        event_type = config.EVENT_TYPE_LOGIN_SUCCESS
        login_outcome = "Success"
        username = sess_open.group("user")
        description = f"PAM session opened for user '{username}'"

    # Check for Session Closed
    elif (sess_close := RE_SESSION_CLOSED.search(message)):
        event_type = config.EVENT_TYPE_LOGOUT
        login_outcome = "N/A"
        username = sess_close.group("user")
        description = f"PAM session closed for user '{username}'"

    # Check for Disconnection
    elif (disc_match := RE_DISCONNECTED.search(message)):
        event_type = config.EVENT_TYPE_SSH_DISCONNECT
        login_outcome = "N/A"
        raw_ip = disc_match.group("ip") or disc_match.group("ip2")
        raw_user = disc_match.group("user") or disc_match.group("user2")
        raw_port = disc_match.group("port") or disc_match.group("port2")
        username = raw_user
        source_ip = validate_ip(raw_ip)
        port = int(raw_port) if raw_port else None
        description = f"SSH connection disconnected from {source_ip or 'unknown IP'}"

    # Check for Sudo Execution
    elif (sudo_match := RE_SUDO_COMMAND.search(message)):
        event_type = config.EVENT_TYPE_SYSTEM_EVENT
        username = sudo_match.group("user")
        runas = sudo_match.group("runas")
        cmd = sudo_match.group("command")
        description = f"User '{username}' executed privileged command as '{runas}': {cmd}"

    return {
        "line_number": line_number,
        "raw_log": raw_line,
        "is_parsed": True,
        "error_reason": None,
        "timestamp": parsed_dt,
        "raw_timestamp": raw_ts,
        "hostname": hostname,
        "process": process,
        "pid": pid,
        "event_type": event_type,
        "login_outcome": login_outcome,
        "username": username,
        "source_ip": source_ip,
        "port": port,
        "description": description,
    }


def parse_log_content(
    content: str, default_year: Optional[int] = None
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Parses full text log content into a normalized Pandas DataFrame and statistics.

    Returns:
        (df_events, stats_dict)
        where stats_dict contains:
            - total_lines
            - parsed_lines
            - unparsed_lines
            - parse_success_rate_pct
    """
    if not content or not content.strip():
        empty_df = pd.DataFrame(columns=[
            "line_number", "timestamp", "raw_timestamp", "hostname",
            "process", "pid", "event_type", "login_outcome", "username",
            "source_ip", "port", "description", "raw_log", "is_parsed", "error_reason"
        ])
        stats = {
            "total_lines": 0,
            "parsed_lines": 0,
            "unparsed_lines": 0,
            "parse_success_rate_pct": 0.0
        }
        return empty_df, stats

    lines = content.splitlines()
    records = []
    parsed_count = 0
    unparsed_count = 0

    for idx, line in enumerate(lines, start=1):
        if not line.strip():
            continue  # Skip trailing empty lines gracefully
        record = parse_log_line(line, line_number=idx, default_year=default_year)
        if record["is_parsed"]:
            parsed_count += 1
        else:
            unparsed_count += 1
        records.append(record)

    total_lines = len(records)
    rate = (parsed_count / total_lines * 100.0) if total_lines > 0 else 0.0

    stats = {
        "total_lines": total_lines,
        "parsed_lines": parsed_count,
        "unparsed_lines": unparsed_count,
        "parse_success_rate_pct": round(rate, 2),
    }

    df = pd.DataFrame(records)
    # Ensure datetime format for timestamps
    if not df.empty and "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"])

    return df, stats
