"""
Security Detection Engine for Security Log Analyser.

Executes transparent, rule-based cybersecurity anomaly detection with
configurable thresholds against normalized log events.

Rules:
- Rule 1: Repeated Failed Logins (Brute Force candidate)
- Rule 2: Successful Login After Repeated Failures (Credential compromise candidate)
- Rule 3: Unusual Event Bursts (High event velocity from single source)
- Rule 4: Repeated Failed-Login Activity Across Entire Dataset
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import pandas as pd

import config


class SecurityDetectionEngine:
    """
    Evaluates normalized log DataFrames against configured security detection rules.
    """

    def __init__(
        self,
        rule1_threshold: int = config.RULE1_FAILED_LOGIN_THRESHOLD,
        rule1_window_sec: int = config.RULE1_WINDOW_SECONDS,
        rule2_fail_count: int = config.RULE2_PREVIOUS_FAIL_COUNT,
        rule2_window_sec: int = config.RULE2_WINDOW_SECONDS,
        rule3_burst_count: int = config.RULE3_BURST_EVENT_COUNT,
        rule3_window_sec: int = config.RULE3_WINDOW_SECONDS,
        rule4_dataset_fails: int = config.RULE4_DATASET_FAIL_THRESHOLD,
    ):
        self.rule1_threshold = rule1_threshold
        self.rule1_window_sec = rule1_window_sec
        self.rule2_fail_count = rule2_fail_count
        self.rule2_window_sec = rule2_window_sec
        self.rule3_burst_count = rule3_burst_count
        self.rule3_window_sec = rule3_window_sec
        self.rule4_dataset_fails = rule4_dataset_fails

    def detect_rule1_repeated_failed_logins(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Rule 1: Detects at least N failed logins from the same source IP within a rolling window.
        """
        alerts = []
        if df.empty or "source_ip" not in df.columns or "login_outcome" not in df.columns:
            return alerts

        # Filter failed logins with valid timestamps and source IPs
        fails = df[
            (df["login_outcome"] == "Failure")
            & (df["source_ip"].notna())
            & (df["timestamp"].notna())
        ].copy()

        if fails.empty:
            return alerts

        fails = fails.sort_values("timestamp")
        window_delta = timedelta(seconds=self.rule1_window_sec)

        # Evaluate rolling windows per source IP
        for ip, group in fails.groupby("source_ip"):
            records = group.to_dict("records")
            n = len(records)
            last_alerted_idx = -1

            for i in range(n):
                if i < last_alerted_idx:
                    continue

                curr_ts = records[i]["timestamp"]
                # Find all failures within window ending at curr_ts or starting from curr_ts
                window_events = [
                    r for r in records
                    if curr_ts <= r["timestamp"] <= curr_ts + window_delta
                ]

                if len(window_events) >= self.rule1_threshold:
                    users_targeted = list({
                        r["username"] for r in window_events if r.get("username")
                    })
                    target_summary = ", ".join(users_targeted[:5]) if users_targeted else "unspecified"
                    if len(users_targeted) > 5:
                        target_summary += f" (+{len(users_targeted) - 5} more)"

                    last_event = window_events[-1]
                    alerts.append({
                        "rule_id": "RULE_1",
                        "rule_name": "Repeated Failed Logins (Brute Force Suspected)",
                        "severity": config.RULE1_SEVERITY,
                        "timestamp": last_event["timestamp"],
                        "source_ip": ip,
                        "username": target_summary,
                        "event_count": len(window_events),
                        "window_seconds": self.rule1_window_sec,
                        "explanation": (
                            f"Detected {len(window_events)} failed login attempts from IP {ip} "
                            f"within {self.rule1_window_sec // 60} minutes. "
                            f"Targeted user accounts: [{target_summary}]. "
                            f"Pattern indicates automated password guessing or brute-force scanning."
                        )
                    })
                    # Skip to the end of this cluster to prevent duplicate alerts for the same burst
                    last_alerted_idx = records.index(window_events[-1]) + 1

        return alerts

    def detect_rule2_success_after_failures(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Rule 2: Flags a successful login from the same source IP when it follows
        at least N failed login events from that IP within the preceding window.
        """
        alerts = []
        if df.empty or "source_ip" not in df.columns or "login_outcome" not in df.columns:
            return alerts

        valid_events = df[
            (df["source_ip"].notna())
            & (df["timestamp"].notna())
            & (df["login_outcome"].isin(["Success", "Failure"]))
        ].copy()

        if valid_events.empty:
            return alerts

        valid_events = valid_events.sort_values("timestamp")
        window_delta = timedelta(seconds=self.rule2_window_sec)

        for ip, group in valid_events.groupby("source_ip"):
            records = group.to_dict("records")
            for i, event in enumerate(records):
                if event["login_outcome"] == "Success":
                    success_ts = event["timestamp"]
                    window_start = success_ts - window_delta

                    # Look for preceding failures in [window_start, success_ts)
                    preceding_failures = [
                        r for r in records[:i]
                        if r["login_outcome"] == "Failure"
                        and window_start <= r["timestamp"] < success_ts
                    ]

                    if len(preceding_failures) >= self.rule2_fail_count:
                        failed_users = list({
                            r["username"] for r in preceding_failures if r.get("username")
                        })
                        failed_user_str = ", ".join(failed_users[:3]) if failed_users else "various"
                        curr_user = event.get("username") or "unknown"

                        alerts.append({
                            "rule_id": "RULE_2",
                            "rule_name": "Successful Login After Repeated Failures",
                            "severity": config.RULE2_SEVERITY,
                            "timestamp": success_ts,
                            "source_ip": ip,
                            "username": curr_user,
                            "event_count": len(preceding_failures) + 1,
                            "window_seconds": self.rule2_window_sec,
                            "explanation": (
                                f"A successful login for account '{curr_user}' occurred from IP {ip} "
                                f"after {len(preceding_failures)} failed login attempts from the same IP "
                                f"within the preceding {self.rule2_window_sec // 60} minutes. "
                                f"Previous attempted accounts: [{failed_user_str}]. "
                                f"High-risk anomaly indicating potential credential compromise."
                            )
                        })

        return alerts

    def detect_rule3_event_bursts(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Rule 3: Flags at least N events from the same source IP within a rolling window.
        """
        alerts = []
        if df.empty or "source_ip" not in df.columns or "timestamp" not in df.columns:
            return alerts

        valid_events = df[
            (df["source_ip"].notna()) & (df["timestamp"].notna())
        ].copy()

        if valid_events.empty:
            return alerts

        valid_events = valid_events.sort_values("timestamp")
        window_delta = timedelta(seconds=self.rule3_window_sec)

        for ip, group in valid_events.groupby("source_ip"):
            records = group.to_dict("records")
            n = len(records)
            last_alerted_idx = -1

            for i in range(n):
                if i < last_alerted_idx:
                    continue

                curr_ts = records[i]["timestamp"]
                window_events = [
                    r for r in records
                    if curr_ts <= r["timestamp"] <= curr_ts + window_delta
                ]

                if len(window_events) >= self.rule3_burst_count:
                    event_types = list({r["event_type"] for r in window_events})
                    last_event = window_events[-1]
                    alerts.append({
                        "rule_id": "RULE_3",
                        "rule_name": "Unusual Event Burst Rate",
                        "severity": config.RULE3_SEVERITY,
                        "timestamp": last_event["timestamp"],
                        "source_ip": ip,
                        "username": last_event.get("username") or "multiple",
                        "event_count": len(window_events),
                        "window_seconds": self.rule3_window_sec,
                        "explanation": (
                            f"Source IP {ip} generated {len(window_events)} log events "
                            f"within {self.rule3_window_sec // 60} minutes "
                            f"(threshold: >= {self.rule3_burst_count}). "
                            f"Observed event types: {', '.join(event_types)}. "
                            f"Indicates aggressive automated scanning or denial-of-service attempt."
                        )
                    })
                    last_alerted_idx = records.index(window_events[-1]) + 1

        return alerts

    def detect_rule4_dataset_repeated_failures(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Rule 4: Identifies source IP addresses with unusually frequent failed logins
        throughout the entire analysed dataset.
        """
        alerts = []
        if df.empty or "source_ip" not in df.columns or "login_outcome" not in df.columns:
            return alerts

        fails = df[
            (df["login_outcome"] == "Failure") & (df["source_ip"].notna())
        ].copy()

        if fails.empty:
            return alerts

        ip_counts = fails.groupby("source_ip").size()
        flagged_ips = ip_counts[ip_counts >= self.rule4_dataset_fails].to_dict()

        for ip, count in flagged_ips.items():
            ip_fails = fails[fails["source_ip"] == ip]
            targeted_users = [u for u in ip_fails["username"].dropna().unique() if u]
            target_str = ", ".join(targeted_users[:5]) if targeted_users else "unspecified"
            first_seen = ip_fails["timestamp"].min() if "timestamp" in ip_fails.columns else None
            last_seen = ip_fails["timestamp"].max() if "timestamp" in ip_fails.columns else None

            time_str = ""
            if pd.notna(first_seen) and pd.notna(last_seen):
                time_str = f" between {first_seen} and {last_seen}"

            alerts.append({
                "rule_id": "RULE_4",
                "rule_name": "High-Frequency Failed Logins (Dataset Wide)",
                "severity": config.RULE4_SEVERITY,
                "timestamp": last_seen if pd.notna(last_seen) else datetime.now(),
                "source_ip": ip,
                "username": target_str,
                "event_count": int(count),
                "window_seconds": None,
                "explanation": (
                    f"Source IP {ip} accumulated {count} total failed logins across the dataset{time_str}. "
                    f"Target accounts: [{target_str}]. "
                    f"Persistent failure rate exceeds baseline threshold ({self.rule4_dataset_fails} attempts)."
                )
            })

        return alerts

    def run_all_detections(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Runs all configured detection rules and returns a consolidated
        Pandas DataFrame of alerts sorted by timestamp descending.
        """
        if df.empty:
            return pd.DataFrame(columns=[
                "alert_id", "rule_id", "rule_name", "severity",
                "timestamp", "source_ip", "username", "event_count", "explanation"
            ])

        all_alerts: List[Dict[str, Any]] = []
        all_alerts.extend(self.detect_rule1_repeated_failed_logins(df))
        all_alerts.extend(self.detect_rule2_success_after_failures(df))
        all_alerts.extend(self.detect_rule3_event_bursts(df))
        all_alerts.extend(self.detect_rule4_dataset_repeated_failures(df))

        if not all_alerts:
            return pd.DataFrame(columns=[
                "alert_id", "rule_id", "rule_name", "severity",
                "timestamp", "source_ip", "username", "event_count", "explanation"
            ])

        # Assign unique incremental Alert IDs
        for idx, alert in enumerate(all_alerts, start=1):
            alert["alert_id"] = f"ALT-{idx:04d}"

        alerts_df = pd.DataFrame(all_alerts)
        if "timestamp" in alerts_df.columns:
            alerts_df["timestamp"] = pd.to_datetime(alerts_df["timestamp"])
            alerts_df = alerts_df.sort_values("timestamp", ascending=False)

        return alerts_df
