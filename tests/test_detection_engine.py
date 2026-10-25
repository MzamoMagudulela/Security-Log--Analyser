"""
Automated unit tests for Security Detection Engine.
"""

from datetime import datetime, timedelta
import pandas as pd
import pytest

from src.detection_engine import SecurityDetectionEngine
import config


@pytest.fixture
def engine():
    """Initializes a detection engine with default configurations."""
    return SecurityDetectionEngine(
        rule1_threshold=5,
        rule1_window_sec=300,
        rule2_fail_count=5,
        rule2_window_sec=600,
        rule3_burst_count=20,
        rule3_window_sec=300,
        rule4_dataset_fails=8
    )


class TestRule1RepeatedFailedLogins:
    """Tests Rule 1: Repeated Failed Logins within 5 minutes."""

    def test_threshold_triggered(self, engine):
        base_time = datetime(2026, 10, 25, 10, 0, 0)
        events = [
            {
                "timestamp": base_time + timedelta(seconds=i * 30),
                "source_ip": "198.51.100.1",
                "login_outcome": "Failure",
                "event_type": config.EVENT_TYPE_LOGIN_FAILURE,
                "username": f"user{i}"
            }
            for i in range(5)
        ]
        df = pd.DataFrame(events)
        alerts = engine.detect_rule1_repeated_failed_logins(df)
        assert len(alerts) == 1
        assert alerts[0]["rule_id"] == "RULE_1"
        assert alerts[0]["source_ip"] == "198.51.100.1"
        assert alerts[0]["event_count"] >= 5
        assert alerts[0]["severity"] == "High"

    def test_below_threshold_boundary(self, engine):
        base_time = datetime(2026, 10, 25, 10, 0, 0)
        events = [
            {
                "timestamp": base_time + timedelta(seconds=i * 30),
                "source_ip": "198.51.100.1",
                "login_outcome": "Failure",
                "event_type": config.EVENT_TYPE_LOGIN_FAILURE,
                "username": "user1"
            }
            for i in range(4)  # 4 is below threshold of 5
        ]
        df = pd.DataFrame(events)
        alerts = engine.detect_rule1_repeated_failed_logins(df)
        assert len(alerts) == 0

    def test_window_exceeded_no_alert(self, engine):
        base_time = datetime(2026, 10, 25, 10, 0, 0)
        # 5 failures spread over 1 hour (outside 300s window)
        events = [
            {
                "timestamp": base_time + timedelta(minutes=i * 15),
                "source_ip": "198.51.100.1",
                "login_outcome": "Failure",
                "event_type": config.EVENT_TYPE_LOGIN_FAILURE,
                "username": "user1"
            }
            for i in range(5)
        ]
        df = pd.DataFrame(events)
        alerts = engine.detect_rule1_repeated_failed_logins(df)
        assert len(alerts) == 0


class TestRule2SuccessAfterFailures:
    """Tests Rule 2: Successful Login After Repeated Failures within 10 minutes."""

    def test_success_after_5_failures_triggers_alert(self, engine):
        base_time = datetime(2026, 10, 25, 10, 0, 0)
        # 5 failures from min 0 to min 4, then success at min 5
        events = [
            {
                "timestamp": base_time + timedelta(minutes=i),
                "source_ip": "198.51.100.2",
                "login_outcome": "Failure",
                "event_type": config.EVENT_TYPE_LOGIN_FAILURE,
                "username": "target_user"
            }
            for i in range(5)
        ]
        events.append({
            "timestamp": base_time + timedelta(minutes=5),
            "source_ip": "198.51.100.2",
            "login_outcome": "Success",
            "event_type": config.EVENT_TYPE_LOGIN_SUCCESS,
            "username": "target_user"
        })
        df = pd.DataFrame(events)
        alerts = engine.detect_rule2_success_after_failures(df)
        assert len(alerts) == 1
        assert alerts[0]["rule_id"] == "RULE_2"
        assert alerts[0]["source_ip"] == "198.51.100.2"
        assert alerts[0]["username"] == "target_user"
        assert alerts[0]["severity"] == "High"

    def test_insufficient_failures_before_success(self, engine):
        base_time = datetime(2026, 10, 25, 10, 0, 0)
        # 4 failures (less than 5) then success
        events = [
            {
                "timestamp": base_time + timedelta(minutes=i),
                "source_ip": "198.51.100.2",
                "login_outcome": "Failure",
                "event_type": config.EVENT_TYPE_LOGIN_FAILURE,
                "username": "target_user"
            }
            for i in range(4)
        ]
        events.append({
            "timestamp": base_time + timedelta(minutes=5),
            "source_ip": "198.51.100.2",
            "login_outcome": "Success",
            "event_type": config.EVENT_TYPE_LOGIN_SUCCESS,
            "username": "target_user"
        })
        df = pd.DataFrame(events)
        alerts = engine.detect_rule2_success_after_failures(df)
        assert len(alerts) == 0


class TestRule3UnusualEventBursts:
    """Tests Rule 3: Event Bursts (20 events in 5 minutes)."""

    def test_burst_triggered(self, engine):
        base_time = datetime(2026, 10, 25, 10, 0, 0)
        # 20 events in 2 minutes
        events = [
            {
                "timestamp": base_time + timedelta(seconds=i * 6),
                "source_ip": "198.51.100.99",
                "login_outcome": "Failure",
                "event_type": config.EVENT_TYPE_LOGIN_FAILURE,
                "username": f"bot_{i}"
            }
            for i in range(20)
        ]
        df = pd.DataFrame(events)
        alerts = engine.detect_rule3_event_bursts(df)
        assert len(alerts) == 1
        assert alerts[0]["rule_id"] == "RULE_3"
        assert alerts[0]["source_ip"] == "198.51.100.99"
        assert alerts[0]["event_count"] >= 20

    def test_burst_below_threshold(self, engine):
        base_time = datetime(2026, 10, 25, 10, 0, 0)
        events = [
            {
                "timestamp": base_time + timedelta(seconds=i * 6),
                "source_ip": "198.51.100.99",
                "login_outcome": "Failure",
                "event_type": config.EVENT_TYPE_LOGIN_FAILURE,
                "username": f"bot_{i}"
            }
            for i in range(19)  # 19 < 20
        ]
        df = pd.DataFrame(events)
        alerts = engine.detect_rule3_event_bursts(df)
        assert len(alerts) == 0


class TestRule4DatasetRepeatedFailures:
    """Tests Rule 4: Frequent Failed Logins Across Dataset (threshold 8)."""

    def test_threshold_triggered(self, engine):
        base_time = datetime(2026, 10, 25, 8, 0, 0)
        events = [
            {
                "timestamp": base_time + timedelta(hours=i),
                "source_ip": "203.0.113.45",
                "login_outcome": "Failure",
                "event_type": config.EVENT_TYPE_LOGIN_FAILURE,
                "username": "admin"
            }
            for i in range(8)
        ]
        df = pd.DataFrame(events)
        alerts = engine.detect_rule4_dataset_repeated_failures(df)
        assert len(alerts) == 1
        assert alerts[0]["rule_id"] == "RULE_4"
        assert alerts[0]["event_count"] == 8

    def test_below_threshold(self, engine):
        base_time = datetime(2026, 10, 25, 8, 0, 0)
        events = [
            {
                "timestamp": base_time + timedelta(hours=i),
                "source_ip": "203.0.113.45",
                "login_outcome": "Failure",
                "event_type": config.EVENT_TYPE_LOGIN_FAILURE,
                "username": "admin"
            }
            for i in range(7)
        ]
        df = pd.DataFrame(events)
        alerts = engine.detect_rule4_dataset_repeated_failures(df)
        assert len(alerts) == 0


class TestEngineEdgeCases:
    """Tests robustness with missing data, None values, and empty dataframes."""

    def test_empty_dataframe(self, engine):
        df = pd.DataFrame()
        alerts = engine.run_all_detections(df)
        assert alerts.empty

    def test_missing_ip_and_timestamp_handled_safely(self, engine):
        df = pd.DataFrame([
            {"timestamp": None, "source_ip": None, "login_outcome": "Failure", "event_type": "Login Failure"},
            {"timestamp": pd.NaT, "source_ip": "1.2.3.4", "login_outcome": "Failure", "event_type": "Login Failure"},
            {"timestamp": datetime.now(), "source_ip": None, "login_outcome": "Failure", "event_type": "Login Failure"},
        ])
        alerts = engine.run_all_detections(df)
        assert alerts.empty
