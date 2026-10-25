"""
Configuration settings for the Security Log Analyser.

Centralises detection rule thresholds, upload limits, severity levels,
and file path configurations.
"""

from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
SAMPLE_LOG_PATH = DATA_DIR / "sample_auth.log"

# Upload Constraints
ALLOWED_EXTENSIONS = {".log", ".txt"}
MAX_UPLOAD_SIZE_MB = 10  # Maximum file size permitted for upload in Megabytes
MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024

# Security Detection Engine Rules and Thresholds
# Rule 1: Repeated Failed Logins (Brute Force candidate)
RULE1_FAILED_LOGIN_THRESHOLD = 5
RULE1_WINDOW_SECONDS = 300  # 5 minutes
RULE1_SEVERITY = "High"

# Rule 2: Successful Login After Repeated Failures (Possible credential compromise)
RULE2_PREVIOUS_FAIL_COUNT = 5
RULE2_WINDOW_SECONDS = 600  # 10 minutes prior
RULE2_SEVERITY = "High"

# Rule 3: Unusual Event Bursts (High rate of activity from a single source)
RULE3_BURST_EVENT_COUNT = 20
RULE3_WINDOW_SECONDS = 300  # 5 minutes
RULE3_SEVERITY = "Medium"

# Rule 4: Repeated Failed-Login Activity Across Dataset
RULE4_DATASET_FAIL_THRESHOLD = 8
RULE4_SEVERITY = "Medium"

# Severity Levels
SEVERITY_LEVELS = ["Informational", "Low", "Medium", "High"]

# Color palette for alerts and UI
SEVERITY_COLORS = {
    "High": "#E53E3E",          # Red
    "Medium": "#ED8936",        # Orange
    "Low": "#ECC94B",           # Amber/Yellow
    "Informational": "#4299E1"  # Blue
}

# Event Types recognized
EVENT_TYPE_LOGIN_SUCCESS = "Login Success"
EVENT_TYPE_LOGIN_FAILURE = "Login Failure"
EVENT_TYPE_LOGOUT = "Logout"
EVENT_TYPE_SSH_DISCONNECT = "Session Disconnected"
EVENT_TYPE_SYSTEM_EVENT = "System Event"
EVENT_TYPE_UNRECOGNIZED = "Unrecognized"
