"""
Configuration settings for the Security Logger application.
"""

LOG_FILE = "security_log.txt"
REPORT_FILE = "security_report.txt"

AUTH_LOG_PATH = "/var/log/auth.log"
POLLING_INTERVAL = 0.1  # seconds between checks

WINDOW_TITLE = "Security Logger"
WINDOW_SIZE = "700x500"
REFRESH_RATE = 2000  # milliseconds

FAILED_LOGIN_THRESHOLD = 3
SUDO_COMMAND_THRESHOLD = 1
