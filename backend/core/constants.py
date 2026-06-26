"""
==========================================================
CyberScan Enterprise
Core Constants Module
----------------------------------------------------------
Author  : Graduation Project Team
Purpose : Global constants used across the scanning engine.
Version : 1.0
==========================================================
"""

from pathlib import Path

# ==========================================================
# Project Information
# ==========================================================

PROJECT_NAME = "CyberScan Enterprise"

PROJECT_VERSION = "1.0.0"

PROJECT_AUTHOR = "Graduation Project Team"

DEFAULT_ENCODING = "utf-8"

# ==========================================================
# Network Configuration
# ==========================================================

DEFAULT_TIMEOUT = 10          # seconds

CONNECT_TIMEOUT = 5

READ_TIMEOUT = 10

ALLOW_REDIRECTS = True

MAX_REDIRECTS = 10

VERIFY_SSL = True

RETRY_COUNT = 2

RETRY_DELAY = 1

DEFAULT_SCHEME = "https"

# ==========================================================
# HTTP Configuration
# ==========================================================

DEFAULT_USER_AGENT = (
    "CyberScan Enterprise Scanner/1.0 "
    "(Security Assessment Tool)"
)

DEFAULT_HEADERS = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "close",
}

# ==========================================================
# Scan Configuration
# ==========================================================

DEFAULT_CONFIDENCE = "Medium"

DEFAULT_SEVERITY = "Info"

DEFAULT_THREADS = 10

DEFAULT_DELAY = 0

MAX_SCAN_TIME = 300

MAX_RESPONSE_SIZE = 20 * 1024 * 1024

MAX_DOWNLOAD_SIZE = 50 * 1024 * 1024

# ==========================================================
# Logging
# ==========================================================

LOG_LEVEL = "INFO"

LOG_FORMAT = (
    "%(asctime)s | %(levelname)s | "
    "%(name)s | %(message)s"
)

LOG_DIRECTORY = Path("logs")

LOG_FILE = LOG_DIRECTORY / "cyberscan.log"

# ==========================================================
# Reports
# ==========================================================

REPORT_LANGUAGE = "en"

REPORT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

REPORT_DIRECTORY = Path("reports")

SCREENSHOT_DIRECTORY = REPORT_DIRECTORY / "screenshots"

# ==========================================================
# AI
# ==========================================================

ENABLE_AI_ANALYSIS = True

AI_MODEL_NAME = "gpt"

# ==========================================================
# Cache
# ==========================================================

ENABLE_CACHE = False

CACHE_DIRECTORY = Path("cache")

# ==========================================================
# Future Features
# ==========================================================

ENABLE_PROXY = False

PROXY_URL = None

ENABLE_SCREENSHOTS = False

ENABLE_CRAWLER = False

ENABLE_ASYNC = False

ENABLE_HEADLESS_BROWSER = False

ENABLE_API_DISCOVERY = False

ENABLE_SUBDOMAIN_DISCOVERY = False

ENABLE_WAF_DETECTION = False

ENABLE_TECHNOLOGY_DETECTION = False

# ==========================================================
# Database
# ==========================================================

DATABASE_NAME = "cyberscan.sqlite3"

# ==========================================================
# Misc
# ==========================================================

UNKNOWN = "Unknown"

NOT_AVAILABLE = "N/A"

SUCCESS = "Success"

FAILED = "Failed"