"""
config/settings.py – Central configuration for RVIS.

All tuneable defaults live here. Override via environment variables or
by editing this file directly.
"""

import os

# ── Scanner defaults ──────────────────────────────────────────────────────────
DEFAULT_PORTS   = os.getenv("RVIS_PORTS",   "1-65535")
DEFAULT_TIMING  = int(os.getenv("RVIS_TIMING", "4"))     # nmap -T template
DEFAULT_UDP     = os.getenv("RVIS_UDP",     "false").lower() == "true"
DEFAULT_OS_DET  = os.getenv("RVIS_OS_DET",  "false").lower() == "true"

# ── CVE / NVD ─────────────────────────────────────────────────────────────────
NVD_API_KEY     = os.getenv("NVD_API_KEY",  None)        # set for 10× rate limit
NVD_MAX_RESULTS = int(os.getenv("NVD_MAX_RESULTS", "10"))
NVD_REQUEST_DELAY = float(os.getenv("NVD_REQUEST_DELAY", "0.6"))  # seconds

# ── Output ────────────────────────────────────────────────────────────────────
REPORTS_DIR     = os.getenv("RVIS_REPORTS_DIR", "reports")
JSON_INDENT     = int(os.getenv("RVIS_JSON_INDENT", "2"))

# ── Risk engine ───────────────────────────────────────────────────────────────
# Exposure weight multipliers for high-risk services
SERVICE_WEIGHTS: dict[str, float] = {
    "telnet":        1.30,
    "ftp":           1.20,
    "rpcbind":       1.15,
    "ms-wbt-server": 1.25,   # RDP
    "microsoft-ds":  1.25,   # SMB 445
    "netbios-ssn":   1.20,   # SMB 139
    "vnc":           1.20,
    "smtp":          1.10,
    "snmp":          1.15,
    "tftp":          1.15,
    "finger":        1.10,
    "http":          1.05,
    "https":         1.05,
}
