"""
utils.py - Shared utility functions for RVIS
"""

import re
import socket
import ipaddress
import logging
from datetime import datetime
from typing import Optional

# ── Logging ──────────────────────────────────────────────────────────────────

def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """Return a consistently formatted logger."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        fmt = logging.Formatter(
            "[%(asctime)s] %(levelname)-8s %(name)s – %(message)s",
            datefmt="%H:%M:%S",
        )
        handler.setFormatter(fmt)
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger


# ── Validation ────────────────────────────────────────────────────────────────

def validate_target(target: str) -> bool:
    """
    Accept IPv4, IPv6, CIDR ranges, and hostnames.
    Returns True when the target looks syntactically valid.
    """
    # Try plain IP / CIDR
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass

    # Try hostname (very permissive – nmap will reject bad ones anyway)
    hostname_re = re.compile(
        r"^(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )
    if hostname_re.match(target):
        return True

    # Fallback: try resolving
    try:
        socket.getaddrinfo(target, None)
        return True
    except socket.gaierror:
        return False


def validate_ports(ports: str) -> bool:
    """
    Accept port specs understood by nmap:
      22, 80, 1-1024, 22,80,443, 1-65535
    """
    port_re = re.compile(r"^(\d+(-\d+)?)(,\d+(-\d+)?)*$")
    return bool(port_re.match(ports))


# ── Timestamp / helpers ───────────────────────────────────────────────────────

def timestamp() -> str:
    """ISO-8601 timestamp string for the current UTC moment."""
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def severity_color(severity: str) -> str:
    """Map CVSS severity label to an ANSI-style rich color tag."""
    return {
        "CRITICAL": "bold red",
        "HIGH":     "red",
        "MEDIUM":   "yellow",
        "LOW":      "green",
        "NONE":     "white",
    }.get(severity.upper(), "white")


def cvss_to_severity(score: float) -> str:
    """Map a numeric CVSS v3 base score to its severity label."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    return "NONE"
