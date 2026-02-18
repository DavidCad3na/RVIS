"""
scanner.py – Nmap-based port / service / version scanner for RVIS.

Requires nmap to be installed on the host OS:
  Debian/Ubuntu : sudo apt install nmap
  macOS         : brew install nmap
  Windows       : https://nmap.org/download.html
"""

from __future__ import annotations

import nmap
from typing import Any
from rvis.core.utils import get_logger, timestamp

logger = get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

class ScanResult:
    """Holds structured data returned by a single host scan."""

    def __init__(self, target: str):
        self.target: str = target
        self.scan_time: str = timestamp()
        self.hosts: list[dict[str, Any]] = []
        self.raw: dict = {}

    def to_dict(self) -> dict:
        return {
            "target":    self.target,
            "scan_time": self.scan_time,
            "hosts":     self.hosts,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────────────────────────────────────

class RVISScanner:
    """
    Wraps python-nmap to perform service/version detection.

    Parameters
    ----------
    ports : str
        nmap port spec, e.g. ``"1-1024"`` or ``"22,80,443"``.
    timing : int
        nmap timing template 0-5 (default 4 = aggressive).
    udp : bool
        Also run UDP scan (requires root/admin).
    os_detection : bool
        Attempt OS detection (requires root/admin).
    """

    DEFAULT_ARGS = "-sV --version-intensity 5"

    def __init__(
        self,
        ports: str = "1-65535",
        timing: int = 4,
        udp: bool = False,
        os_detection: bool = False,
    ) -> None:
        self.ports = ports
        self.timing = timing
        self.udp = udp
        self.os_detection = os_detection
        self._nm = nmap.PortScanner()

    # ── public ────────────────────────────────────────────────────────────────

    def scan(self, target: str) -> ScanResult:
        """
        Scan *target* and return a :class:`ScanResult`.

        Parameters
        ----------
        target : str
            IPv4/IPv6 address, hostname, or CIDR range.
        """
        args = self._build_args()
        logger.info("Starting scan | target=%s ports=%s args=%s", target, self.ports, args)

        try:
            raw = self._nm.scan(hosts=target, ports=self.ports, arguments=args)
        except nmap.PortScannerError as exc:
            logger.error("nmap error: %s", exc)
            raise

        result = ScanResult(target)
        result.raw = raw

        for host_ip in self._nm.all_hosts():
            host_data = self._parse_host(host_ip)
            result.hosts.append(host_data)
            logger.debug("Parsed host %s → %d open port(s)", host_ip, len(host_data["ports"]))

        logger.info("Scan complete | hosts_up=%d", len(result.hosts))
        return result

    # ── private ───────────────────────────────────────────────────────────────

    def _build_args(self) -> str:
        args = self.DEFAULT_ARGS
        args += f" -T{self.timing}"
        if self.udp:
            args += " -sU"
        if self.os_detection:
            args += " -O"
        return args

    def _parse_host(self, host_ip: str) -> dict[str, Any]:
        """Extract clean data from nmap's host object."""
        nm_host = self._nm[host_ip]

        # Hostname
        hostnames = nm_host.get("hostnames", [])
        hostname = hostnames[0]["name"] if hostnames else host_ip

        # OS guess
        os_guess = "Unknown"
        os_matches = nm_host.get("osmatch", [])
        if os_matches:
            os_guess = os_matches[0].get("name", "Unknown")

        # Ports
        ports = []
        for proto in nm_host.all_protocols():
            for port_num in sorted(nm_host[proto]):
                port_info = nm_host[proto][port_num]
                if port_info["state"] != "open":
                    continue
                ports.append(self._parse_port(proto, port_num, port_info))

        return {
            "ip":       host_ip,
            "hostname": hostname,
            "status":   nm_host.state(),
            "os":       os_guess,
            "ports":    ports,
        }

    @staticmethod
    def _parse_port(proto: str, port_num: int, info: dict) -> dict[str, Any]:
        """Flatten a single port's nmap data into a clean dict."""
        cpe_list = info.get("cpe", "")
        # nmap returns CPEs as a space-separated string
        cpes = [c.strip() for c in cpe_list.split() if c.strip()] if cpe_list else []

        return {
            "port":     port_num,
            "protocol": proto,
            "state":    info.get("state", "unknown"),
            "service":  info.get("name", "unknown"),
            "product":  info.get("product", ""),
            "version":  info.get("version", ""),
            "extra":    info.get("extrainfo", ""),
            "cpe":      cpes,
        }
