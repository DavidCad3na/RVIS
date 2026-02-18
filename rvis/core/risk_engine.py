"""
risk_engine.py – Aggregate CVE data into per-port and per-host risk scores.

Risk scoring philosophy
-----------------------
* Base score is the highest individual CVSS score for a port's CVEs.
* An "exposure multiplier" adjusts for well-known dangerous services
  (e.g. Telnet, RDP, SMB) that are inherently riskier when publicly exposed.
* Host risk score = weighted average of port scores (highest-scoring ports
  count more).
"""

from __future__ import annotations

from typing import Any
from rvis.core.utils import get_logger, cvss_to_severity

logger = get_logger(__name__)

# ── Exposure weights for high-risk service names ──────────────────────────────
RISKY_SERVICES: dict[str, float] = {
    "telnet":   1.30,
    "ftp":      1.20,
    "rpcbind":  1.15,
    "ms-wbt-server": 1.25,   # RDP
    "microsoft-ds":  1.25,   # SMB (445)
    "netbios-ssn":   1.20,   # SMB (139)
    "vnc":      1.20,
    "smtp":     1.10,
    "snmp":     1.15,
    "tftp":     1.15,
    "finger":   1.10,
    "http":     1.05,
    "https":    1.05,
}

MAX_CVSS = 10.0


# ─────────────────────────────────────────────────────────────────────────────

class RiskEngine:
    """
    Calculates risk scores from scan results enriched with CVE data.

    Usage
    -----
    ::

        engine = RiskEngine()
        scored = engine.score(scan_result_dict, cve_map)
    """

    def score(
        self,
        scan_result: dict[str, Any],
        cve_map: dict[str, list[dict]],
    ) -> dict[str, Any]:
        """
        Attach risk scores to *scan_result* in-place and return it.

        Parameters
        ----------
        scan_result : dict
            Output of ``ScanResult.to_dict()``.
        cve_map : dict
            Mapping ``"<ip>:<port>"`` → list of CVE dicts from
            :class:`~cve_lookup.CVELookup`.
        """
        for host in scan_result.get("hosts", []):
            self._score_host(host, cve_map)

        return scan_result

    # ── private ───────────────────────────────────────────────────────────────

    def _score_host(
        self,
        host: dict[str, Any],
        cve_map: dict[str, list[dict]],
    ) -> None:
        port_scores: list[float] = []

        for port_info in host.get("ports", []):
            key = f"{host['ip']}:{port_info['port']}"
            cves = cve_map.get(key, [])

            port_score = self._score_port(port_info, cves)
            port_info["risk_score"] = round(port_score, 2)
            port_info["risk_severity"] = cvss_to_severity(port_score)
            port_info["cves"] = cves

            port_scores.append(port_score)

        if port_scores:
            host["host_risk_score"] = round(self._aggregate(port_scores), 2)
        else:
            host["host_risk_score"] = 0.0

        host["host_risk_severity"] = cvss_to_severity(host["host_risk_score"])

    def _score_port(
        self,
        port_info: dict[str, Any],
        cves: list[dict],
    ) -> float:
        """
        Compute a risk score (0-10) for a single port.

        Algorithm
        ---------
        1. Base = max CVSS score from associated CVEs (0 if none).
        2. If no CVEs but port is open, assign a minimal exposure score (1.0).
        3. Multiply by service exposure weight.
        4. Clamp to [0, 10].
        """
        if cves:
            base = max((c.get("cvss_score", 0.0) for c in cves), default=0.0)
        else:
            base = 1.0  # minimal exposure for any open port

        service = port_info.get("service", "").lower()
        multiplier = RISKY_SERVICES.get(service, 1.0)

        raw = base * multiplier
        return min(raw, MAX_CVSS)

    @staticmethod
    def _aggregate(scores: list[float]) -> float:
        """
        Weighted average: highest score has weight=2, others weight=1.
        Produces a value that skews toward the worst port without simply
        taking the maximum.
        """
        if not scores:
            return 0.0
        sorted_scores = sorted(scores, reverse=True)
        weights = [2.0] + [1.0] * (len(sorted_scores) - 1)
        weighted_sum = sum(s * w for s, w in zip(sorted_scores, weights))
        total_weight = sum(weights)
        return weighted_sum / total_weight
