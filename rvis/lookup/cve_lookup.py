"""
cve_lookup.py – Query the NIST NVD API v2 for CVEs matching a service/product.

API docs: https://nvd.nist.gov/developers/vulnerabilities
Rate limit: 5 req/30 s unauthenticated, 50 req/30 s with API key.
"""

from __future__ import annotations

import time
import requests
from typing import Any, Optional
from rvis.core.utils import get_logger, cvss_to_severity

logger = get_logger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_REQUEST_DELAY = 0.6   # seconds between calls (conservative)


# ─────────────────────────────────────────────────────────────────────────────

class CVELookup:
    """
    Fetches CVE records from the NVD REST API v2.

    Parameters
    ----------
    api_key : str, optional
        NVD API key for higher rate limits.
    max_results : int
        Maximum CVEs to retrieve per query (NVD caps at 2000).
    """

    def __init__(self, api_key: Optional[str] = None, max_results: int = 10) -> None:
        self.api_key = api_key
        self.max_results = max_results
        self._session = requests.Session()
        if api_key:
            self._session.headers["apiKey"] = api_key

    # ── public ────────────────────────────────────────────────────────────────

    def lookup_by_keyword(self, keyword: str) -> list[dict[str, Any]]:
        """
        Search NVD for CVEs matching *keyword* (product name / version string).

        Returns a list of simplified CVE dicts.
        """
        if not keyword or keyword.lower() in {"unknown", ""}:
            return []

        logger.debug("NVD lookup | keyword=%r", keyword)
        time.sleep(_REQUEST_DELAY)   # be polite to the API

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(self.max_results, 2000),
        }

        try:
            resp = self._session.get(NVD_BASE, params=params, timeout=15)
            resp.raise_for_status()
        except requests.RequestException as exc:
            logger.warning("NVD request failed: %s", exc)
            return []

        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])
        return [self._parse_cve(v) for v in vulnerabilities]

    def lookup_by_cpe(self, cpe: str) -> list[dict[str, Any]]:
        """
        Search NVD for CVEs matching a CPE 2.3 URI.
        """
        if not cpe:
            return []

        logger.debug("NVD lookup | cpe=%r", cpe)
        time.sleep(_REQUEST_DELAY)

        params = {
            "cpeName":        cpe,
            "resultsPerPage": min(self.max_results, 2000),
        }

        try:
            resp = self._session.get(NVD_BASE, params=params, timeout=15)
            resp.raise_for_status()
        except requests.RequestException as exc:
            logger.warning("NVD CPE request failed: %s", exc)
            return []

        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])
        return [self._parse_cve(v) for v in vulnerabilities]

    # ── private ───────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_cve(vuln_item: dict) -> dict[str, Any]:
        """Flatten a raw NVD vulnerability item into a concise dict."""
        cve = vuln_item.get("cve", {})
        cve_id = cve.get("id", "N/A")

        # Description (English preferred)
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available.",
        )

        # CVSS v3.1 → v3.0 → v2 fallback
        metrics = cve.get("metrics", {})
        cvss_score, cvss_vector, cvss_version = CVELookup._extract_cvss(metrics)

        severity = cvss_to_severity(cvss_score)

        # References
        refs = [r["url"] for r in cve.get("references", [])[:3]]

        # Published / modified dates
        published = cve.get("published", "")
        modified  = cve.get("lastModified", "")

        return {
            "cve_id":       cve_id,
            "description":  description[:500],   # keep reports readable
            "cvss_score":   cvss_score,
            "cvss_vector":  cvss_vector,
            "cvss_version": cvss_version,
            "severity":     severity,
            "published":    published,
            "modified":     modified,
            "references":   refs,
        }

    @staticmethod
    def _extract_cvss(metrics: dict) -> tuple[float, str, str]:
        """Return (score, vector, version) trying v3.1 → v3.0 → v2."""
        for key, ver in [
            ("cvssMetricV31", "3.1"),
            ("cvssMetricV30", "3.0"),
            ("cvssMetricV2",  "2.0"),
        ]:
            entries = metrics.get(key, [])
            if not entries:
                continue
            data = entries[0].get("cvssData", {})
            score  = float(data.get("baseScore", 0.0))
            vector = data.get("vectorString", "")
            return score, vector, ver

        return 0.0, "", "N/A"
