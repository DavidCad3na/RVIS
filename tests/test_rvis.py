"""
tests/test_rvis.py – Unit tests for RVIS.

Run from the project root:
    pytest tests/ -v
"""

from __future__ import annotations

import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# ── Stub unavailable deps before any rvis import ──────────────────────────────
def _stub_nmap():
    nmap_mod = types.ModuleType("nmap")
    class PortScanner: pass
    class PortScannerError(Exception): pass
    nmap_mod.PortScanner = PortScanner
    nmap_mod.PortScannerError = PortScannerError
    sys.modules["nmap"] = nmap_mod

def _stub_rich():
    for mod_name in ["rich","rich.console","rich.panel","rich.table","rich.text","rich.box"]:
        sys.modules.setdefault(mod_name, types.ModuleType(mod_name))
    sys.modules["rich.console"].Console = lambda: type("C",(),{"print":lambda *a,**k:None})()
    sys.modules["rich.panel"].Panel      = object
    sys.modules["rich.table"].Table      = object
    sys.modules["rich.text"].Text        = str
    sys.modules["rich.box"].SIMPLE_HEAVY = None
    sys.modules["rich.box"].MINIMAL      = None

_stub_nmap()
_stub_rich()

from rvis.core.utils       import validate_target, validate_ports, cvss_to_severity, severity_color
from rvis.core.risk_engine import RiskEngine
from rvis.reporting.report import JSONReporter


# ─────────────────────────────────────────────────────────────────────────────
# utils
# ─────────────────────────────────────────────────────────────────────────────

class TestValidateTarget(unittest.TestCase):
    def test_valid_ipv4(self):    self.assertTrue(validate_target("192.168.1.1"))
    def test_valid_cidr(self):    self.assertTrue(validate_target("10.0.0.0/24"))
    def test_valid_hostname(self):self.assertTrue(validate_target("scanme.nmap.org"))
    def test_invalid_target(self):self.assertFalse(validate_target("not_a_host!!!"))
    def test_loopback(self):      self.assertTrue(validate_target("127.0.0.1"))


class TestValidatePorts(unittest.TestCase):
    def test_single_port(self):    self.assertTrue(validate_ports("80"))
    def test_range(self):          self.assertTrue(validate_ports("1-65535"))
    def test_csv(self):            self.assertTrue(validate_ports("22,80,443"))
    def test_mixed(self):          self.assertTrue(validate_ports("22,80-100,443"))
    def test_invalid_letters(self):self.assertFalse(validate_ports("http"))
    def test_invalid_negative(self):self.assertFalse(validate_ports("-1"))


class TestCvssHelpers(unittest.TestCase):
    def test_critical(self):          self.assertEqual(cvss_to_severity(9.5),  "CRITICAL")
    def test_high(self):              self.assertEqual(cvss_to_severity(7.8),  "HIGH")
    def test_medium(self):            self.assertEqual(cvss_to_severity(5.0),  "MEDIUM")
    def test_low(self):               self.assertEqual(cvss_to_severity(2.0),  "LOW")
    def test_none(self):              self.assertEqual(cvss_to_severity(0.0),  "NONE")
    def test_boundary_critical(self): self.assertEqual(cvss_to_severity(9.0),  "CRITICAL")
    def test_boundary_high(self):     self.assertEqual(cvss_to_severity(7.0),  "HIGH")


class TestSeverityColor(unittest.TestCase):
    def test_critical(self): self.assertEqual(severity_color("CRITICAL"), "bold red")
    def test_unknown(self):  self.assertEqual(severity_color("WHATEVER"), "white")


# ─────────────────────────────────────────────────────────────────────────────
# risk_engine
# ─────────────────────────────────────────────────────────────────────────────

def _make_host(ip="1.2.3.4", ports=None) -> dict:
    return {"ip":ip,"hostname":ip,"status":"up","os":"Linux","ports":ports or []}

def _make_port(port=80, service="http") -> dict:
    return {"port":port,"protocol":"tcp","state":"open","service":service,
            "product":"","version":"","extra":"","cpe":[]}

def _make_cve(score=7.5) -> dict:
    return {"cve_id":"CVE-2024-9999","description":"Test CVE","cvss_score":score,
            "cvss_vector":"","cvss_version":"3.1","severity":cvss_to_severity(score),
            "published":"2024-01-01","modified":"2024-01-02","references":[]}


class TestRiskEngine(unittest.TestCase):
    def setUp(self): self.engine = RiskEngine()

    def test_no_hosts(self):
        self.assertEqual(self.engine.score({"target":"x","scan_time":"t","hosts":[]},{})["hosts"],[])

    def test_port_with_no_cves_gets_minimal_score(self):
        result = {"target":"x","scan_time":"t","hosts":[_make_host(ports=[_make_port(80,"http")])]}
        p = self.engine.score(result,{})["hosts"][0]["ports"][0]
        self.assertAlmostEqual(p["risk_score"], 1.05, places=1)

    def test_port_with_cve_scores_higher(self):
        result  = {"target":"x","scan_time":"t","hosts":[_make_host(ports=[_make_port(22,"ssh")])]}
        scored  = self.engine.score(result, {"1.2.3.4:22":[_make_cve(9.8)]})
        self.assertGreaterEqual(scored["hosts"][0]["ports"][0]["risk_score"], 9.0)

    def test_risky_service_multiplier_telnet(self):
        result  = {"target":"x","scan_time":"t","hosts":[_make_host(ports=[_make_port(23,"telnet")])]}
        scored  = self.engine.score(result, {"1.2.3.4:23":[_make_cve(5.0)]})
        self.assertAlmostEqual(scored["hosts"][0]["ports"][0]["risk_score"], 6.5, places=1)

    def test_score_capped_at_10(self):
        result  = {"target":"x","scan_time":"t","hosts":[_make_host(ports=[_make_port(445,"microsoft-ds")])]}
        scored  = self.engine.score(result, {"1.2.3.4:445":[_make_cve(10.0)]})
        self.assertLessEqual(scored["hosts"][0]["ports"][0]["risk_score"], 10.0)

    def test_host_risk_score_present(self):
        result = {"target":"x","scan_time":"t","hosts":[_make_host(ports=[_make_port(80,"http")])]}
        self.assertIn("host_risk_score", self.engine.score(result,{})["hosts"][0])

    def test_severity_label_attached(self):
        result  = {"target":"x","scan_time":"t","hosts":[_make_host(ports=[_make_port(80,"http")])]}
        scored  = self.engine.score(result, {"1.2.3.4:80":[_make_cve(9.9)]})
        self.assertEqual(scored["hosts"][0]["ports"][0]["risk_severity"], "CRITICAL")


# ─────────────────────────────────────────────────────────────────────────────
# JSONReporter
# ─────────────────────────────────────────────────────────────────────────────

class TestJSONReporter(unittest.TestCase):
    def setUp(self):
        self.reporter = JSONReporter()
        self.tmp = Path("/tmp/rvis_test_report.json")

    def tearDown(self):
        if self.tmp.exists(): self.tmp.unlink()

    def _sample(self) -> dict:
        port = _make_port(80,"http")
        port.update({"risk_score":5.0,"risk_severity":"MEDIUM","cves":[]})
        host = _make_host(ports=[port])
        host.update({"host_risk_score":5.0,"host_risk_severity":"MEDIUM"})
        return {"target":"1.2.3.4","scan_time":"2024-01-01T00:00:00Z","hosts":[host]}

    def test_file_created(self):
        self.reporter.save(self._sample(), str(self.tmp))
        self.assertTrue(self.tmp.exists())

    def test_json_valid(self):
        self.reporter.save(self._sample(), str(self.tmp))
        data = json.loads(self.tmp.read_text())
        self.assertIn("rvis_version", data)
        self.assertIn("scan", data)

    def test_json_has_hosts(self):
        self.reporter.save(self._sample(), str(self.tmp))
        self.assertEqual(len(json.loads(self.tmp.read_text())["scan"]["hosts"]), 1)

    def test_returns_path(self):
        self.assertIsInstance(self.reporter.save(self._sample(), str(self.tmp)), Path)


# ─────────────────────────────────────────────────────────────────────────────
# Scanner (mocked nmap)
# ─────────────────────────────────────────────────────────────────────────────

class TestRVISScanner(unittest.TestCase):
    def _build_mock_nm(self):
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["10.0.0.1"]
        host_mock = MagicMock()
        host_mock.state.return_value = "up"
        host_mock.__getitem__.side_effect = lambda proto: {
            "tcp": {80: {"state":"open","name":"http","product":"Apache httpd",
                         "version":"2.4.49","extrainfo":"",
                         "cpe":"cpe:/a:apache:http_server:2.4.49"}}
        }[proto]
        host_mock.all_protocols.return_value = ["tcp"]
        host_mock.get.return_value = [{"name":"router.local"}]
        mock_nm.__getitem__ = MagicMock(return_value=host_mock)
        mock_nm.scan.return_value = {}
        return mock_nm

    @patch("rvis.core.scanner.nmap.PortScanner")
    def test_scan_returns_result(self, mock_cls):
        mock_cls.return_value = self._build_mock_nm()
        from rvis.core.scanner import RVISScanner
        result = RVISScanner(ports="80").scan("10.0.0.1")
        self.assertEqual(result.target, "10.0.0.1")
        self.assertEqual(result.hosts[0]["ports"][0]["service"], "http")


# ─────────────────────────────────────────────────────────────────────────────
# CVELookup (mocked HTTP)
# ─────────────────────────────────────────────────────────────────────────────

class TestCVELookup(unittest.TestCase):
    NVD_RESPONSE = {"vulnerabilities":[{"cve":{
        "id":"CVE-2021-41773",
        "descriptions":[{"lang":"en","value":"Path traversal in Apache 2.4.49"}],
        "published":"2021-10-05T00:00:00","lastModified":"2021-10-10T00:00:00",
        "references":[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2021-41773"}],
        "metrics":{"cvssMetricV31":[{"cvssData":{
            "baseScore":7.5,
            "vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        }}]},
    }}]}

    @patch("rvis.lookup.cve_lookup.time.sleep", return_value=None)
    @patch("rvis.lookup.cve_lookup.requests.Session")
    def test_lookup_returns_cve(self, mock_session_cls, _sleep):
        mock_resp = MagicMock()
        mock_resp.json.return_value = self.NVD_RESPONSE
        mock_resp.raise_for_status.return_value = None
        mock_session = MagicMock()
        mock_session.get.return_value = mock_resp
        mock_session.headers = {}
        mock_session_cls.return_value = mock_session
        from rvis.lookup.cve_lookup import CVELookup
        results = CVELookup().lookup_by_keyword("Apache httpd 2.4.49")
        self.assertEqual(results[0]["cve_id"], "CVE-2021-41773")
        self.assertAlmostEqual(results[0]["cvss_score"], 7.5)

    @patch("rvis.lookup.cve_lookup.time.sleep", return_value=None)
    @patch("rvis.lookup.cve_lookup.requests.Session")
    def test_empty_keyword_returns_empty(self, mock_session_cls, _sleep):
        from rvis.lookup.cve_lookup import CVELookup
        self.assertEqual(CVELookup().lookup_by_keyword(""), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
