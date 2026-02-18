# RVIS Architecture

## Package layout

```
RVIS/
├── main.py                   CLI entry point & pipeline orchestrator
│
├── rvis/                     Main Python package
│   ├── __init__.py
│   ├── core/                 Scanning & analysis
│   │   ├── scanner.py        python-nmap wrapper → ScanResult
│   │   ├── risk_engine.py    CVSS-based port/host risk scorer
│   │   └── utils.py          Validation, logging, severity helpers
│   ├── lookup/               Threat intelligence
│   │   └── cve_lookup.py     NIST NVD API v2 client
│   └── reporting/            Output
│       └── report.py         Rich terminal tables + JSON export
│
├── config/
│   └── settings.py           All tuneable defaults (env-var aware)
│
├── tests/
│   └── test_rvis.py          34 unit tests (nmap/HTTP fully mocked)
│
├── reports/                  Default output directory for JSON reports
├── docs/                     Documentation
│   └── ARCHITECTURE.md       This file
│
├── .github/
│   └── workflows/
│       └── rvis-ci.yml       lint → test → build → docker pipeline
│
├── Dockerfile                Container image (nmap pre-installed)
├── requirements.txt
└── README.md
```

## Data flow

```
CLI args (main.py)
       │
       ▼
  RVISScanner                 nmap -sV -p 1-65535 <target>
  (core/scanner.py)
       │  ScanResult
       ▼
  CVELookup                   NVD API v2  (per open port)
  (lookup/cve_lookup.py)
       │  cve_map
       ▼
  RiskEngine                  score = max_cvss × service_weight
  (core/risk_engine.py)       host_score = weighted_avg(port_scores)
       │  scored_result dict
       ▼
  TerminalReporter  ──►  Rich colour tables (stdout)
  JSONReporter      ──►  reports/<filename>.json
```

## Adding a new module

1. Create `rvis/<category>/my_module.py`
2. Export from `rvis/<category>/__init__.py`
3. Import and call in `main.py`
4. Add tests in `tests/test_rvis.py`
