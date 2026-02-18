# RVIS – Recon Vulnerability Identification System

```
██████╗ ██╗   ██╗██╗███████╗
██╔══██╗██║   ██║██║██╔════╝
██████╔╝██║   ██║██║███████╗
██╔══██╗╚██╗ ██╔╝██║╚════██║
██║  ██║ ╚████╔╝ ██║███████║
╚═╝  ╚═╝  ╚═══╝  ╚═╝╚══════╝
```

> **Ethical-use only.** Only scan systems you own or have explicit written permission to test.

---

## Project Structure

```
RVIS/
├── main.py                   Entry point (argparse CLI)
│
├── rvis/                     Core package
│   ├── core/
│   │   ├── scanner.py        Nmap scanning (all 65535 ports by default)
│   │   ├── risk_engine.py    CVSS-based risk scorer
│   │   └── utils.py          Shared helpers
│   ├── lookup/
│   │   └── cve_lookup.py     NIST NVD API v2 client
│   └── reporting/
│       └── report.py         Terminal (Rich) + JSON reports
│
├── config/
│   └── settings.py           Centralised defaults (env-var aware)
│
├── tests/
│   └── test_rvis.py          34 unit tests (fully mocked)
│
├── reports/                  JSON report output directory
├── docs/
│   └── ARCHITECTURE.md       Data flow & extension guide
│
├── .github/workflows/
│   └── rvis-ci.yml           CI/CD (lint → test → build → docker)
├── Dockerfile
└── requirements.txt
```

---

## Setup

### Requirements

| Tool | Install |
|---|---|
| Python 3.10+ | https://python.org |
| nmap | `sudo apt install nmap` / `brew install nmap` |

### Install

```bash
git clone https://github.com/<you>/rvis.git
cd rvis
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Optional: NVD API key

Register at <https://nvd.nist.gov/developers/request-an-api-key> for 10× rate limits,
then either pass `--api-key <KEY>` or set `NVD_API_KEY=<KEY>` in your environment.

---

## Usage

```bash
# Full scan – all 65535 ports (default)
python main.py -t 192.168.1.1

# Save report to reports/
python main.py -t scanme.nmap.org -o reports/scan.json

# Specific ports, with API key
python main.py -t 10.0.0.5 -p 22,80,443 --api-key $NVD_API_KEY -o reports/out.json

# Subnet, skip CVE lookup (fast recon)
python main.py -t 10.0.0.0/24 --no-cve

# Quiet – JSON only
python main.py -t 10.0.0.1 --quiet -o reports/result.json
```

### Docker

```bash
docker build -t rvis .
docker run --rm --cap-add=NET_ADMIN \
  -v $(pwd)/reports:/app/reports \
  rvis -t 192.168.1.1 -o reports/scan.json
```

---

## Configuration

All defaults live in `config/settings.py` and can be overridden with environment variables:

| Env var | Default | Description |
|---|---|---|
| `RVIS_PORTS` | `1-65535` | Port range |
| `RVIS_TIMING` | `4` | Nmap timing template |
| `NVD_API_KEY` | _(none)_ | NVD API key |
| `NVD_MAX_RESULTS` | `10` | CVEs per service |
| `RVIS_REPORTS_DIR` | `reports` | Output directory |

---

## Tests

```bash
pip install pytest pytest-cov
pytest tests/ -v --cov=rvis --cov-report=term-missing
```

No network or root access required — nmap and HTTP calls are fully mocked.

---

## CI/CD

`.github/workflows/rvis-ci.yml` runs four stages on every push/PR:

1. **lint** — flake8
2. **test** — pytest + coverage
3. **build** — ZIP artifact
4. **docker** — build & push (main branch only)

Required secrets: `DOCKER_USERNAME`, `DOCKER_PASSWORD`, optionally `NVD_API_KEY`.

---

## Disclaimer

For authorised penetration testing and CTF use only. Unauthorised scanning is illegal.
