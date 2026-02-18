#!/usr/bin/env python3
"""
main.py – RVIS entry point.

Usage examples
--------------
# Full port scan (default: all 65535 ports)
python main.py -t 192.168.1.1

# Custom ports + save report to reports/ folder
python main.py -t scanme.nmap.org -p 22,80,443,8080 -o reports/scan.json

# Subnet scan with NVD API key
python main.py -t 10.0.0.0/24 --api-key <YOUR_NVD_KEY>

# Quiet mode – JSON only, no terminal output
python main.py -t 10.0.0.5 --quiet -o reports/result.json
"""

from __future__ import annotations

import argparse
import sys

from rvis.core import (
    RVISScanner, RiskEngine, get_logger, validate_target, validate_ports,
)
from rvis.lookup import CVELookup
from rvis.reporting import TerminalReporter, JSONReporter

logger = get_logger("rvis.main")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rvis",
        description=(
            "RVIS – Recon Vulnerability Identification System\n"
            "Ethical hacking / CTF vulnerability scanner"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py -t 192.168.1.1\n"
            "  python main.py -t scanme.nmap.org -p 22,80,443 -o reports/scan.json\n"
            "  python main.py -t 10.0.0.0/24 --os --timing 3\n"
        ),
    )

    # Target
    parser.add_argument(
        "-t", "--target",
        required=True,
        metavar="HOST/CIDR",
        help="Target IP, hostname, or CIDR range",
    )

    # Ports
    parser.add_argument(
        "-p", "--ports",
        default="1-65535",
        metavar="PORTS",
        help='Ports to scan (default: all "1-65535")',
    )

    # Scan options
    parser.add_argument(
        "--timing", type=int, default=4, choices=range(0, 6), metavar="0-5",
        help="Nmap timing template (default: 4)",
    )
    parser.add_argument(
        "--udp", action="store_true",
        help="Include UDP scan (requires root)",
    )
    parser.add_argument(
        "--os", dest="os_detection", action="store_true",
        help="Enable OS detection (requires root)",
    )

    # CVE options
    parser.add_argument(
        "--api-key", metavar="KEY", default=None,
        help="NVD API key for higher rate limits",
    )
    parser.add_argument(
        "--max-cves", type=int, default=10, metavar="N",
        help="Max CVEs per service (default: 10)",
    )
    parser.add_argument(
        "--no-cve", action="store_true",
        help="Skip CVE lookup",
    )

    # Output
    parser.add_argument(
        "-o", "--output", metavar="FILE.json", default=None,
        help="Save JSON report (e.g. reports/scan.json)",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress terminal output",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable debug logging",
    )

    return parser


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline
# ─────────────────────────────────────────────────────────────────────────────

def run(args: argparse.Namespace) -> int:
    import logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # 1. Validate
    if not validate_target(args.target):
        logger.error("Invalid target: %r", args.target)
        return 1
    if not validate_ports(args.ports):
        logger.error("Invalid port spec: %r", args.ports)
        return 1

    # 2. Scan
    scanner = RVISScanner(
        ports=args.ports,
        timing=args.timing,
        udp=args.udp,
        os_detection=args.os_detection,
    )
    try:
        scan_result = scanner.scan(args.target)
    except Exception as exc:
        logger.error("Scan failed: %s", exc)
        return 1

    result_dict = scan_result.to_dict()

    # 3. CVE lookup
    cve_map: dict = {}
    if not args.no_cve:
        lookup = CVELookup(api_key=args.api_key, max_results=args.max_cves)
        for host in result_dict.get("hosts", []):
            for port_info in host.get("ports", []):
                key = f"{host['ip']}:{port_info['port']}"
                keyword = port_info.get("product") or port_info.get("service", "")
                version = port_info.get("version", "")
                if version:
                    keyword = f"{keyword} {version}".strip()

                cves: list = []
                for cpe in port_info.get("cpe", []):
                    cves = lookup.lookup_by_cpe(cpe)
                    if cves:
                        break
                if not cves and keyword:
                    cves = lookup.lookup_by_keyword(keyword)

                cve_map[key] = cves

    # 4. Risk score
    RiskEngine().score(result_dict, cve_map)

    # 5. Report
    if not args.quiet:
        TerminalReporter().render(result_dict)

    if args.output:
        saved = JSONReporter().save(result_dict, args.output)
        if not args.quiet:
            print(f"\n[+] JSON report saved → {saved}")

    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(run(args))


if __name__ == "__main__":
    main()
