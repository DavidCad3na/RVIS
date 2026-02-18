"""
report.py – Terminal and JSON reporting for RVIS.

Terminal output uses the ``rich`` library for colour, tables, and panels.
JSON output is a flat, machine-readable summary of the scored scan.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from rvis.core.utils import get_logger, severity_color, timestamp

logger = get_logger(__name__)
console = Console()

BANNER = r"""
██████╗ ██╗   ██╗██╗███████╗
██╔══██╗██║   ██║██║██╔════╝
██████╔╝██║   ██║██║███████╗
██╔══██╗╚██╗ ██╔╝██║╚════██║
██║  ██║ ╚████╔╝ ██║███████║
╚═╝  ╚═╝  ╚═══╝  ╚═╝╚══════╝
 Recon Vulnerability Identification System
"""


# ─────────────────────────────────────────────────────────────────────────────
# Terminal report
# ─────────────────────────────────────────────────────────────────────────────

class TerminalReporter:
    """Render a full rich-formatted scan report to the terminal."""

    def render(self, scored_result: dict[str, Any]) -> None:
        self._print_banner()
        self._print_meta(scored_result)

        hosts = scored_result.get("hosts", [])
        if not hosts:
            console.print("[yellow]No live hosts found.[/yellow]")
            return

        for host in hosts:
            self._print_host(host)

        self._print_summary(hosts)

    # ── private ───────────────────────────────────────────────────────────────

    @staticmethod
    def _print_banner() -> None:
        console.print(Text(BANNER, style="bold cyan"))

    @staticmethod
    def _print_meta(result: dict) -> None:
        meta = (
            f"[bold]Target:[/bold] {result.get('target', 'N/A')}   "
            f"[bold]Scan time:[/bold] {result.get('scan_time', 'N/A')}"
        )
        console.print(Panel(meta, title="[bold blue]Scan Metadata[/bold blue]", expand=False))

    def _print_host(self, host: dict) -> None:
        host_risk = host.get("host_risk_score", 0.0)
        host_sev  = host.get("host_risk_severity", "NONE")
        color     = severity_color(host_sev)

        header = (
            f"[bold]{host['ip']}[/bold]  ({host.get('hostname', host['ip'])})\n"
            f"OS: {host.get('os', 'Unknown')}   "
            f"Host Risk: [{color}]{host_risk:.1f} / 10.0 ({host_sev})[/{color}]"
        )
        console.print(Panel(header, title=f"[bold green]Host[/bold green]", expand=False))

        ports = host.get("ports", [])
        if not ports:
            console.print("  [dim]No open ports.[/dim]\n")
            return

        self._print_ports_table(ports)
        self._print_cves_for_host(ports)

    @staticmethod
    def _print_ports_table(ports: list[dict]) -> None:
        table = Table(
            box=box.SIMPLE_HEAVY,
            show_lines=True,
            title="[bold]Open Ports[/bold]",
        )
        table.add_column("Port",     style="cyan",  no_wrap=True)
        table.add_column("Proto",    style="white")
        table.add_column("Service",  style="white")
        table.add_column("Product",  style="white")
        table.add_column("Version",  style="white")
        table.add_column("Risk",     no_wrap=True)
        table.add_column("CVEs",     justify="center")

        for p in ports:
            sev   = p.get("risk_severity", "NONE")
            color = severity_color(sev)
            score = p.get("risk_score", 0.0)
            cve_count = len(p.get("cves", []))

            table.add_row(
                str(p["port"]),
                p.get("protocol", ""),
                p.get("service", ""),
                p.get("product", ""),
                p.get("version", ""),
                Text(f"{score:.1f} {sev}", style=color),
                str(cve_count) if cve_count else "[dim]0[/dim]",
            )

        console.print(table)

    def _print_cves_for_host(self, ports: list[dict]) -> None:
        for port_info in ports:
            cves = port_info.get("cves", [])
            if not cves:
                continue

            console.print(
                f"\n  [bold]CVEs for port {port_info['port']} "
                f"({port_info.get('service', '')} {port_info.get('product', '')})[/bold]"
            )
            self._print_cve_table(cves)

    @staticmethod
    def _print_cve_table(cves: list[dict]) -> None:
        table = Table(box=box.MINIMAL, show_lines=True)
        table.add_column("CVE ID",     style="bold white", no_wrap=True)
        table.add_column("CVSS",       justify="center",   no_wrap=True)
        table.add_column("Severity",   no_wrap=True)
        table.add_column("Published",  no_wrap=True)
        table.add_column("Description")

        for cve in cves:
            sev   = cve.get("severity", "NONE")
            color = severity_color(sev)
            score = cve.get("cvss_score", 0.0)
            desc  = cve.get("description", "")[:100]
            if len(cve.get("description", "")) > 100:
                desc += "…"

            table.add_row(
                cve["cve_id"],
                Text(f"{score:.1f}", style=color),
                Text(sev, style=color),
                cve.get("published", "")[:10],
                desc,
            )

        console.print(table)

    @staticmethod
    def _print_summary(hosts: list[dict]) -> None:
        total_ports = sum(len(h.get("ports", [])) for h in hosts)
        total_cves  = sum(
            sum(len(p.get("cves", [])) for p in h.get("ports", []))
            for h in hosts
        )
        max_risk    = max((h.get("host_risk_score", 0.0) for h in hosts), default=0.0)

        summary = (
            f"Hosts scanned : [bold]{len(hosts)}[/bold]\n"
            f"Open ports    : [bold]{total_ports}[/bold]\n"
            f"Total CVEs    : [bold]{total_cves}[/bold]\n"
            f"Max host risk : [bold red]{max_risk:.1f} / 10.0[/bold red]"
        )
        console.print(Panel(summary, title="[bold blue]Summary[/bold blue]", expand=False))


# ─────────────────────────────────────────────────────────────────────────────
# JSON report
# ─────────────────────────────────────────────────────────────────────────────

class JSONReporter:
    """Save the full scored scan result as a JSON file."""

    def save(self, scored_result: dict[str, Any], output_path: str) -> Path:
        """
        Write *scored_result* to *output_path* as pretty-printed JSON.

        Returns the resolved :class:`Path` of the saved file.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        report = {
            "rvis_version": "1.0.0",
            "generated_at": timestamp(),
            "scan":         scored_result,
        }

        with path.open("w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)

        logger.info("JSON report saved → %s", path.resolve())
        return path.resolve()
