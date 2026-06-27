"""Rich-based CLI table reporter for scankii scan results."""

from __future__ import annotations

import io
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich.markup import escape as rich_escape

from scankii.core.nl_analyzer import NLFinding
from scankii.core.ast_analyzer import ASTFinding
from scankii.core.cross_modal import CrossModalFinding
from scankii.core.scorer import ScoredFinding
from scankii.scanner import ScanResult

_SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold yellow",
    "MEDIUM": "bold dark_orange",
    "LOW": "bold blue",
}


def render_cli_report(
    result: ScanResult,
    console: Console | None = None,
) -> None:
    """Render a compact scan results table using rich."""
    console = console or Console()

    if not result.findings:
        console.print(Panel("✅ No findings detected.", style="green"))
        return

    table = Table(
        title=f"scankii scan: {rich_escape(result.skill_path)}",
        show_header=True,
        header_style="bold white",
    )
    table.add_column("File", style="cyan")
    table.add_column("Line", justify="right", style="white")
    table.add_column("Pattern", style="white")
    table.add_column("Channel", style="white")
    table.add_column("Severity", justify="center")

    for sf in result.findings:
        file_name, line, pattern, channel = _extract_row(sf)
        color = _SEVERITY_COLORS.get(sf.severity, "white")
        table.add_row(
            Text(file_name),
            Text(str(line)),
            Text(pattern),
            Text(channel),
            Text(sf.severity, style=color),
        )

    console.print(table)

    # Summary at bottom
    console.print()
    parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = result.summary.get(sev, 0)
        if count > 0:
            color = _SEVERITY_COLORS.get(sev, "white")
            parts.append(f"[{color}]{sev}: {count}[/{color}]")
    console.print(f"  Total: {result.summary.get('total', 0)}  ({', '.join(parts)})")


def render_cli_to_string(result: ScanResult) -> str:
    """Render CLI report to a string (for testing)."""
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=True, width=120)
    render_cli_report(result, console)
    return buf.getvalue()


def _extract_row(sf: ScoredFinding) -> tuple[str, int, str, str]:
    """Extract table row data from a ScoredFinding."""
    finding = sf.finding

    if isinstance(finding, CrossModalFinding):
        ast = finding.ast_finding
        return (
            _short_path(ast.file_path),
            ast.line_number,
            "Cross-Modal Leak",
            _channel_name(ast.sink_category),
        )
    if isinstance(finding, ASTFinding):
        return (
            _short_path(finding.file_path),
            finding.line_number,
            f"{finding.variable_name} → {finding.sink_name}",
            _channel_name(finding.sink_category),
        )
    if isinstance(finding, NLFinding):
        titles = {
            "credential_action": "Credential Action",
            "prompt_injection": "Prompt Injection",
            "social_engineering": "Social Engineering",
        }
        return (
            "SKILL.md",
            finding.line_number,
            titles.get(finding.finding_type, finding.finding_type),
            "NL instruction",
        )
    return ("unknown", 0, "unknown", "unknown")


def _short_path(path: str) -> str:
    """Get just the filename from a path."""
    from pathlib import Path
    return Path(path).name


def _channel_name(category: str) -> str:
    """Map sink category to a human-readable channel name."""
    return {
        "logging": "stdout",
        "network": "network",
        "file": "file",
    }.get(category, category)
