"""Rich-based attack flow visualization for scankii findings."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from scankii.core.nl_analyzer import NLFinding
from scankii.core.ast_analyzer import ASTFinding
from scankii.core.cross_modal import CrossModalFinding
from scankii.core.scorer import ScoredFinding
from scankii.scanner import ScanResult, load_scan_result

# Severity → color mapping
_SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold yellow",
    "MEDIUM": "bold dark_orange",
    "LOW": "bold blue",
    "DEFER": "bold cyan",
}

_SEVERITY_EMOJI = {
    "CRITICAL": "🚨",
    "HIGH": "⚠️ ",
    "MEDIUM": "🔶",
    "LOW": "ℹ️ ",
    "DEFER": "⏳",
}

# Arrow gradient colors for attack flow (white → yellow → orange → red)
_FLOW_COLORS = ["white", "bright_yellow", "dark_orange", "bold red", "bold red"]


def explain_scan_result(
    result: ScanResult,
    console: Console | None = None,
) -> None:
    """Render the full explain output for a ScanResult."""
    console = console or Console()

    if not result.findings:
        console.print(Panel("No findings to explain.", style="green"))
        return

    for scored_finding in result.findings:
        _render_finding(scored_finding, console)

    _render_summary(result.summary, console)


def explain_from_file(
    findings_path: str | Path,
    console: Console | None = None,
) -> None:
    """Load findings from a JSON file and render the explain output."""
    result = load_scan_result(findings_path)
    explain_scan_result(result, console)


def explain_to_string(result: ScanResult) -> str:
    """Render explain output to a string (useful for testing)."""
    string_io = io.StringIO()
    console = Console(file=string_io, force_terminal=True, width=100)
    explain_scan_result(result, console)
    return string_io.getvalue()


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------


def _render_finding(scored: ScoredFinding, console: Console) -> None:
    """Render a single scored finding with attack flow visualization."""
    severity = scored.severity
    color = _SEVERITY_COLORS.get(severity, "white")
    emoji = _SEVERITY_EMOJI.get(severity, "")
    finding = scored.finding

    # Header bar
    title = _get_finding_title(finding)
    header = Text()
    header.append(f"{emoji} {severity}", style=color)
    header.append(" — ", style="white")
    header.append(title, style=color)

    console.print()
    console.rule(style=color)
    console.print(header, justify="center")
    console.rule(style=color)
    console.print()

    # Details section
    _render_details(finding, scored, console)

    # Attack flow for cross-modal findings
    if isinstance(finding, CrossModalFinding) and finding.attack_flow:
        console.print()
        console.print("  [bold]Attack Flow:[/bold]")
        _render_attack_flow(finding.attack_flow, console)

    # Suggested fix
    _render_fix_suggestion(finding, console)

    console.print()


def _get_finding_title(finding: Any) -> str:
    """Generate a human-readable title for a finding."""
    if isinstance(finding, CrossModalFinding):
        cat = finding.ast_finding.sink_category
        channel = {"logging": "stdout", "network": "network", "file": "file"}.get(cat, cat)
        return f"Information Exposure via {channel}"
    if isinstance(finding, ASTFinding):
        channel = {"logging": "stdout", "network": "network", "file": "file"}.get(
            finding.sink_category, finding.sink_category
        )
        return f"Credential Leak via {channel}"
    if isinstance(finding, NLFinding):
        titles = {
            "credential_action": "NL Credential Action Instruction",
            "prompt_injection": "Prompt Injection Detected",
            "social_engineering": "Social Engineering Detected",
        }
        return titles.get(finding.finding_type, "NL Finding")
    return "Security Finding"


def _render_details(finding: Any, scored: ScoredFinding, console: Console) -> None:
    """Render the detail lines for a finding."""
    from rich.markup import escape as rich_escape

    if isinstance(finding, CrossModalFinding):
        ast = finding.ast_finding
        cat = ast.sink_category
        channel = {"logging": "stdout → LLM context window", "network": "network", "file": "file"}.get(
            cat, cat
        )
        console.print(f"  [bold]Pattern:[/bold]   Information Exposure")
        console.print(f"  [bold]Channel:[/bold]   {rich_escape(channel)}")
        console.print(f"  [bold]File:[/bold]      {rich_escape(ast.file_path)}, line {ast.line_number}")
        console.print(f"  [bold]Score:[/bold]     {scored.score}")
    elif isinstance(finding, ASTFinding):
        console.print(f"  [bold]Variable:[/bold]  {rich_escape(finding.variable_name)}")
        console.print(f"  [bold]Sink:[/bold]      {rich_escape(finding.sink_name)}")
        console.print(f"  [bold]File:[/bold]      {rich_escape(finding.file_path)}, line {finding.line_number}")
        console.print(f"  [bold]Function:[/bold]  {rich_escape(finding.enclosing_function)}")
        console.print(f"  [bold]Score:[/bold]     {scored.score}")
    elif isinstance(finding, NLFinding):
        console.print(f"  [bold]Type:[/bold]      {rich_escape(finding.finding_type)}")
        console.print(f"  [bold]Terms:[/bold]     {rich_escape(', '.join(finding.matched_terms))}")
        console.print(f"  [bold]Line:[/bold]      {finding.line_number}")
        console.print(f"  [bold]Score:[/bold]     {scored.score}")


def _render_attack_flow(flow: list[str], console: Console) -> None:
    """Render attack flow with gradient coloring on the arrows."""
    from rich.markup import escape as rich_escape

    for i, step in enumerate(flow):
        color_idx = min(i, len(_FLOW_COLORS) - 1)
        color = _FLOW_COLORS[color_idx]
        safe_step = rich_escape(step)
        console.print(f"    [{color}]{safe_step}[/{color}]")
        if i < len(flow) - 1:
            arrow_color = _FLOW_COLORS[min(i + 1, len(_FLOW_COLORS) - 1)]
            console.print(f"    [{arrow_color}]↓[/{arrow_color}]")


def _render_fix_suggestion(finding: Any, console: Console) -> None:
    """Render a suggested fix for the finding."""
    from rich.markup import escape as rich_escape

    console.print()
    console.print("  [bold]Suggested Fix:[/bold]")

    if isinstance(finding, CrossModalFinding) or isinstance(finding, ASTFinding):
        ast = finding.ast_finding if isinstance(finding, CrossModalFinding) else finding
        if ast.sink_category == "logging":
            console.print(f"    [red]Replace:[/red]  {rich_escape(ast.code_snippet)}")
            console.print(f"    [green]With:[/green]     from credential_safe import SafeLogger")
            console.print(f"              logger = SafeLogger()")
            console.print(f"              logger.info({rich_escape(ast.variable_name)})")
        elif ast.sink_category == "network":
            console.print(f"    [red]Replace:[/red]  hardcoded credential in network call")
            console.print(f"    [green]With:[/green]     Read credential from environment variable")
            console.print(f"              import os")
            console.print(f"              {rich_escape(ast.variable_name)} = os.environ.get('{rich_escape(ast.variable_name.upper())}')")
        elif ast.sink_category == "file":
            console.print(f"    [red]Replace:[/red]  credential written to file")
            console.print(f"    [green]With:[/green]     Use SafeLogger to redact before writing")
    elif isinstance(finding, NLFinding):
        if finding.finding_type == "prompt_injection":
            console.print("    Remove prompt injection language from SKILL.md")
        elif finding.finding_type == "social_engineering":
            console.print("    Remove social engineering patterns from SKILL.md")
        else:
            console.print("    Rephrase SKILL.md to avoid instructing credential passing")


def _render_summary(summary: dict[str, int], console: Console) -> None:
    """Render the summary panel."""
    console.print()

    table = Table(title="Scan Summary", show_header=True, header_style="bold")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = summary.get(sev, 0)
        color = _SEVERITY_COLORS.get(sev, "white")
        table.add_row(
            Text(sev, style=color),
            Text(str(count), style=color),
        )

    table.add_row(
        Text("TOTAL", style="bold"),
        Text(str(summary.get("total", 0)), style="bold"),
    )

    console.print(Panel(table, border_style="red" if summary.get("CRITICAL", 0) > 0 else "yellow"))
