"""Click-based CLI for scankii."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import click

OutputFormat = Literal["json", "sarif", "terminal"]


@click.group()
@click.version_option(package_name="scankii")
def main() -> None:
    """Scan LLM agent skill directories for credential leakage."""


@main.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "sarif", "terminal"], case_sensitive=False),
    default="terminal",
    help="Output format for scan results.",
)
@click.option(
    "--explain",
    "run_explain",
    is_flag=True,
    default=False,
    help="Show detailed attack flow explanation after scan.",
)
@click.option(
    "--resolve",
    "run_resolve",
    is_flag=True,
    default=False,
    help="Automatically rewrite source code to resolve safe findings (e.g. print -> safe_print).",
)
def scan(path: Path, output_format: OutputFormat, run_explain: bool, run_resolve: bool) -> None:
    """Scan a skill directory for security findings."""
    from scankii.scanner import scan_directory
    from scankii.output.cli_reporter import render_cli_report
    from scankii.output.explain import explain_scan_result
    from scankii.output.json_reporter import save_json_report
    from scankii.output.sarif import save_sarif_report
    result = scan_directory(path)

    if output_format == "json":
        output_path = save_json_report(result)
        click.echo(f"JSON report saved to {output_path}")
    elif output_format == "sarif":
        output_path = save_sarif_report(result)
        click.echo(f"SARIF report saved to {output_path}")
    else:
        render_cli_report(result)
        if run_explain:
            click.echo()
            explain_scan_result(result)
            
        if run_resolve:
            click.echo()
            from scankii.remediation import resolve_findings
            fixes = resolve_findings(result)
            if not fixes:
                click.secho("No auto-resolvable findings found.", fg="yellow")
            else:
                click.secho("✅ Auto-Resolution Complete", fg="green", bold=True)
                for fpath, count in fixes.items():
                    click.echo(f"  - Fixed {count} issue(s) in {fpath}")


@main.command()
@click.argument(
    "findings_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
def explain(findings_file: Path) -> None:
    """Explain findings from a previous scan JSON file."""
    from scankii.output.explain import explain_from_file

    explain_from_file(findings_file)
