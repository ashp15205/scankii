"""Basic CLI smoke tests."""

from __future__ import annotations

from click.testing import CliRunner

from scankii.cli import explain, main, scan


def test_cli_loads() -> None:
    """Main CLI group loads and exposes help."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "scankii" in result.output.lower() or "Scan LLM" in result.output


def test_scan_subcommand_exists() -> None:
    """Scan subcommand is registered and shows help."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert result.exit_code == 0
    assert "Scan a skill directory" in result.output
    assert scan.name == "scan"


def test_explain_subcommand_exists() -> None:
    """Explain subcommand is registered and shows help."""
    runner = CliRunner()
    result = runner.invoke(main, ["explain", "--help"])
    assert result.exit_code == 0
    assert "Explain findings" in result.output
    assert explain.name == "explain"
