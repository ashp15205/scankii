"""Basic CLI smoke tests."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from scankii.cli import explain, main, scan

VULNERABLE_SKILL_DIR = Path(__file__).resolve().parent.parent / "examples" / "vulnerable-skill"


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


def test_scan_json_writes_findings_file() -> None:
    """JSON format must write findings.json for CI/CD and pre-commit hooks."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main, ["scan", str(VULNERABLE_SKILL_DIR), "--format", "json"]
        )
        assert result.exit_code == 0
        assert Path("findings.json").is_file()
        data = json.loads(Path("findings.json").read_text(encoding="utf-8"))
        assert "findings" in data
        assert "summary" in data
        assert "JSON report saved to findings.json" in result.output


def test_scan_sarif_writes_findings_file() -> None:
    """SARIF format must write findings.sarif for GitHub Code Scanning uploads."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main, ["scan", str(VULNERABLE_SKILL_DIR), "--format", "sarif"]
        )
        assert result.exit_code == 0
        assert Path("findings.sarif").is_file()
        data = json.loads(Path("findings.sarif").read_text(encoding="utf-8"))
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert "SARIF report saved to findings.sarif" in result.output
