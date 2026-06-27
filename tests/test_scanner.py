"""Tests for the scanner module."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scankii.scanner import ScanResult, scan_directory, load_scan_result

VULNERABLE_SKILL_DIR = Path(__file__).resolve().parent.parent / "examples" / "vulnerable-skill"


class TestScanDirectory:
    def test_scan_returns_scan_result(self):
        result = scan_directory(VULNERABLE_SKILL_DIR)
        assert isinstance(result, ScanResult)
        assert result.skill_path == str(VULNERABLE_SKILL_DIR)

    def test_scan_finds_findings(self):
        result = scan_directory(VULNERABLE_SKILL_DIR)
        assert result.summary["total"] > 0, "Should detect findings in vulnerable skill"

    def test_scan_has_timestamp(self):
        result = scan_directory(VULNERABLE_SKILL_DIR)
        assert result.scan_timestamp  # non-empty ISO string

    def test_scan_summary_has_severity_keys(self):
        result = scan_directory(VULNERABLE_SKILL_DIR)
        for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "total"):
            assert key in result.summary

    def test_scan_detects_cross_modal(self):
        """The vulnerable skill has SKILL.md referencing api_key + run.py using it in print()."""
        result = scan_directory(VULNERABLE_SKILL_DIR)
        finding_types = set()
        for sf in result.findings:
            finding_types.add(type(sf.finding).__name__)
        # Should have at least AST or CrossModal findings
        assert "ASTFinding" in finding_types or "CrossModalFinding" in finding_types


class TestSerialization:
    def test_to_json(self):
        result = scan_directory(VULNERABLE_SKILL_DIR)
        json_str = result.to_json()
        data = json.loads(json_str)
        assert "skill_path" in data
        assert "findings" in data
        assert "summary" in data
        assert "scan_timestamp" in data

    def test_to_dict(self):
        result = scan_directory(VULNERABLE_SKILL_DIR)
        d = result.to_dict()
        assert isinstance(d, dict)
        assert isinstance(d["findings"], list)

    def test_round_trip_json(self, tmp_path):
        result = scan_directory(VULNERABLE_SKILL_DIR)
        json_file = tmp_path / "findings.json"
        json_file.write_text(result.to_json())

        loaded = load_scan_result(json_file)
        assert loaded.skill_path == result.skill_path
        assert loaded.summary == result.summary
        assert len(loaded.findings) == len(result.findings)


class TestEdgeCases:
    def test_empty_directory(self, tmp_path):
        result = scan_directory(tmp_path)
        assert result.summary["total"] == 0

    def test_invalid_path_raises(self):
        with pytest.raises(ValueError):
            scan_directory("/nonexistent/path/that/does/not/exist")
