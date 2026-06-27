"""Tests for the explain output module."""

from __future__ import annotations

from pathlib import Path

import pytest

from scankii.scanner import scan_directory
from scankii.output.explain import explain_to_string, explain_scan_result

VULNERABLE_SKILL_DIR = Path(__file__).resolve().parent.parent / "examples" / "vulnerable-skill"


class TestExplainOutput:
    def _get_result(self):
        return scan_directory(VULNERABLE_SKILL_DIR)

    def test_explain_produces_output(self):
        result = self._get_result()
        output = explain_to_string(result)
        assert len(output) > 0

    def test_explain_contains_severity(self):
        result = self._get_result()
        output = explain_to_string(result)
        assert "CRITICAL" in output or "HIGH" in output or "MEDIUM" in output

    def test_explain_contains_attack_flow(self):
        result = self._get_result()
        output = explain_to_string(result)
        assert "Attack Flow" in output

    def test_explain_contains_suggested_fix(self):
        result = self._get_result()
        output = explain_to_string(result)
        assert "Suggested Fix" in output

    def test_explain_contains_file_reference(self):
        result = self._get_result()
        output = explain_to_string(result)
        assert "run.py" in output

    def test_explain_contains_summary(self):
        result = self._get_result()
        output = explain_to_string(result)
        assert "Scan Summary" in output

    def test_explain_empty_result(self, tmp_path):
        result = scan_directory(tmp_path)
        output = explain_to_string(result)
        assert "No findings" in output
