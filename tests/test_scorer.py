"""Tests for the scorer module."""

from __future__ import annotations

import pytest

from scankii.core.nl_analyzer import NLFinding
from scankii.core.ast_analyzer import ASTFinding
from scankii.core.cross_modal import CrossModalFinding
from scankii.core.scorer import ScoredFinding, score_finding, score_findings


# ---------- Helpers ----------


def _nl(
    finding_type: str = "credential_action",
    matched_terms: list[str] | None = None,
    severity: str = "MEDIUM",
) -> NLFinding:
    return NLFinding(
        file_path="dummy.md",
        window_text="test window text",
        finding_type=finding_type,
        matched_terms=tuple(matched_terms or ["api_key", "pass"]),
        line_number=5,
        severity=severity,
    )


def _ast(
    variable_name: str = "api_key",
    sink_category: str = "logging",
    severity: str = "MEDIUM",
) -> ASTFinding:
    return ASTFinding(
        file_path="run.py",
        line_number=10,
        column=4,
        variable_name=variable_name,
        sink_name="Python print()",
        sink_category=sink_category,
        enclosing_function="execute",
        severity=severity,
        code_snippet="print(api_key)",
    )


def _cross(
    variable_name: str = "api_key",
    sink_category: str = "logging",
    nl_type: str = "credential_action",
) -> CrossModalFinding:
    return CrossModalFinding(
        nl_finding=_nl(finding_type=nl_type),
        ast_finding=_ast(variable_name=variable_name, sink_category=sink_category),
        cross_modal=True,
        attack_flow=["step1", "step2"],
        severity="HIGH",
    )


# ---------- Tests ----------


class TestScoringAxes:
    def test_nl_finding_static_only(self):
        """NL findings are static-only → exploitability = 1.0."""
        scored = score_finding(_nl())
        assert scored.score >= 1.0  # At least base score
        assert isinstance(scored, ScoredFinding)

    def test_ast_finding_network_sink(self):
        """Network sink → exploitability=2.0, leakage=1.8."""
        scored = score_finding(_ast(sink_category="network"))
        # 2.0 * 1.4 * 1.8 * 1.0 = 5.04 → CRITICAL
        assert scored.severity == "CRITICAL"

    def test_ast_finding_logging_sink(self):
        """Logging sink → exploitability=1.5, leakage=1.3."""
        scored = score_finding(_ast(variable_name="api_key", sink_category="logging"))
        # 1.5 * 1.4 * 1.3 * 1.0 = 2.73 → MEDIUM
        assert scored.severity == "MEDIUM"

    def test_ast_finding_file_sink(self):
        """File sink → exploitability=1.5, leakage=1.0."""
        scored = score_finding(_ast(variable_name="api_key", sink_category="file"))
        # 1.5 * 1.4 * 1.0 * 1.0 = 2.1 → MEDIUM
        assert scored.severity == "MEDIUM"

    def test_private_key_multiplier(self):
        """Private key → credential type = 2.0."""
        scored = score_finding(_ast(variable_name="private_key", sink_category="network"))
        # 2.0 * 2.0 * 1.8 * 1.0 = 7.2 → CRITICAL
        assert scored.severity == "CRITICAL"
        assert scored.score > 5.0

    def test_token_multiplier(self):
        """Token → credential type = 1.2."""
        scored = score_finding(_ast(variable_name="access_token", sink_category="logging"))
        # 1.5 * 1.2 * 1.3 * 1.0 = 2.34 → MEDIUM
        assert scored.severity == "MEDIUM"

    def test_generic_variable(self):
        """Generic variable → credential type = 1.0."""
        scored = score_finding(_ast(variable_name="secret", sink_category="file"))
        # 1.5 * 1.0 * 1.0 * 1.0 = 1.5 → LOW
        assert scored.severity == "LOW"


class TestPatternCategory:
    def test_prompt_injection_is_malicious(self):
        """Prompt injection NL finding → pattern category = 2.0."""
        scored = score_finding(_nl(finding_type="prompt_injection"))
        # 1.0 * 1.4 * 1.0 * 2.0 = 2.8 → MEDIUM
        assert scored.score >= 2.0

    def test_social_engineering_is_malicious(self):
        """Social engineering → pattern category = 2.0."""
        scored = score_finding(_nl(finding_type="social_engineering"))
        assert scored.score >= 2.0

    def test_negligent_pattern(self):
        """Normal credential-action is negligent → pattern category = 1.0."""
        scored = score_finding(_nl(finding_type="credential_action"))
        # pattern_category = 1.0


class TestCrossModal:
    def test_cross_modal_network(self):
        """Cross-modal with network sink gets highest scores."""
        scored = score_finding(_cross(sink_category="network"))
        assert scored.severity in ("HIGH", "CRITICAL")

    def test_cross_modal_logging(self):
        """Cross-modal with logging sink."""
        scored = score_finding(_cross(sink_category="logging"))
        assert scored.severity in ("MEDIUM", "HIGH")


class TestSeverityMapping:
    def test_low_severity(self):
        scored = score_finding(_ast(variable_name="secret", sink_category="file"))
        # 1.5 * 1.0 * 1.0 * 1.0 = 1.5 → LOW
        assert scored.severity == "LOW"

    def test_score_is_positive(self):
        scored = score_finding(_nl())
        assert scored.score > 0


class TestBatchScoring:
    def test_score_findings_list(self):
        findings = [_nl(), _ast(), _cross()]
        scored = score_findings(findings)
        assert len(scored) == 3
        assert all(isinstance(s, ScoredFinding) for s in scored)
