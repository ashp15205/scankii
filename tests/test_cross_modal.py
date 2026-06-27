"""Tests for the cross-modal analyzer."""

from __future__ import annotations

import pytest

from scankii.core.nl_analyzer import NLFinding
from scankii.core.ast_analyzer import ASTFinding
from scankii.core.cross_modal import (
    CrossModalFinding,
    analyze_cross_modal,
)


def _make_nl_finding(
    matched_terms: list[str] | None = None,
    finding_type: str = "credential_action",
    line_number: int = 5,
) -> NLFinding:
    return NLFinding(
        file_path="dummy.md",
        window_text="Pass your API key to the execute function.",
        finding_type=finding_type,
        matched_terms=tuple(matched_terms or ["api_key", "pass"]),
        line_number=line_number,
        severity="MEDIUM",
    )


def _make_ast_finding(
    variable_name: str = "api_key",
    sink_name: str = "Python print()",
    sink_category: str = "logging",
    severity: str = "MEDIUM",
) -> ASTFinding:
    return ASTFinding(
        file_path="run.py",
        line_number=10,
        column=4,
        variable_name=variable_name,
        sink_name=sink_name,
        sink_category=sink_category,
        enclosing_function="execute",
        severity=severity,
        code_snippet='print(api_key)',
    )


class TestCrossModalMatch:
    def test_basic_cross_modal_match(self):
        nl = [_make_nl_finding(["api_key", "pass"])]
        ast = [_make_ast_finding(variable_name="api_key")]
        results = analyze_cross_modal(nl, ast)

        cross_modal = [r for r in results if isinstance(r, CrossModalFinding)]
        assert len(cross_modal) == 1
        assert cross_modal[0].cross_modal is True
        assert cross_modal[0].nl_finding == nl[0]
        assert cross_modal[0].ast_finding == ast[0]

    def test_severity_escalated(self):
        nl = [_make_nl_finding()]
        ast = [_make_ast_finding(severity="MEDIUM")]
        results = analyze_cross_modal(nl, ast)

        cross_modal = [r for r in results if isinstance(r, CrossModalFinding)]
        assert len(cross_modal) == 1
        assert cross_modal[0].severity == "HIGH"  # escalated from MEDIUM

    def test_severity_escalation_high_to_critical(self):
        nl = [_make_nl_finding()]
        ast = [_make_ast_finding(severity="HIGH")]
        results = analyze_cross_modal(nl, ast)

        cross_modal = [r for r in results if isinstance(r, CrossModalFinding)]
        assert len(cross_modal) == 1
        assert cross_modal[0].severity == "CRITICAL"

    def test_severity_critical_stays_critical(self):
        nl = [_make_nl_finding()]
        ast = [_make_ast_finding(severity="CRITICAL")]
        results = analyze_cross_modal(nl, ast)

        cross_modal = [r for r in results if isinstance(r, CrossModalFinding)]
        assert len(cross_modal) == 1
        assert cross_modal[0].severity == "CRITICAL"

    def test_attack_flow_has_steps(self):
        nl = [_make_nl_finding()]
        ast = [_make_ast_finding()]
        results = analyze_cross_modal(nl, ast)

        cross_modal = [r for r in results if isinstance(r, CrossModalFinding)]
        assert len(cross_modal[0].attack_flow) >= 3


class TestNoMatch:
    def test_no_cross_modal_when_terms_differ(self):
        nl = [_make_nl_finding(["password", "send"])]
        ast = [_make_ast_finding(variable_name="api_key")]
        results = analyze_cross_modal(nl, ast)

        cross_modal = [r for r in results if isinstance(r, CrossModalFinding)]
        assert len(cross_modal) == 0
        # Both should be passed through as standalone
        assert len(results) == 2  # 1 NL + 1 AST

    def test_non_credential_nl_not_matched(self):
        nl = [_make_nl_finding(finding_type="prompt_injection")]
        ast = [_make_ast_finding()]
        results = analyze_cross_modal(nl, ast)

        cross_modal = [r for r in results if isinstance(r, CrossModalFinding)]
        assert len(cross_modal) == 0

    def test_empty_inputs(self):
        results = analyze_cross_modal([], [])
        assert len(results) == 0

    def test_only_nl_findings(self):
        nl = [_make_nl_finding()]
        results = analyze_cross_modal(nl, [])
        assert len(results) == 1
        assert isinstance(results[0], NLFinding)

    def test_only_ast_findings(self):
        ast = [_make_ast_finding()]
        results = analyze_cross_modal([], ast)
        assert len(results) == 1
        assert isinstance(results[0], ASTFinding)


class TestPassthrough:
    def test_unmatched_findings_passed_through(self):
        nl = [
            _make_nl_finding(["api_key", "pass"]),
            _make_nl_finding(["password", "log"], finding_type="credential_action", line_number=20),
        ]
        ast = [
            _make_ast_finding(variable_name="api_key"),
            _make_ast_finding(variable_name="username"),  # won't match any NL term
        ]
        results = analyze_cross_modal(nl, ast)

        cross_modal = [r for r in results if isinstance(r, CrossModalFinding)]
        standalone_nl = [r for r in results if isinstance(r, NLFinding)]
        standalone_ast = [r for r in results if isinstance(r, ASTFinding)]

        assert len(cross_modal) >= 1
        # The password NL finding should be standalone (no matching AST)
        # The username AST finding should be standalone (no matching NL)
        assert len(standalone_nl) >= 1 or len(standalone_ast) >= 1
