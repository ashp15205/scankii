"""Scoring engine for scankii findings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Union

from scankii.core.nl_analyzer import NLFinding
from scankii.core.ast_analyzer import ASTFinding
from scankii.core.cross_modal import CrossModalFinding
from scankii.core.patterns import MaliciousFinding

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "DEFER"]
AnyFinding = Union[NLFinding, ASTFinding, CrossModalFinding, MaliciousFinding]


@dataclass(frozen=True)
class ScoredFinding:
    """A finding wrapped with a numeric score and final severity."""

    finding: AnyFinding
    score: float
    severity: Severity


def score_finding(finding: AnyFinding) -> ScoredFinding:
    """Score a finding on four axes and return a ScoredFinding."""
    exploitability = _score_exploitability(finding)
    credential_type = _score_credential_type(finding)
    leakage_channel = _score_leakage_channel(finding)
    pattern_category = _score_pattern_category(finding)

    if isinstance(finding, MaliciousFinding):
        if finding.severity == "DEFER":
            return ScoredFinding(finding=finding, score=0.0, severity="DEFER")
        else:
            return ScoredFinding(finding=finding, score=10.0, severity=finding.severity)

    composite = exploitability * credential_type * leakage_channel * pattern_category
    severity = _map_severity(composite)

    return ScoredFinding(
        finding=finding,
        score=round(composite, 3),
        severity=severity,
    )


def score_findings(findings: list[AnyFinding]) -> list[ScoredFinding]:
    """Score a list of findings."""
    return [score_finding(f) for f in findings]


# ---------------------------------------------------------------------------
# Scoring axes
# ---------------------------------------------------------------------------


def _score_exploitability(finding: AnyFinding) -> float:
    """Exploitability: static-only=1.0, runtime-triggered=1.5, network-exfiltrated=2.0."""
    if isinstance(finding, CrossModalFinding):
        # Cross-modal implies runtime agent triggers the flow
        ast = finding.ast_finding
        if ast.sink_category == "network":
            return 2.0
        return 1.5
    if isinstance(finding, ASTFinding):
        if finding.sink_category == "network":
            return 2.0
        return 1.5
    if isinstance(finding, MaliciousFinding):
        return 2.0
    # NLFinding is static analysis only
    return 1.0


def _score_credential_type(finding: AnyFinding) -> float:
    """Credential type multiplier based on the variable/term involved."""
    var_name = _get_variable_name(finding).lower()

    if "private_key" in var_name or "priv_key" in var_name:
        return 2.0
    if "oauth" in var_name:
        return 1.5
    if "api_key" in var_name or "apikey" in var_name:
        return 1.4
    if "token" in var_name:
        return 1.2
    return 1.0  # generic


def _score_leakage_channel(finding: AnyFinding) -> float:
    """Leakage channel: file=1.0, stdout=1.3, network=1.8."""
    category = _get_sink_category(finding)

    if category == "network":
        return 1.8
    if category == "logging":
        return 1.3
    if category == "file":
        return 1.0
    # NL findings or unknown
    return 1.0


def _score_pattern_category(finding: AnyFinding) -> float:
    """Pattern category: negligent=1.0, malicious=2.0."""
    if isinstance(finding, NLFinding):
        if finding.finding_type in ("prompt_injection", "social_engineering"):
            return 2.0
    if isinstance(finding, CrossModalFinding):
        if finding.nl_finding.finding_type in ("prompt_injection", "social_engineering"):
            return 2.0
    return 1.0  # negligent by default


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_variable_name(finding: AnyFinding) -> str:
    """Extract the variable name from any finding type."""
    if isinstance(finding, ASTFinding):
        return finding.variable_name
    if isinstance(finding, CrossModalFinding):
        return finding.ast_finding.variable_name
    if isinstance(finding, NLFinding):
        # Use the first matched term that looks like a credential
        for term in finding.matched_terms:
            if term.lower() not in {
                "send", "store", "embed", "log", "post", "forward", "transmit", "pass"
            }:
                return term
    if isinstance(finding, MaliciousFinding):
        return finding.pattern_id
    return ""


def _get_sink_category(finding: AnyFinding) -> str:
    """Extract the sink category from any finding type."""
    if isinstance(finding, ASTFinding):
        return finding.sink_category
    if isinstance(finding, CrossModalFinding):
        return finding.ast_finding.sink_category
    if isinstance(finding, MaliciousFinding):
        return finding.attack_category
    return ""


def _map_severity(score: float) -> Severity:
    """Map composite score to severity level."""
    if score == 0.0:
        return "DEFER"
    if score > 5.0:
        return "CRITICAL"
    if score > 3.5:
        return "HIGH"
    if score >= 2.0:
        return "MEDIUM"
    return "LOW"
