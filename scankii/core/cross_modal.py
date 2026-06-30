"""Cross-modal analyzer linking NL findings to AST findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Union

from scankii.core.nl_analyzer import NLFinding
from scankii.core.ast_analyzer import ASTFinding

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "DEFER"]

_SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass(frozen=True)
class CrossModalFinding:
    """A finding where NL instructions and code findings are correlated."""

    nl_finding: NLFinding
    ast_finding: ASTFinding
    cross_modal: bool
    attack_flow: tuple[str, ...]
    severity: Severity


AnyFinding = Union[NLFinding, ASTFinding, CrossModalFinding]


def analyze_cross_modal(
    nl_findings: list[NLFinding],
    ast_findings: list[ASTFinding],
) -> list[AnyFinding]:
    """Detect cross-modal leakage and return all findings.

    Cross-modal leakage occurs when an NL instruction references a credential
    term AND a matching ASTFinding exists for the same credential term.

    Findings that don't match cross-modally are passed through as standalone.
    """
    matched_nl_indices: set[int] = set()
    matched_ast_indices: set[int] = set()
    cross_modal_findings: list[CrossModalFinding] = []

    for nl_idx, nl_finding in enumerate(nl_findings):
        if nl_finding.finding_type != "credential_action":
            continue

        nl_cred_terms = _extract_credential_terms(nl_finding.matched_terms)

        for ast_idx, ast_finding in enumerate(ast_findings):
            ast_var_lower = ast_finding.variable_name.lower()
            ast_var_normalized = ast_var_lower.replace("-", "_")

            for term in nl_cred_terms:
                term_normalized = term.lower().replace("-", "_")
                if term_normalized in ast_var_normalized or ast_var_normalized in term_normalized:
                    # Cross-modal match found
                    escalated_severity = _escalate_severity(ast_finding.severity)
                    attack_flow = _build_attack_flow(nl_finding, ast_finding)
                    cmf = CrossModalFinding(
                        nl_finding=nl_finding,
                        ast_finding=ast_finding,
                        cross_modal=True,
                        attack_flow=attack_flow,
                        severity=escalated_severity,
                    )
                    cross_modal_findings.append(cmf)
                    matched_nl_indices.add(nl_idx)
                    matched_ast_indices.add(ast_idx)
                    break  # one match per NL-AST pair

    # Collect all findings: cross-modal + standalone
    all_findings: list[AnyFinding] = list(cross_modal_findings)

    for idx, nl_f in enumerate(nl_findings):
        if idx not in matched_nl_indices:
            all_findings.append(nl_f)

    for idx, ast_f in enumerate(ast_findings):
        if idx not in matched_ast_indices:
            all_findings.append(ast_f)

    return all_findings


def _extract_credential_terms(matched_terms: list[str]) -> list[str]:
    """Extract credential-related terms from NL matched_terms.

    The matched_terms list contains both credential terms and action verbs;
    we only want the credential terms.
    """
    _ACTION_VERBS = {
        "send", "store", "embed", "log", "post", "forward", "transmit", "pass",
    }
    return [t for t in matched_terms if t.lower() not in _ACTION_VERBS]


def _escalate_severity(current: Severity) -> Severity:
    """Escalate severity by one level."""
    idx = _SEVERITY_ORDER.index(current)
    new_idx = min(idx + 1, len(_SEVERITY_ORDER) - 1)
    return _SEVERITY_ORDER[new_idx]  # type: ignore[return-value]


def _build_attack_flow(nl_finding: NLFinding, ast_finding: ASTFinding) -> tuple[str, ...]:
    """Build the attack flow path description."""
    flow: list[str] = []

    flow.append(
        f"SKILL.md [line {nl_finding.line_number}] ← NL instruction references "
        f"credential terms: {', '.join(nl_finding.matched_terms)}"
    )
    flow.append(
        f"{ast_finding.enclosing_function}({ast_finding.variable_name}) "
        f"[{ast_finding.file_path}:{ast_finding.line_number}] ← credential enters function"
    )
    snippet = ast_finding.code_snippet.strip()
    flow.append(
        f"{snippet} [{ast_finding.file_path}:{ast_finding.line_number}] "
        f"← sinks to {ast_finding.sink_category}"
    )

    channel_map = {
        "logging": "stdout ← captured by agent framework",
        "network": "network ← exfiltrated externally",
        "file": "file ← persisted to disk",
    }
    flow.append(channel_map.get(ast_finding.sink_category, "unknown channel"))
    flow.append("LLM context window ← credential now queryable via natural language")

    return tuple(flow)
