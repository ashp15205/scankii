"""SARIF 2.1.0 reporter for scankii scan results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scankii.core.nl_analyzer import NLFinding
from scankii.core.ast_analyzer import ASTFinding
from scankii.core.cross_modal import CrossModalFinding
from scankii.core.scorer import ScoredFinding
from scankii.scanner import ScanResult

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_SARIF_VERSION = "2.1.0"

_SEVERITY_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def to_sarif(result: ScanResult) -> dict[str, Any]:
    """Convert a ScanResult to SARIF 2.1.0 format."""
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    rule_ids_seen: set[str] = set()

    for idx, sf in enumerate(result.findings):
        rule_id, rule_obj = _make_rule(sf, idx)
        if rule_id not in rule_ids_seen:
            rules.append(rule_obj)
            rule_ids_seen.add(rule_id)

        results.append(_make_result(sf, rule_id))

    sarif = {
        "version": _SARIF_VERSION,
        "$schema": _SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "scankii",
                        "version": "1.2.1",
                        "informationUri": "https://github.com/ashp15205/scankii",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    return sarif


def save_sarif_report(
    result: ScanResult,
    output_path: str | Path = "findings.sarif",
) -> Path:
    """Save SARIF report to a file."""
    sarif = to_sarif(result)
    output = Path(output_path)
    output.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return output


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _make_rule(sf: ScoredFinding, index: int) -> tuple[str, dict[str, Any]]:
    """Create a SARIF rule entry from a ScoredFinding."""
    finding = sf.finding

    if isinstance(finding, CrossModalFinding):
        rule_id = "SG-CM-001"
        name = "CrossModalCredentialLeak"
        short_desc = "Cross-modal credential leakage detected"
        full_desc = (
            "An NL instruction in SKILL.md references a credential that also "
            "appears as a variable flowing into a sink in the source code."
        )
        help_text = (
            "Remove the credential reference from SKILL.md or use SafeLogger "
            "to redact credential values before they reach stdout."
        )
    elif isinstance(finding, ASTFinding):
        rule_id = f"SG-AST-{finding.sink_category.upper()}"
        name = f"CredentialTo{finding.sink_category.capitalize()}"
        short_desc = f"Credential leaked to {finding.sink_category}"
        full_desc = (
            f"The variable '{finding.variable_name}' matches a credential pattern "
            f"and is passed to {finding.sink_name}."
        )
        help_text = (
            "Use SafeLogger or redact credentials before passing to sink functions."
        )
    elif isinstance(finding, NLFinding):
        rule_id = f"SG-NL-{finding.finding_type.upper()}"
        name = finding.finding_type.replace("_", " ").title().replace(" ", "")
        short_desc = f"NL {finding.finding_type.replace('_', ' ')} detected"
        full_desc = f"Matched terms: {', '.join(finding.matched_terms)}"
        help_text = "Review and revise the SKILL.md language."
    else:
        rule_id = f"SG-UNKNOWN-{index}"
        name = "UnknownFinding"
        short_desc = "Unknown finding type"
        full_desc = "An unrecognized finding was detected."
        help_text = "Review the finding manually."

    rule = {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": short_desc},
        "fullDescription": {"text": full_desc},
        "help": {
            "text": help_text,
            "markdown": f"**Fix:** {help_text}",
        },
        "defaultConfiguration": {
            "level": _SEVERITY_TO_SARIF_LEVEL.get(sf.severity, "warning"),
        },
    }

    return rule_id, rule


def _make_result(sf: ScoredFinding, rule_id: str) -> dict[str, Any]:
    """Create a SARIF result entry from a ScoredFinding."""
    finding = sf.finding
    file_path, line, col = _get_location(finding)

    message = _get_message(finding)

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": _SEVERITY_TO_SARIF_LEVEL.get(sf.severity, "warning"),
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path},
                    "region": {
                        "startLine": max(line, 1),
                        "startColumn": max(col, 1),
                    },
                }
            }
        ],
        "properties": {
            "score": sf.score,
            "severity": sf.severity,
        },
    }

    # Add fix suggestions
    fix = _get_fix_suggestion(finding)
    if fix:
        result["fixes"] = [
            {
                "description": {"text": fix},
            }
        ]

    return result


def _get_location(finding: Any) -> tuple[str, int, int]:
    """Extract file path, line, and column from any finding type."""
    if isinstance(finding, CrossModalFinding):
        ast = finding.ast_finding
        return ast.file_path, ast.line_number, ast.column + 1
    if isinstance(finding, ASTFinding):
        return finding.file_path, finding.line_number, finding.column + 1
    if isinstance(finding, NLFinding):
        return "SKILL.md", finding.line_number, 1
    return "unknown", 1, 1


def _get_message(finding: Any) -> str:
    """Generate a human-readable message for a SARIF result."""
    if isinstance(finding, CrossModalFinding):
        return (
            f"Cross-modal credential leak: SKILL.md references credential that "
            f"flows through {finding.ast_finding.enclosing_function}() "
            f"to {finding.ast_finding.sink_name}"
        )
    if isinstance(finding, ASTFinding):
        return (
            f"Credential '{finding.variable_name}' passed to "
            f"{finding.sink_name} in {finding.enclosing_function}()"
        )
    if isinstance(finding, NLFinding):
        return (
            f"NL {finding.finding_type.replace('_', ' ')}: "
            f"matched terms [{', '.join(finding.matched_terms)}]"
        )
    return "Security finding detected"


def _get_fix_suggestion(finding: Any) -> str:
    """Get a fix suggestion string for a finding."""
    if isinstance(finding, CrossModalFinding) or isinstance(finding, ASTFinding):
        ast = finding.ast_finding if isinstance(finding, CrossModalFinding) else finding
        if ast.sink_category == "logging":
            return f"Replace {ast.sink_name} with SafeLogger to redact credentials"
        if ast.sink_category == "network":
            return "Read credentials from environment variables instead of hardcoding"
        return "Use SafeLogger or redact credentials before output"
    if isinstance(finding, NLFinding):
        return "Revise SKILL.md language to avoid credential exposure instructions"
    return ""
