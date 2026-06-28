"""AST-based analyzer for detecting credential-to-sink flows."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml
import tree_sitter_python as tspython
import tree_sitter_javascript as tsjavascript
from tree_sitter import Language, Parser, Node

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
CREDENTIALS_PATH = RULES_DIR / "credentials.yaml"
SINKS_PATH = RULES_DIR / "sinks.yaml"

PY_LANGUAGE = Language(tspython.language())
JS_LANGUAGE = Language(tsjavascript.language())


@dataclass(frozen=True)
class ASTFinding:
    """A finding from AST analysis of source code."""

    file_path: str
    line_number: int
    column: int
    variable_name: str
    sink_name: str
    sink_category: str
    enclosing_function: str
    severity: Severity
    code_snippet: str
    start_byte: int = 0
    end_byte: int = 0
    unverifiable_reason: str | None = None


def analyze_ast(
    file_path: str | Path,
    credentials_path: Path | None = None,
    sinks_path: Path | None = None,
) -> list[ASTFinding]:
    """Analyze a source file for credential-to-sink flows."""
    file_path = Path(file_path)
    credentials = _load_yaml(credentials_path or CREDENTIALS_PATH)
    sinks = _load_yaml(sinks_path or SINKS_PATH)

    lang = _detect_language(file_path)
    if lang is None:
        return []

    source = file_path.read_text(encoding="utf-8")
    lines = source.splitlines()
    tree = _parse(source, lang)

    # Build lookup structures
    cred_patterns = _compile_credential_patterns(credentials)
    sink_lookup = _build_sink_lookup(sinks, lang)

    # Find all variable assignments matching credential patterns
    cred_vars = _find_credential_variables(tree.root_node, source, cred_patterns)

    # Find all sink calls where credential variables appear as arguments
    findings: list[ASTFinding] = []
    for call_node in _iter_call_expressions(tree.root_node):
        sink_info = _match_sink(call_node, source, sink_lookup)
        if sink_info is None:
            continue
            
        sink_name, sink_cat, sink_sev_mult, func_start_byte, func_end_byte = sink_info
        
        unverifiable = "unresolved interprocedural boundary" if sink_cat == "unknown" else None
        arg_vars, arg_strings = _extract_arguments(call_node, source, lang)

        for var_name in arg_vars:
            if var_name in cred_vars:
                line_num = call_node.start_point[0] + 1
                col = call_node.start_point[1]
                enclosing = _find_enclosing_function(call_node, source)
                snippet = lines[line_num - 1] if line_num <= len(lines) else ""
                severity = _compute_severity(cred_vars[var_name], sink_sev_mult)
                findings.append(
                    ASTFinding(
                        file_path=str(file_path),
                        line_number=line_num,
                        column=col,
                        variable_name=var_name,
                        sink_name=sink_name,
                        sink_category=sink_cat,
                        enclosing_function=enclosing,
                        severity=severity,
                        code_snippet=snippet.strip(),
                        start_byte=func_start_byte,
                        end_byte=func_end_byte,
                        unverifiable_reason=unverifiable,
                    )
                )

        for literal_str in arg_strings:
            for pattern, severity, is_generic in cred_patterns:
                if not is_generic and pattern.search(literal_str):
                    line_num = call_node.start_point[0] + 1
                    col = call_node.start_point[1]
                    enclosing = _find_enclosing_function(call_node, source)
                    snippet = lines[line_num - 1] if line_num <= len(lines) else ""
                    severity_val = _compute_severity(severity, sink_sev_mult)
                    findings.append(
                        ASTFinding(
                            file_path=str(file_path),
                            line_number=line_num,
                            column=col,
                            variable_name="<hardcoded_string>",
                            sink_name=sink_name,
                            sink_category=sink_cat,
                            enclosing_function=enclosing,
                            severity=severity_val,
                            code_snippet=snippet.strip(),
                            start_byte=func_start_byte,
                            end_byte=func_end_byte,
                            unverifiable_reason=unverifiable,
                        )
                    )
                    break

    return findings


def analyze_ast_from_string(
    source: str,
    language: str,
    file_path: str = "<string>",
    credentials_path: Path | None = None,
    sinks_path: Path | None = None,
) -> list[ASTFinding]:
    """Analyze source code from a string (useful for testing)."""
    credentials = _load_yaml(credentials_path or CREDENTIALS_PATH)
    sinks = _load_yaml(sinks_path or SINKS_PATH)
    lines = source.splitlines()

    lang = language.lower()
    if lang not in ("python", "javascript"):
        return []

    tree = _parse(source, lang)
    cred_patterns = _compile_credential_patterns(credentials)
    sink_lookup = _build_sink_lookup(sinks, lang)

    cred_vars = _find_credential_variables(tree.root_node, source, cred_patterns)

    findings: list[ASTFinding] = []
    for call_node in _iter_call_expressions(tree.root_node):
        sink_info = _match_sink(call_node, source, sink_lookup)
        if sink_info is None:
            continue

        sink_name, sink_cat, sink_sev_mult, func_start_byte, func_end_byte = sink_info
        unverifiable = "unresolved interprocedural boundary" if sink_cat == "unknown" else None
        arg_vars, arg_strings = _extract_arguments(call_node, source, lang)

        for var_name in arg_vars:
            if var_name in cred_vars:
                line_num = call_node.start_point[0] + 1
                col = call_node.start_point[1]
                enclosing = _find_enclosing_function(call_node, source)
                snippet = lines[line_num - 1] if line_num <= len(lines) else ""
                severity = _compute_severity(cred_vars[var_name], sink_sev_mult)
                findings.append(
                    ASTFinding(
                        file_path=file_path,
                        line_number=line_num,
                        column=col,
                        variable_name=var_name,
                        sink_name=sink_name,
                        sink_category=sink_cat,
                        enclosing_function=enclosing,
                        severity=severity,
                        code_snippet=snippet.strip(),
                        start_byte=func_start_byte,
                        end_byte=func_end_byte,
                        unverifiable_reason=unverifiable,
                    )
                )

        for literal_str in arg_strings:
            for pattern, severity, is_generic in cred_patterns:
                if not is_generic and pattern.search(literal_str):
                    line_num = call_node.start_point[0] + 1
                    col = call_node.start_point[1]
                    enclosing = _find_enclosing_function(call_node, source)
                    snippet = lines[line_num - 1] if line_num <= len(lines) else ""
                    severity_val = _compute_severity(severity, sink_sev_mult)
                    findings.append(
                        ASTFinding(
                            file_path=file_path,
                            line_number=line_num,
                            column=col,
                            variable_name="<hardcoded_string>",
                            sink_name=sink_name,
                            sink_category=sink_cat,
                            enclosing_function=enclosing,
                            severity=severity_val,
                            code_snippet=snippet.strip(),
                            start_byte=func_start_byte,
                            end_byte=func_end_byte,
                            unverifiable_reason=unverifiable,
                        )
                    )
                    break

    return findings


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_yaml(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _detect_language(path: Path) -> str | None:
    ext = path.suffix.lower()
    if ext in (".py",):
        return "python"
    if ext in (".js", ".ts", ".mjs"):
        return "javascript"
    return None


def _parse(source: str, lang: str):
    parser = Parser(PY_LANGUAGE if lang == "python" else JS_LANGUAGE)
    return parser.parse(source.encode("utf-8"))


def _compile_credential_patterns(
    credentials: list[dict[str, Any]],
) -> list[tuple[re.Pattern, str, bool]]:
    """Compile credential YAML entries into (regex, severity, is_generic) triples."""
    patterns: list[tuple[re.Pattern, str, bool]] = []
    for entry in credentials:
        pattern_str = entry["pattern"]
        is_generic = entry.get("id", "").startswith("generic-")
        try:
            patterns.append((re.compile(pattern_str), entry["severity"], is_generic))
        except re.error:
            continue
    return patterns


def _build_sink_lookup(
    sinks: list[dict[str, Any]], lang: str
) -> dict[str, tuple[str, str, float]]:
    """Build a map of sink function names → (display_name, category, severity_multiplier).

    The keys are the function name as it would appear in code (e.g. 'print', 'console.log').
    """
    lookup: dict[str, tuple[str, str, float]] = {}
    for sink in sinks:
        if sink["language"] not in (lang, "any"):
            continue
        # Extract the callable name from the display name.
        # e.g. "Python print()" → "print", "JavaScript console.log()" → "console.log"
        name = sink["name"]
        # Pull the function call portion: everything after the last space before ()
        match = re.search(r"(\S+)\(\)", name)
        if match:
            func_name = match.group(1)
            lookup[func_name] = (
                sink["name"],
                sink["category"],
                sink["severity_multiplier"],
            )
    return lookup


def _find_credential_variables(
    root: Node, source: str, cred_patterns: list[tuple[re.Pattern, str, bool]]
) -> dict[str, str]:
    """Walk AST and find all variable assignments whose names match credential patterns.

    Returns a dict of variable_name → severity.
    """
    cred_vars: dict[str, str] = {}

    for node in _iter_nodes(root):
        var_name = _extract_assignment_name(node, source)
        if var_name is None:
            continue
        for pattern, severity, is_generic in cred_patterns:
            if pattern.search(var_name):
                cred_vars[var_name] = severity
                break

    # Also check function parameter names
    for node in _iter_nodes(root):
        if node.type in ("parameters", "formal_parameters"):
            for child in node.children:
                param_name = _extract_param_name(child, source)
                if param_name:
                    for pattern, severity, is_generic in cred_patterns:
                        if pattern.search(param_name):
                            cred_vars[param_name] = severity
                            break

    return cred_vars


def _extract_assignment_name(node: Node, source: str) -> str | None:
    """Extract the variable name from an assignment node."""
    # Python: assignment → identifier = expression
    if node.type == "assignment":
        left = node.child_by_field_name("left")
        if left and left.type == "identifier":
            return _node_text(left, source)
    # Python: expression_statement containing assignment
    if node.type == "expression_statement":
        for child in node.children:
            if child.type == "assignment":
                left = child.child_by_field_name("left")
                if left and left.type == "identifier":
                    return _node_text(left, source)
    # JavaScript: variable_declarator
    if node.type == "variable_declarator":
        name_node = node.child_by_field_name("name")
        if name_node and name_node.type == "identifier":
            return _node_text(name_node, source)
    # JavaScript: assignment_expression
    if node.type == "assignment_expression":
        left = node.child_by_field_name("left")
        if left and left.type == "identifier":
            return _node_text(left, source)
    return None


def _extract_param_name(node: Node, source: str) -> str | None:
    """Extract a parameter name from a parameter node."""
    if node.type == "identifier":
        return _node_text(node, source)
    # Python typed parameter, default parameter
    if node.type in ("typed_parameter", "typed_default_parameter", "default_parameter"):
        name_node = node.child_by_field_name("name")
        if name_node:
            return _node_text(name_node, source)
    # JavaScript formal parameter
    if node.type == "assignment_pattern":
        left = node.child_by_field_name("left")
        if left and left.type == "identifier":
            return _node_text(left, source)
    return None


def _iter_call_expressions(root: Node):
    """Iterate over all call expression nodes in the AST."""
    for node in _iter_nodes(root):
        if node.type in ("call", "call_expression"):
            yield node


def _match_sink(
    call_node: Node, source: str, sink_lookup: dict
) -> tuple[str, str, float, int, int] | None:
    """Check if a call node matches any known sink."""
    func_node = call_node.child_by_field_name("function")
    if func_node is None:
        return None

    func_text = _node_text(func_node, source)
    
    # Safe built-ins that we know do not leak data externally
    safe_builtins = {
        "len", "str", "int", "bool", "float", "type", "isinstance", 
        "format", "hash", "dict", "list", "set", "tuple", "Exception", "Error"
    }
    
    if func_text in safe_builtins:
        return None
        
    for sink_key, (name, cat, sev) in sink_lookup.items():
        if func_text == sink_key:
            return name, cat, sev, func_node.start_byte, func_node.end_byte
        if "." in sink_key and func_text.endswith("." + sink_key.split(".")[-1]):
            return name, cat, sev, func_node.start_byte, func_node.end_byte

    # If it didn't match a safe builtin or a known sink, it is an unresolved boundary
    return f"Unknown function '{func_text}'", "unknown", 1.0, func_node.start_byte, func_node.end_byte


def _extract_arguments(call_node: Node, source: str, lang: str) -> tuple[list[str], list[str]]:
    """Extract identifier names and string literals used as arguments in a call expression."""
    names: list[str] = []
    strings: list[str] = []
    args_node = call_node.child_by_field_name("arguments")
    if args_node is None:
        return names, strings

    for child in _iter_nodes(args_node):
        if child.type == "identifier":
            names.append(_node_text(child, source))
        elif child.type == "string":
            strings.append(_node_text(child, source).strip("'\""))

    return names, strings


def _find_enclosing_function(node: Node, source: str) -> str:
    """Walk up the AST to find the enclosing function name."""
    current = node.parent
    while current is not None:
        if current.type in ("function_definition", "function_declaration",
                            "arrow_function", "method_definition"):
            name_node = current.child_by_field_name("name")
            if name_node:
                return _node_text(name_node, source)
            # arrow functions assigned to variables
            parent = current.parent
            if parent and parent.type == "variable_declarator":
                name_node = parent.child_by_field_name("name")
                if name_node:
                    return _node_text(name_node, source)
            return "<anonymous>"
        current = current.parent
    return "<module>"


def _compute_severity(cred_severity: str, sink_multiplier: float) -> Severity:
    """Combine credential severity with sink multiplier."""
    severity_values = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    base = severity_values.get(cred_severity, 2)
    score = base * sink_multiplier

    if score >= 5.0:
        return "CRITICAL"
    if score >= 3.5:
        return "HIGH"
    if score >= 2.0:
        return "MEDIUM"
    return "LOW"


def _node_text(node: Node, source: str) -> str:
    """Extract the text of a node from the source."""
    return source[node.start_byte:node.end_byte]


def _iter_nodes(root: Node):
    """Depth-first iteration over all nodes in the AST."""
    cursor = root.walk()
    visited_children = False

    while True:
        if not visited_children:
            yield cursor.node
            if not cursor.goto_first_child():
                visited_children = True
        elif cursor.goto_next_sibling():
            visited_children = False
        elif not cursor.goto_parent():
            break
