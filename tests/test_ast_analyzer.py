"""Tests for the AST analyzer."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from scankii.core.ast_analyzer import ASTFinding, analyze_ast_from_string


# ---------- Python test fixtures ----------


PYTHON_CREDENTIAL_TO_PRINT = textwrap.dedent("""\
    API_KEY = "sk-proj-abc123def456ghi789jkl"

    def execute():
        print(API_KEY)
""")


PYTHON_CREDENTIAL_TO_REQUESTS = textwrap.dedent("""\
    import requests

    api_key = "sk-proj-abc123def456ghi789jkl"

    def send_data():
        requests.post("https://example.com", data=api_key)
""")


PYTHON_NO_CREDENTIAL = textwrap.dedent("""\
    name = "Alice"

    def greet():
        print(name)
""")


PYTHON_CREDENTIAL_NO_SINK = textwrap.dedent("""\
    API_KEY = "sk-proj-abc123def456ghi789jkl"

    def compute():
        x = API_KEY + "_suffix"
        return x
""")


PYTHON_PARAM_CREDENTIAL = textwrap.dedent("""\
    def execute(api_key: str = "default"):
        print(api_key)
""")


# ---------- JavaScript test fixtures ----------


JS_CREDENTIAL_TO_CONSOLE = textwrap.dedent("""\
    const apiKey = "sk-proj-abc123def456ghi789jkl";

    function run() {
        console.log(apiKey);
    }
""")


JS_CREDENTIAL_TO_FETCH = textwrap.dedent("""\
    const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234";

    async function sendData() {
        fetch("https://example.com", { body: token });
    }
""")


JS_NO_CREDENTIAL = textwrap.dedent("""\
    const name = "Bob";

    function greet() {
        console.log(name);
    }
""")


# ---------- Python tests ----------


class TestPythonAnalysis:
    def test_detects_credential_to_print(self):
        findings = analyze_ast_from_string(
            PYTHON_CREDENTIAL_TO_PRINT, "python", "test.py"
        )
        assert len(findings) >= 1
        f = findings[0]
        assert f.variable_name == "API_KEY"
        assert f.sink_name == "Python print()"
        assert f.sink_category == "logging"
        assert f.enclosing_function == "execute"

    def test_detects_credential_to_requests(self):
        findings = analyze_ast_from_string(
            PYTHON_CREDENTIAL_TO_REQUESTS, "python", "test.py"
        )
        assert len(findings) >= 1
        f = findings[0]
        assert f.variable_name == "api_key"
        assert "requests.post" in f.sink_name.lower() or f.sink_category == "network"

    def test_no_findings_for_normal_code(self):
        findings = analyze_ast_from_string(PYTHON_NO_CREDENTIAL, "python", "test.py")
        assert len(findings) == 0

    def test_no_finding_when_no_sink(self):
        findings = analyze_ast_from_string(
            PYTHON_CREDENTIAL_NO_SINK, "python", "test.py"
        )
        assert len(findings) == 0

    def test_detects_parameter_credential(self):
        findings = analyze_ast_from_string(
            PYTHON_PARAM_CREDENTIAL, "python", "test.py"
        )
        assert len(findings) >= 1
        assert findings[0].variable_name == "api_key"

    def test_finding_has_correct_fields(self):
        findings = analyze_ast_from_string(
            PYTHON_CREDENTIAL_TO_PRINT, "python", "myfile.py"
        )
        assert len(findings) >= 1
        f = findings[0]
        assert isinstance(f, ASTFinding)
        assert f.file_path == "myfile.py"
        assert f.line_number > 0
        assert f.column >= 0
        assert f.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert f.code_snippet  # non-empty


# ---------- JavaScript tests ----------


class TestJavaScriptAnalysis:
    def test_detects_credential_to_console_log(self):
        findings = analyze_ast_from_string(
            JS_CREDENTIAL_TO_CONSOLE, "javascript", "test.js"
        )
        assert len(findings) >= 1
        f = findings[0]
        assert f.variable_name == "apiKey"
        assert "console.log" in f.sink_name.lower() or f.sink_category == "logging"
        assert f.enclosing_function == "run"

    def test_detects_credential_to_fetch(self):
        findings = analyze_ast_from_string(
            JS_CREDENTIAL_TO_FETCH, "javascript", "test.js"
        )
        assert len(findings) >= 1
        f = findings[0]
        assert f.variable_name == "token"

    def test_no_findings_for_normal_js(self):
        findings = analyze_ast_from_string(JS_NO_CREDENTIAL, "javascript", "test.js")
        assert len(findings) == 0


# ---------- Edge cases ----------


class TestEdgeCases:
    def test_unsupported_language(self):
        findings = analyze_ast_from_string("fn main() {}", "rust", "test.rs")
        assert len(findings) == 0

    def test_empty_source(self):
        findings = analyze_ast_from_string("", "python", "empty.py")
        assert len(findings) == 0
