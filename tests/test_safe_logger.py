"""Tests for the SafeLogger and safe_print credential redaction."""

from __future__ import annotations

import io
import logging
from pathlib import Path

import pytest

from scankii.runtime.safe_logger import SafeLogger, safe_print, redact


class TestRedact:
    """Test the redact() function directly."""

    def test_redacts_openai_key(self):
        text = "Key: sk-proj-abc123def456ghi789jkl012mno345"
        result = redact(text)
        assert "sk-[REDACTED]" in result
        assert "abc123" not in result

    def test_redacts_aws_key(self):
        text = "Access key: AKIAIOSFODNN7EXAMPLE"
        result = redact(text)
        assert "AKIA-[REDACTED]" in result
        assert "IOSFODNN7EXAMPLE" not in result

    def test_redacts_github_pat(self):
        text = "Token: ghp_1234567890abcdefghijklmnopqrstuvwxyz1234"
        result = redact(text)
        assert "ghp-[REDACTED]" in result
        assert "1234567890" not in result

    def test_redacts_mongodb_connection(self):
        text = "Connection: mongodb://user:pass@localhost:27017/mydb"
        result = redact(text)
        assert "mongodb-[REDACTED]" in result
        assert "user:pass" not in result

    def test_redacts_postgres_connection(self):
        text = "DB: postgres://admin:secret@db.example.com:5432/prod"
        result = redact(text)
        assert "postgres-[REDACTED]" in result
        assert "admin:secret" not in result

    def test_normal_string_unchanged(self):
        text = "Hello, world! This is a normal message."
        result = redact(text)
        assert result == text

    def test_multiple_credentials_redacted(self):
        text = "Keys: sk-proj-abc123def456ghi789jkl, AKIAIOSFODNN7EXAMPLE"
        result = redact(text)
        assert "sk-[REDACTED]" in result
        assert "AKIA-[REDACTED]" in result

    def test_redacts_private_key_marker(self):
        text = "-----BEGIN RSA PRIVATE KEY-----"
        result = redact(text)
        assert "KEY-[REDACTED]" in result

    def test_empty_string_unchanged(self):
        result = redact("")
        assert result == ""


class TestSafeLogger:
    """Test the SafeLogger class."""

    def test_info_redacts_credential(self):
        stream = io.StringIO()
        logger = SafeLogger(name="test-info", stream=stream)
        logger.info("Using key sk-proj-abc123def456ghi789jkl012mno345")
        output = stream.getvalue()
        assert "sk-[REDACTED]" in output
        assert "abc123" not in output

    def test_debug_redacts_credential(self):
        stream = io.StringIO()
        logger = SafeLogger(name="test-debug", stream=stream)
        logger._logger.setLevel(logging.DEBUG)
        logger.debug("Key: AKIAIOSFODNN7EXAMPLE")
        output = stream.getvalue()
        assert "AKIA-[REDACTED]" in output

    def test_warning_redacts_credential(self):
        stream = io.StringIO()
        logger = SafeLogger(name="test-warning", stream=stream)
        logger.warning("Token: ghp_1234567890abcdefghijklmnopqrstuvwxyz1234")
        output = stream.getvalue()
        assert "ghp-[REDACTED]" in output

    def test_error_redacts_credential(self):
        stream = io.StringIO()
        logger = SafeLogger(name="test-error", stream=stream)
        logger.error("DB: postgres://admin:secret@localhost/db")
        output = stream.getvalue()
        assert "postgres-[REDACTED]" in output

    def test_normal_message_passes_through(self):
        stream = io.StringIO()
        logger = SafeLogger(name="test-normal", stream=stream)
        logger.info("Starting application")
        output = stream.getvalue()
        assert "Starting application" in output


class TestSafePrint:
    """Test the safe_print() function."""

    def test_redacts_credential(self):
        buf = io.StringIO()
        safe_print("Key: sk-proj-abc123def456ghi789jkl012mno345", file=buf)
        output = buf.getvalue()
        assert "sk-[REDACTED]" in output
        assert "abc123" not in output

    def test_normal_text_passes_through(self):
        buf = io.StringIO()
        safe_print("Hello, world!", file=buf)
        output = buf.getvalue()
        assert "Hello, world!" in output

    def test_multiple_args(self):
        buf = io.StringIO()
        safe_print("Key:", "sk-proj-abc123def456ghi789jkl012mno345", file=buf)
        output = buf.getvalue()
        assert "sk-[REDACTED]" in output

    def test_custom_separator(self):
        buf = io.StringIO()
        safe_print("a", "b", "c", sep="-", file=buf)
        output = buf.getvalue()
        assert "a-b-c" in output
