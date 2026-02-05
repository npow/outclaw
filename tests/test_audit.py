"""Tests for outclaw audit scanner."""

import json
import os
import stat
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from app.audit import (
    Finding,
    _check_plaintext_keys,
    _check_tool_policies,
    _check_file_permissions,
    _check_gateway_binding,
    _check_outclaw_running,
    _check_gateway_auth,
    run_audit,
)


class TestFindingDataclass:
    def test_defaults(self):
        f = Finding(check="test", severity="info", message="msg")
        assert f.detail == ""

    def test_fields(self):
        f = Finding(check="c", severity="critical", message="m", detail="d")
        assert f.check == "c"
        assert f.severity == "critical"


class TestCheckPlaintextKeys:
    def test_detects_aws_key(self, tmp_path, monkeypatch):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("api_key: AKIAIOSFODNN7EXAMPLE")
        with patch("app.audit.OPENCLAW_SEARCH_PATHS", [cfg]):
            findings = _check_plaintext_keys()
        assert len(findings) >= 1
        assert findings[0].severity == "critical"
        assert "AWS" in findings[0].message

    def test_clean_file_no_findings(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("mode: strict\ndrivers: {}")
        with patch("app.audit.OPENCLAW_SEARCH_PATHS", [cfg]):
            findings = _check_plaintext_keys()
        assert findings == []

    def test_scans_directory(self, tmp_path):
        d = tmp_path / ".openclaw"
        d.mkdir()
        (d / "settings.yaml").write_text("key: sk-" + "a" * 48)
        with patch("app.audit.OPENCLAW_SEARCH_PATHS", [d]):
            findings = _check_plaintext_keys()
        assert len(findings) >= 1


class TestCheckToolPolicies:
    def test_detects_allow_all(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text('{"allowAll": true}')
        with patch("app.audit.OPENCLAW_SEARCH_PATHS", [cfg]):
            findings = _check_tool_policies()
        assert len(findings) >= 1
        assert findings[0].severity == "warning"

    def test_detects_empty_blocklist(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("tool_guard_blocklist: []")
        with patch("app.audit.OPENCLAW_SEARCH_PATHS", [cfg]):
            findings = _check_tool_policies()
        assert len(findings) >= 1

    def test_normal_config_clean(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("mode: strict\ntool_guard_blocklist:\n  - rm")
        with patch("app.audit.OPENCLAW_SEARCH_PATHS", [cfg]):
            findings = _check_tool_policies()
        assert findings == []


class TestCheckFilePermissions:
    def test_detects_world_readable(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("secret: data")
        cfg.chmod(0o644)  # world-readable
        with patch("app.audit.OPENCLAW_SEARCH_PATHS", [cfg]):
            findings = _check_file_permissions()
        assert len(findings) >= 1
        assert findings[0].severity == "warning"

    def test_restricted_file_clean(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("mode: strict")
        cfg.chmod(0o600)
        with patch("app.audit.OPENCLAW_SEARCH_PATHS", [cfg]):
            findings = _check_file_permissions()
        assert findings == []


class TestCheckGatewayBinding:
    def test_detects_bind_all_in_config(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("host: 0.0.0.0")
        with patch("app.audit.OPENCLAW_SEARCH_PATHS", [cfg]):
            with patch("subprocess.run", return_value=MagicMock(stdout="")):
                findings = _check_gateway_binding()
        assert len(findings) >= 1
        assert findings[0].severity == "critical"


class TestRunAudit:
    def test_text_output_no_findings(self, capsys):
        with patch("app.audit.ALL_CHECKS", [lambda: []]):
            code = run_audit(fmt="text")
        assert code == 0
        assert "No security issues found" in capsys.readouterr().out

    def test_json_output(self, capsys):
        with patch("app.audit.ALL_CHECKS", [lambda: [
            Finding(check="test", severity="info", message="hello")
        ]]):
            code = run_audit(fmt="json")
        assert code == 0
        data = json.loads(capsys.readouterr().out)
        assert len(data) == 1
        assert data[0]["check"] == "test"

    def test_exit_code_1_on_critical(self):
        with patch("app.audit.ALL_CHECKS", [lambda: [
            Finding(check="test", severity="critical", message="bad")
        ]]):
            code = run_audit(fmt="text")
        assert code == 1
