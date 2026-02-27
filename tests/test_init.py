"""Tests for outclaw init config generator."""

from unittest.mock import patch, MagicMock

import pytest
import yaml

from app.init_config import run_init, _choose, _store_key, PROVIDERS, DEFAULT_CONFIG


class TestChoose:
    def test_valid_selection(self):
        with patch("builtins.input", return_value="2"):
            result = _choose("Pick: ", ["a", "b", "c"])
        assert result == "b"

    def test_retries_on_invalid(self):
        with patch("builtins.input", side_effect=["0", "5", "abc", "1"]):
            result = _choose("Pick: ", ["x", "y"])
        assert result == "x"


class TestStoreKey:
    def test_stores_via_keyring(self):
        mock_keyring = MagicMock()
        with patch.dict("sys.modules", {"keyring": mock_keyring}):
            _store_key("test-key")
        mock_keyring.set_password.assert_called_once_with(
            "outclaw", "api_key", "test-key"
        )

    def test_handles_missing_keyring(self, capsys):
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "keyring":
                raise ImportError("no keyring")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fake_import):
            _store_key("test-key")

        out = capsys.readouterr().out
        assert "keyring not installed" in out.lower()


class TestRunInit:
    def test_openai_flow(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        inputs = iter([
            "1",       # openai
            "",        # skip api key
            "1",       # strict mode
            "1",       # balanced tool guard profile
        ])
        with patch("builtins.input", lambda _: next(inputs)):
            run_init()

        config_path = tmp_path / "config.yaml"
        assert config_path.exists()
        cfg = yaml.safe_load(config_path.read_text())
        assert cfg["mode"] == "strict"
        assert cfg["tool_guard_profile"] == "balanced"
        assert cfg["drivers"]["tool_guard"] is True

    def test_custom_provider_flow(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        inputs = iter([
            "6",                           # custom
            "https://my-llm.example.com",  # custom URL
            "sk-test123",                  # api key
            "2",                           # audit mode
            "3",                           # paranoid profile
        ])
        with patch("builtins.input", lambda _: next(inputs)):
            with patch("app.init_config._store_key") as mock_store:
                run_init()
                mock_store.assert_called_once_with("sk-test123")

        cfg = yaml.safe_load((tmp_path / "config.yaml").read_text())
        assert cfg["mode"] == "audit"
        assert cfg["tool_guard_profile"] == "paranoid"

    def test_anthropic_provider(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        inputs = iter([
            "2",       # anthropic
            "",        # skip api key
            "1",       # strict
            "2",       # strict profile
        ])
        with patch("builtins.input", lambda _: next(inputs)):
            run_init()

        cfg = yaml.safe_load((tmp_path / "config.yaml").read_text())
        assert cfg["tool_guard_profile"] == "strict"
        assert cfg["drivers"]["secret_guard"] is True
