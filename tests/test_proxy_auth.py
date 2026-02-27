"""Tests for proxy authentication configuration.

Since auth is now handled by LiteLLM's master_key mechanism,
these tests verify that Outclaw correctly configures it.
"""

import os
import pytest


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Ensure auth-related env vars are unset between tests."""
    monkeypatch.delenv("OUTCLAW_TOKEN", raising=False)
    monkeypatch.delenv("API_KEY", raising=False)
    monkeypatch.delenv("UPSTREAM_BASE_URL", raising=False)


def test_outclaw_token_sets_master_key(monkeypatch):
    """OUTCLAW_TOKEN should map to LiteLLM's general_settings.master_key."""
    monkeypatch.setenv("OUTCLAW_TOKEN", "secret123")
    from app.main import generate_litellm_config
    config = generate_litellm_config({})
    assert config["general_settings"]["master_key"] == "secret123"


def test_no_token_no_master_key():
    """Without OUTCLAW_TOKEN, master_key should not be set."""
    from app.main import generate_litellm_config
    config = generate_litellm_config({})
    assert "master_key" not in config["general_settings"]


def test_api_key_in_model_config(monkeypatch):
    """API_KEY should be injected into the LiteLLM model config."""
    monkeypatch.setenv("API_KEY", "upstream_key")
    from app.main import generate_litellm_config
    config = generate_litellm_config({})
    assert config["model_list"][0]["litellm_params"]["api_key"] == "upstream_key"


def test_upstream_base_url_in_model_config(monkeypatch):
    """UPSTREAM_BASE_URL should be used as api_base in the model config."""
    monkeypatch.setenv("UPSTREAM_BASE_URL", "https://api.anthropic.com/v1")
    from app.main import generate_litellm_config
    config = generate_litellm_config({})
    assert config["model_list"][0]["litellm_params"]["api_base"] == "https://api.anthropic.com/v1"


def test_wildcard_model_routing():
    """LiteLLM config should use wildcard model routing."""
    from app.main import generate_litellm_config
    config = generate_litellm_config({})
    assert config["model_list"][0]["model_name"] == "*"
    assert config["model_list"][0]["litellm_params"]["model"] == "openai/*"


def test_provider_model_routing_anthropic(monkeypatch):
    monkeypatch.setenv("UPSTREAM_BASE_URL", "https://api.anthropic.com/v1")
    from app.main import generate_litellm_config
    config = generate_litellm_config({})
    assert config["model_list"][0]["litellm_params"]["model"] == "anthropic/*"


def test_provider_model_routing_gemini(monkeypatch):
    monkeypatch.setenv("UPSTREAM_BASE_URL", "https://generativelanguage.googleapis.com/v1beta")
    from app.main import generate_litellm_config
    config = generate_litellm_config({})
    assert config["model_list"][0]["litellm_params"]["model"] == "gemini/*"


def test_provider_model_routing_groq(monkeypatch):
    monkeypatch.setenv("UPSTREAM_BASE_URL", "https://api.groq.com/openai/v1")
    from app.main import generate_litellm_config
    config = generate_litellm_config({})
    assert config["model_list"][0]["litellm_params"]["model"] == "groq/*"


def test_provider_model_routing_ollama(monkeypatch):
    monkeypatch.setenv("UPSTREAM_BASE_URL", "http://127.0.0.1:11434/v1")
    from app.main import generate_litellm_config
    config = generate_litellm_config({})
    assert config["model_list"][0]["litellm_params"]["model"] == "ollama/*"


def test_register_guards_creates_callbacks():
    """register_guards should add guards to litellm.callbacks."""
    import litellm
    original_callbacks = litellm.callbacks[:]
    try:
        from app.main import register_guards
        config = {"mode": "strict", "drivers": {
            "tool_guard": True,
            "workspace_guard": True,
            "network_guard": False,
            "secret_guard": False,
            "pii_guard": False,
            "llm_guard": False,
        }}
        guards = register_guards(config)
        assert len(guards) == 2  # tool_guard + workspace_guard
        assert all(g in litellm.callbacks for g in guards)
    finally:
        litellm.callbacks = original_callbacks
