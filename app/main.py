"""Outclaw – LiteLLM proxy with security guardrails.

Starts a LiteLLM proxy server with Outclaw guards registered as callbacks.
Guards run on every request/response via LiteLLM's CustomGuardrail hooks.
"""

import os
import logging
import tempfile
from pathlib import Path

import yaml
import litellm

from app.config import load_outclaw_config

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
logger = logging.getLogger("outclaw")


def _infer_litellm_model_prefix(upstream_base_url: str) -> str:
    """Infer LiteLLM provider prefix from upstream base URL."""
    url = (upstream_base_url or "").lower()
    if "api.anthropic.com" in url:
        return "anthropic/*"
    if "generativelanguage.googleapis.com" in url or "googleapis.com" in url:
        return "gemini/*"
    if "api.groq.com" in url:
        return "groq/*"
    if "127.0.0.1:11434" in url or "localhost:11434" in url or "ollama" in url:
        return "ollama/*"
    return "openai/*"


def register_guards(config: dict):
    """Instantiate enabled guards and register them as LiteLLM callbacks."""
    drivers = config.get("drivers", {})
    guards = []

    if drivers.get("tool_guard", True):
        from drivers.tool_guard import ToolGuard
        guards.append(ToolGuard(outclaw_config=config))

    if drivers.get("workspace_guard", True):
        from drivers.workspace_guard import WorkspaceGuard
        guards.append(WorkspaceGuard(outclaw_config=config))

    if drivers.get("network_guard", True):
        from drivers.network_guard import NetworkGuard
        guards.append(NetworkGuard(outclaw_config=config))

    if drivers.get("llm_guard", True):
        from drivers.llm_guard import MLGuard
        guards.append(MLGuard(outclaw_config=config))

    if drivers.get("secret_guard", True):
        from drivers.secret_guard import SecretGuard
        guards.append(SecretGuard(outclaw_config=config))

    if drivers.get("pii_guard", True):
        from drivers.pii_guard import PIIGuard
        guards.append(PIIGuard(outclaw_config=config))

    # Register with LiteLLM — these persist through proxy startup
    if isinstance(litellm.callbacks, list):
        litellm.callbacks.extend(guards)
    else:
        litellm.callbacks = guards

    logger.info(f"Registered {len(guards)} Outclaw guard(s) as LiteLLM callbacks")
    return guards


def generate_litellm_config(outclaw_config: dict) -> dict:
    """Generate a LiteLLM proxy config dict from Outclaw settings."""
    upstream = os.getenv("UPSTREAM_BASE_URL", "https://api.openai.com/v1")
    api_key = os.getenv("API_KEY", "")
    model_prefix = _infer_litellm_model_prefix(upstream)

    litellm_config = {
        "model_list": [
            {
                "model_name": "*",
                "litellm_params": {
                    "model": model_prefix,
                    "api_base": upstream,
                    "api_key": api_key or "sk-placeholder",
                },
            }
        ],
        "litellm_settings": {
            "drop_params": True,
        },
        "general_settings": {},
    }

    token = os.getenv("OUTCLAW_TOKEN")
    if token:
        litellm_config["general_settings"]["master_key"] = token

    return litellm_config


def write_litellm_config(litellm_config: dict) -> str:
    """Write LiteLLM config to a temp file and return the path."""
    config_dir = Path(tempfile.mkdtemp(prefix="outclaw_"))
    config_path = config_dir / "litellm_config.yaml"
    with open(config_path, "w") as f:
        yaml.dump(litellm_config, f)
    return str(config_path)


def run_proxy(host: str = "127.0.0.1", port: int = 8080, token: str | None = None):
    """Start the Outclaw proxy (LiteLLM with security guards)."""
    if token:
        os.environ["OUTCLAW_TOKEN"] = token

    # 1. Load Outclaw config and register guards
    outclaw_config = load_outclaw_config()

    if outclaw_config.get("mode") == "audit":
        logger.warning("=" * 60)
        logger.warning("RUNNING IN AUDIT MODE - ZERO PROTECTION ACTIVE")
        logger.warning("Threats will be LOGGED but NOT BLOCKED or MUTATED.")
        logger.warning("=" * 60)

    register_guards(outclaw_config)

    # 2. Generate and write LiteLLM config
    litellm_config = generate_litellm_config(outclaw_config)
    config_path = write_litellm_config(litellm_config)

    # 3. Tell LiteLLM where to find its config
    os.environ["CONFIG_FILE_PATH"] = config_path

    # 4. Start the LiteLLM proxy
    import uvicorn
    from litellm.proxy.proxy_server import app

    logger.info(f"Starting Outclaw (LiteLLM proxy) on {host}:{port}")
    logger.info(f"Upstream: {os.getenv('UPSTREAM_BASE_URL', 'https://api.openai.com/v1')}")
    uvicorn.run(app, host=host, port=port)


# Keep backwards compat for `python -m app.main`
if __name__ == "__main__":
    run_proxy(host="127.0.0.1", port=int(os.getenv("PORT", 8080)))
