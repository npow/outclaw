"""Shared Outclaw configuration loader."""

import yaml

_config = None


def load_outclaw_config() -> dict:
    """Load and cache Outclaw config from config.yaml."""
    global _config
    if _config is not None:
        return _config
    try:
        with open("config.yaml") as f:
            _config = yaml.safe_load(f) or {}
    except FileNotFoundError:
        _config = {}
    return _config
