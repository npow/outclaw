"""outclaw init – interactive config generator."""

import os
import yaml  # type: ignore

PROVIDERS = {
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com/v1",
    "google": "https://generativelanguage.googleapis.com/v1beta",
    "groq": "https://api.groq.com/openai/v1",
    "ollama": "http://127.0.0.1:11434/v1",
}

TOOL_GUARD_PROFILES = ["balanced", "strict", "paranoid"]

DEFAULT_CONFIG = {
    "mode": "strict",
    "drivers": {
        "tool_guard": True,
        "workspace_guard": True,
        "network_guard": True,
        "llm_guard": True,
        "secret_guard": True,
        "pii_guard": True,
    },
    "tool_guard_blocklist": [
        r"rm\s+-[rRf]+",
        r"mkfs",
        r"dd\b",
        r"chmod\s+777",
        r"nc\b.*-e\b",
        r"bash\s+-i",
        r"sh\s+-i",
        r"\bsocat\b",
        r"\btelnet\b",
        r"\bssh\b",
    ],
    "tool_guard_profile": "balanced",
    "workspace_guard": {
        "workspace_root": ".",
        "enforce_strict_subpath": False,
    },
    "network_guard": {
        "allow_unknown": False,
        "use_community_list": True,
        "allowed_domains": [
            "localhost",
            "127.0.0.1",
            "api.openai.com",
            "anthropic.com",
            "google.com",
        ],
        "blocked_domains": [
            "malware.com",
            "phishing.site",
            "pastebin.com",
        ],
    },
    "pii_redact": ["email", "phone_us", "ssn"],
}


def _choose(prompt: str, options: list[str]) -> str:
    """Present a numbered menu and return the chosen option."""
    for i, opt in enumerate(options, 1):
        print(f"  {i}) {opt}")
    while True:
        raw = input(prompt).strip()
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1]
        print(f"  Please enter a number between 1 and {len(options)}")


def _store_key(api_key: str) -> None:
    """Store key in keyring if available, otherwise warn."""
    try:
        import keyring
        keyring.set_password("outclaw", "api_key", api_key)
        print("  Key stored in system keyring.")
    except ImportError:
        print("  Warning: keyring not installed. Use API_KEY env var instead.")
        print("  Install with: pip install outclaw[secure]")
    except Exception as exc:
        print(f"  Warning: keyring backend error ({exc}). Use API_KEY env var instead.")


def run_init() -> None:
    """Run the interactive init flow."""
    print("Outclaw Init – Interactive Config Setup 🦞")
    print("=" * 45)
    print()

    # 1. Provider
    provider_names = list(PROVIDERS.keys()) + ["custom"]
    provider = _choose(f"Choose LLM provider [1-{len(provider_names)}]: ", provider_names)

    if provider == "custom":
        upstream_url = input("Enter upstream base URL: ").strip()
    else:
        upstream_url = PROVIDERS[provider]
    print(f"  Upstream URL: {upstream_url}")
    print()

    # 2. API key
    api_key = input("Enter API key (leave blank to skip): ").strip()
    if api_key:
        _store_key(api_key)
    print()

    # 3. Mode
    mode = _choose("Choose mode [1-2]: ", ["strict", "audit"])
    print()

    # 4. ToolGuard profile
    tool_guard_profile = _choose(
        f"Choose ToolGuard profile [1-{len(TOOL_GUARD_PROFILES)}]: ",
        TOOL_GUARD_PROFILES,
    )
    print()

    # 5. Build config
    cfg = dict(DEFAULT_CONFIG)
    cfg["mode"] = mode
    cfg["tool_guard_profile"] = tool_guard_profile

    # Write config.yaml
    config_path = "config.yaml"
    with open(config_path, "w") as f:
        yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)

    # Write .env hint
    print(f"  Config written to {config_path}")
    print()
    print("  Set environment variables before running:")
    print(f"    export UPSTREAM_BASE_URL={upstream_url}")
    if api_key:
        print("    # API key stored in keyring (or set API_KEY env var)")
    else:
        print("    export API_KEY=<your-api-key>")
    print()
    print("  Start the proxy with:")
    print("    outclaw proxy")
    print()
    print("  Summary:")
    print(f"    Provider:  {provider}")
    print(f"    Upstream:  {upstream_url}")
    print(f"    Mode:      {mode}")
    print(f"    ToolGuard: {tool_guard_profile}")
    print(f"    Drivers:   all enabled")
