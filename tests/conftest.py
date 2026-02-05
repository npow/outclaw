import os
import subprocess
import sys
import time
import pytest
import httpx

# Model name in litellm format (provider/model), e.g. "gemini/gemini-2.5-flash"
EVAL_MODEL = os.getenv("EVAL_MODEL", "gemini/gemini-2.5-flash")

# Mapping from litellm provider prefix to inspect_ai provider prefix
_INSPECT_PROVIDER_MAP = {
    "gemini": "google",
}


def _to_inspect_model(litellm_model: str) -> str:
    """Convert litellm model id to inspect_ai model id.

    litellm uses 'gemini/gemini-2.5-flash', inspect_ai uses 'google/gemini-2.5-flash'.
    Providers that use the same prefix in both (e.g. 'anthropic/') pass through unchanged.
    """
    if "/" not in litellm_model:
        return litellm_model
    provider, model = litellm_model.split("/", 1)
    inspect_provider = _INSPECT_PROVIDER_MAP.get(provider, provider)
    return f"{inspect_provider}/{model}"


def pytest_addoption(parser):
    parser.addoption("--eval-model", default=None, help="Model for safety evals (litellm format, e.g. gemini/gemini-2.5-flash)")


@pytest.fixture(scope="session")
def eval_model(request):
    """Model name in litellm format (for Bloom)."""
    return request.config.getoption("--eval-model") or EVAL_MODEL


@pytest.fixture(scope="session")
def eval_model_inspect(eval_model):
    """Model name in inspect_ai format (for Petri)."""
    return _to_inspect_model(eval_model)


# ---------------------------------------------------------------------------
# Outclaw proxy fixture for dynamic evals (Bloom / Petri)
# ---------------------------------------------------------------------------

OUTCLAW_PROXY_PORT = 8111
OUTCLAW_PROXY_URL = f"http://localhost:{OUTCLAW_PROXY_PORT}"


@pytest.fixture(scope="session")
def outclaw_proxy():
    """Start Outclaw proxy on port 8111 for eval target traffic.

    The proxy forwards to the real upstream LLM API so that all target-model
    traffic is inspected by Outclaw drivers while auditor/judge models
    talk directly to the API.
    """
    upstream = os.getenv(
        "UPSTREAM_BASE_URL", "https://generativelanguage.googleapis.com"
    )
    api_key = os.getenv("GEMINI_API_KEY", os.getenv("API_KEY", ""))

    env = {**os.environ, "PORT": str(OUTCLAW_PROXY_PORT), "UPSTREAM_BASE_URL": upstream}
    if api_key:
        env["API_KEY"] = api_key

    proc = subprocess.Popen(
        [sys.executable, "-m", "app.main"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for the health endpoint to come up
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            r = httpx.get(f"{OUTCLAW_PROXY_URL}/health", timeout=2)
            if r.status_code == 200:
                break
        except (httpx.ConnectError, httpx.ReadError):
            pass
        time.sleep(0.5)
    else:
        proc.terminate()
        stdout, stderr = proc.communicate(timeout=5)
        raise RuntimeError(
            f"Outclaw proxy failed to start on port {OUTCLAW_PROXY_PORT}.\n"
            f"stdout: {stdout.decode()}\nstderr: {stderr.decode()}"
        )

    yield OUTCLAW_PROXY_URL

    proc.terminate()
    proc.wait(timeout=10)


# ---------------------------------------------------------------------------
# Attack vector comparison table (printed after test_attack_vectors runs)
# ---------------------------------------------------------------------------


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Print a before/after comparison table for the attack vector benchmark."""
    try:
        from test_attack_vectors import ATTACK_VECTORS
    except ImportError:
        try:
            from tests.test_attack_vectors import ATTACK_VECTORS
        except ImportError:
            return

    reports = terminalreporter.stats
    passed = {r.nodeid for r in reports.get("passed", [])}
    failed = {r.nodeid for r in reports.get("failed", [])}

    # Only print if attack vector tests actually ran
    prefix = "tests/test_attack_vectors.py::"
    if not any(nid.startswith(prefix) for nid in passed | failed):
        return

    rows = []
    for attack in ATTACK_VECTORS:
        name = attack["name"]
        strict_id = f"{prefix}TestWithOutclaw::test_attack[{name}]"
        audit_id = f"{prefix}TestWithoutOutclaw::test_attack[{name}]"
        strict_ok = "PASS" if strict_id in passed else ("FAIL" if strict_id in failed else "---")
        audit_ok = "PASS" if audit_id in passed else ("FAIL" if audit_id in failed else "---")
        rows.append((name, attack["category"], attack["expected"], strict_ok, audit_ok))

    terminalreporter.section("Outclaw Attack Vector Comparison")
    header = f"{'Attack':<30} {'Category':<16} {'Expect':<8} {'Strict':<8} {'Audit':<8}"
    terminalreporter.write_line(header)
    terminalreporter.write_line("-" * len(header))
    for name, cat, expect, strict, audit in rows:
        terminalreporter.write_line(
            f"{name:<30} {cat:<16} {expect:<8} {strict:<8} {audit:<8}"
        )

    strict_pass = sum(1 for *_, s, _ in rows if s == "PASS")
    audit_pass = sum(1 for *_, _, a in rows if a == "PASS")
    terminalreporter.write_line("")
    terminalreporter.write_line(
        f"Strict mode: {strict_pass}/{len(rows)} passed  |  "
        f"Audit mode: {audit_pass}/{len(rows)} passed"
    )
