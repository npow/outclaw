"""outclaw audit – standalone security scanner.

Scans the local machine for common OpenClaw security misconfigurations.
No FastAPI dependency required.
"""

import dataclasses
import json
import os
import re
import stat
import subprocess
from pathlib import Path

# Reuse secret patterns from the secret guard driver
SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"sk_live_[0-9a-zA-Z]{24}", "Stripe Secret Key"),
    (r"sk-[a-zA-Z0-9]{48}", "OpenAI API Key"),
    (r"xox[baprs]-([0-9a-zA-Z]{10,48})?", "Slack Token"),
    (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Access Token"),
    (r"-----BEGIN PRIVATE KEY-----", "RSA Private Key"),
]

OPENCLAW_SEARCH_PATHS = [
    Path.home() / ".openclaw",
    Path("openclaw.yaml"),
    Path("config.yaml"),
    Path.home() / ".moltbot",
    Path(".env"),
]

COMMON_PORTS = [3000, 8080, 8000, 8888]


@dataclasses.dataclass
class Finding:
    check: str
    severity: str  # "critical", "warning", "info"
    message: str
    detail: str = ""


def _check_gateway_binding() -> list[Finding]:
    """Check for processes bound to 0.0.0.0 on common ports."""
    findings: list[Finding] = []

    # Check config files for host: 0.0.0.0
    for p in OPENCLAW_SEARCH_PATHS:
        if p.is_file():
            try:
                text = p.read_text(errors="ignore")
                if re.search(r'host\s*[:=]\s*["\']?0\.0\.0\.0', text):
                    findings.append(Finding(
                        check="gateway_binding",
                        severity="critical",
                        message=f"Config binds to 0.0.0.0: {p}",
                        detail="Binding to all interfaces exposes the gateway to the network.",
                    ))
            except OSError:
                pass

    # Check lsof for wildcard bindings on common ports
    for port in COMMON_PORTS:
        try:
            result = subprocess.run(
                ["lsof", "-iTCP:" + str(port), "-sTCP:LISTEN", "-nP"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                if "*:" in line:
                    findings.append(Finding(
                        check="gateway_binding",
                        severity="critical",
                        message=f"Process listening on *:{port} (all interfaces)",
                        detail=line.strip(),
                    ))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return findings


def _check_plaintext_keys() -> list[Finding]:
    """Scan config files for plaintext API keys."""
    findings: list[Finding] = []
    compiled = [(re.compile(p), name) for p, name in SECRET_PATTERNS]

    scan_targets: list[Path] = []
    for p in OPENCLAW_SEARCH_PATHS:
        if p.is_dir():
            scan_targets.extend(p.glob("**/*.yaml"))
            scan_targets.extend(p.glob("**/*.yml"))
            scan_targets.extend(p.glob("**/*.json"))
            scan_targets.extend(p.glob("**/*.env"))
        elif p.is_file():
            scan_targets.append(p)

    for target in scan_targets:
        try:
            text = target.read_text(errors="ignore")
        except OSError:
            continue
        for regex, name in compiled:
            if regex.search(text):
                findings.append(Finding(
                    check="plaintext_keys",
                    severity="critical",
                    message=f"Possible {name} in {target}",
                    detail=f"Pattern matched in plaintext config file.",
                ))

    return findings


def _check_gateway_auth() -> list[Finding]:
    """Probe localhost on common ports for unauthenticated access."""
    findings: list[Finding] = []

    try:
        import httpx
    except ImportError:
        return findings

    for port in COMMON_PORTS:
        try:
            r = httpx.get(f"http://127.0.0.1:{port}/", timeout=2)
            if r.status_code == 200:
                findings.append(Finding(
                    check="gateway_auth",
                    severity="warning",
                    message=f"Unauthenticated 200 on port {port}",
                    detail="Gateway responded without requiring authentication.",
                ))
        except (httpx.ConnectError, httpx.ReadError, httpx.TimeoutException, OSError):
            pass

    return findings


def _check_tool_policies() -> list[Finding]:
    """Check OpenClaw configs for overly permissive tool policies."""
    findings: list[Finding] = []

    for p in OPENCLAW_SEARCH_PATHS:
        if not p.is_file():
            continue
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue

        if re.search(r'"allowAll"\s*:\s*true', text) or re.search(r"allowAll\s*:\s*true", text):
            findings.append(Finding(
                check="tool_policies",
                severity="warning",
                message=f"allowAll: true found in {p}",
                detail="All tools are permitted without restriction.",
            ))

        # Check for empty blocklists
        if re.search(r"tool_guard_blocklist\s*:\s*\[\s*\]", text):
            findings.append(Finding(
                check="tool_policies",
                severity="warning",
                message=f"Empty tool blocklist in {p}",
                detail="No tools are blocked.",
            ))

    return findings


def _check_file_permissions() -> list[Finding]:
    """Flag config files that are world-readable."""
    findings: list[Finding] = []

    for p in OPENCLAW_SEARCH_PATHS:
        targets = []
        if p.is_dir():
            targets.extend(p.iterdir())
        elif p.is_file():
            targets.append(p)

        for target in targets:
            if not target.is_file():
                continue
            try:
                mode = target.stat().st_mode
                if mode & stat.S_IROTH:
                    findings.append(Finding(
                        check="file_permissions",
                        severity="warning",
                        message=f"World-readable config: {target}",
                        detail=f"Permissions: {oct(mode)}",
                    ))
            except OSError:
                pass

    return findings


def _check_outclaw_running() -> list[Finding]:
    """Check if an Outclaw instance is listening."""
    findings: list[Finding] = []

    try:
        import httpx
    except ImportError:
        return findings

    for port in COMMON_PORTS:
        try:
            r = httpx.get(f"http://127.0.0.1:{port}/health", timeout=2)
            data = r.json()
            if data.get("status") == "ok" and "shell" in data.get("shell", ""):
                findings.append(Finding(
                    check="outclaw_running",
                    severity="info",
                    message=f"Outclaw detected on port {port}",
                ))
        except Exception:
            pass

    return findings


ALL_CHECKS = [
    _check_gateway_binding,
    _check_plaintext_keys,
    _check_gateway_auth,
    _check_tool_policies,
    _check_file_permissions,
    _check_outclaw_running,
]


def run_audit(fmt: str = "text") -> int:
    """Run all audit checks. Returns exit code (1 if critical findings)."""
    findings: list[Finding] = []
    for check_fn in ALL_CHECKS:
        findings.extend(check_fn())

    if fmt == "json":
        print(json.dumps([dataclasses.asdict(f) for f in findings], indent=2))
    else:
        if not findings:
            print("No security issues found.")
        else:
            for f in findings:
                severity_tag = f.severity.upper()
                print(f"[{severity_tag}] {f.check}: {f.message}")
                if f.detail:
                    print(f"  {f.detail}")
            print()
            criticals = sum(1 for f in findings if f.severity == "critical")
            warnings = sum(1 for f in findings if f.severity == "warning")
            infos = sum(1 for f in findings if f.severity == "info")
            print(f"Summary: {criticals} critical, {warnings} warning, {infos} info")

    has_critical = any(f.severity == "critical" for f in findings)
    return 1 if has_critical else 0
