# Configuration

Outclaw works out of the box with secure defaults. To customize:

```bash
outclaw init    # creates config.yaml in current directory
```

---

## Global Settings

```yaml
mode: strict       # strict = block/redact threats, audit = log only (no mutation)

drivers:
  tool_guard: true       # dangerous commands
  workspace_guard: true  # file system escape
  network_guard: true    # data exfiltration
  secret_guard: true     # API key leaks
  pii_guard: true        # personal info leaks
  llm_guard: true        # prompt injection (ML-based)
```

---

## Guards

### 🔑 Secret Guard

Detects API keys, tokens, and credentials before they leave your machine.

**Detection layers (all active by default):**

| Layer | What it catches |
|-------|-----------------|
| **Regex patterns** | 50+ patterns for AWS, OpenAI, Anthropic, Stripe, GitHub, Twilio, etc. |
| **detect-secrets plugins** | 20+ detectors including JWT, private keys, basic auth |
| **Entropy-based detection** | High-entropy strings near keywords like `key=`, `token=`, `secret=` |
| **Deobfuscation** | Base64-encoded, hex-encoded, and Unicode-obfuscated secrets |

```yaml
# No configuration needed — all layers active by default
# To allowlist your own API key (so it doesn't get flagged):
secret_guard_allowlist:
  - "sk-your-own-key-here"
```

---

### 🌐 Network Guard

Controls which domains the agent can connect to.

**Detection layers:**

| Layer | What it does |
|-------|--------------|
| **URLhaus blacklist** | 28K+ known malware domains, auto-refreshed daily |
| **Tranco whitelist** | Top 10K popular domains (google.com, github.com, etc.) |
| **publicsuffix parsing** | Correctly handles TLDs (evil.co.uk vs safe.co.uk) |
| **IPv6 detection** | Blocks localhost/private network access via IPv6 |
| **Scheme blocking** | Blocks file://, ftp://, gopher://, etc. |

```yaml
network_guard:
  # What to do with unknown domains (not in Tranco or your lists)
  allow_unknown: false        # false = block unknown (secure), true = allow unknown

  # External lists
  use_community_list: true    # Tranco top 10K whitelist
  use_urlhaus: true           # URLhaus malware blacklist

  # Your custom lists
  allowed_domains:
    - 'localhost'
    - '127.0.0.1'
    - 'your-internal-api.corp'

  blocked_domains:
    - 'pastebin.com'
    - 'ngrok.io'
```

---

### 🛡️ Tool Guard

Blocks dangerous shell commands and patterns.

**Detection layers:**

| Layer | What it does |
|-------|--------------|
| **bashlex AST parsing** | Parses shell commands into syntax tree — catches obfuscation automatically |
| **Regex patterns** | 40+ patterns for reverse shells, privilege escalation, etc. |
| **Allow-list mode** | Optional: only permit specific commands (whitelist-only) |
| **Deobfuscation** | Strips Unicode tricks, empty quotes, hex escapes |

```yaml
tool_guard_profile: balanced   # balanced, strict, paranoid

# Default: blocklist mode (block known-bad, allow everything else)
tool_guard_blocklist:
  - 'rm\s+-[rRf]+'           # recursive delete
  - 'bash\s+-i'              # interactive bash
  - '\bssh\b'                # SSH connections
  # see config.yaml for full list

# Optional: allowlist mode (block everything except these)
tool_guard_allowed_commands:
  - 'ls'
  - 'cat'
  - 'grep'
  - 'git'
  # when set, ONLY these commands are permitted
```

`tool_guard_profile` controls AST-level verb blocking strictness:
- `balanced`: lower-friction defaults for common coding workflows.
- `strict`: broader command-verb blocking.
- `paranoid`: strict + wrapper/context commands.

---

### 🙈 PII Guard

Redacts personal information from prompts before they reach the AI.

**Detection layers:**

| Layer | What it catches |
|-------|-----------------|
| **Presidio NER** | 30+ entity types using spaCy NLP models |
| **phonenumbers** | International phone numbers (200+ countries via libphonenumber) |
| **Regex fallback** | Email, SSN, credit card, IP address patterns |
| **Deobfuscation** | Catches `user [at] example [dot] com` tricks |

```yaml
pii_redact:
  - email
  - phone_us
  - ssn
  # Presidio supports: EMAIL_ADDRESS, PHONE_NUMBER, US_SSN, CREDIT_CARD,
  # IP_ADDRESS, US_PASSPORT, US_DRIVER_LICENSE, IBAN_CODE, PERSON, LOCATION, etc.
```

---

### 🧠 ML Guard

Detects prompt injection attempts using ML models.

**Mode options:**

| Mode | Model | Size | Speed |
|------|-------|------|-------|
| `light` | PromptGuard 2 (LlamaFirewall) | ~90MB | Fast |
| `full` | llm-guard ONNX suite | ~500MB | Slower |
| `off` | Disabled | — | — |

```yaml
ml_guard: light    # light, full, or off

# 'full' mode requires: pip install outclaw[heavy]
```

---

### 📁 Workspace Guard

Keeps file access inside the project directory.

**Protection layers:**

| Layer | What it blocks |
|-------|----------------|
| **Path traversal** | `../` and URL-encoded variants (`%2e%2e%2f`) |
| **Dangerous roots** | `/etc`, `/var`, `/root`, `/proc`, `/sys`, etc. |
| **Sensitive dotfiles** | `~/.ssh`, `~/.aws`, `~/.gnupg`, etc. |
| **Device files** | `/dev/sda`, `/dev/mem`, etc. (allows `/dev/null`) |
| **Null bytes** | Null byte injection in paths |
| **Symlink escape** | Checks symlink targets, not just paths |

```yaml
workspace_guard:
  workspace_root: "."           # the folder the agent works in
  enforce_strict_subpath: false # true = ONLY allow writes inside workspace_root
                                # false = block dangerous paths but allow others
```

---

## Environment Variables

| Variable | Default | What it does |
|----------|---------|--------------|
| `UPSTREAM_BASE_URL` | `https://api.openai.com/v1` | The AI service to proxy to |
| `API_KEY` | (none) | Your API key (passed through to upstream) |
| `OUTCLAW_TOKEN` | (none) | Password-protect the Outclaw proxy |
| `PORT` | `8080` | Port Outclaw listens on |

---

## Example: Strict lockdown config

For high-security environments:

```yaml
mode: strict

network_guard:
  allow_unknown: false
  use_community_list: true
  use_urlhaus: true
  allowed_domains:
    - 'api.openai.com'

workspace_guard:
  enforce_strict_subpath: true
  workspace_root: "/app/workspace"

tool_guard_allowed_commands:
  - 'ls'
  - 'cat'
  - 'grep'

ml_guard: full
```

---

## Example: Permissive config

For development/testing (still protected against known-bad):

```yaml
mode: strict

network_guard:
  allow_unknown: true      # allow unknown domains
  use_urlhaus: true        # but still block known malware

workspace_guard:
  enforce_strict_subpath: false

ml_guard: light
```

---

## Proxy Approval Artifacts

Outclaw runs as a non-interactive proxy. For high-risk actions, use prior authorization artifacts rather than runtime prompts.

See [Proxy Approval Artifacts Spec](proxy-approval-spec.md) for:
- Capability token schema (`X-Outclaw-Capability`)
- Deterministic error contract (`outclaw.approval_required`)
- Retry flow and exception bundle model
