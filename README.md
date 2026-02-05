<p align="center">
  🦞🤠 <strong>Outclaw</strong> 🤠🦞<br>
  <em>The shellriff every lobster needs.</em><br>
  <em>Content security for <a href="https://github.com/openclaw/openclaw">OpenClaw</a>.</em>
</p>

---

## What Outclaw does

**Outclaw is the shellriff that rides between your agent and the outside world.** 🤠

It watches everything coming in and going out — and anything that looks like trouble gets stopped at the gate.

```
  You --> Agent --> Outclaw --> AI Service
                    🦞🤠
             watches everything
             stops the bad stuff
             lets the rest ride
```

Your secrets trying to leave town? **Outclawed.** 🔑<br>
A prompt injection sneaking in? **Outclawed.** 🧠<br>
Data heading to a shady domain? **Outclawed.** 🌐

**Six guards riding patrol, all on by default:**

| Guard | What it catches |
|-------|-----------------|
| 🔑 **Secret Guard** | API keys, tokens, credentials about to leak (50+ patterns + entropy detection) |
| 🧠 **ML Guard** | Prompt injection attempts (PromptGuard 2) |
| 🌐 **Network Guard** | Connections to malicious domains (28K+ via URLhaus) |
| 🙈 **PII Guard** | Personal info — emails, SSNs, phones, 30+ entity types |
| 📁 **Workspace Guard** | File access outside the project corral |
| 🛡️ **Tool Guard** | Dangerous shell patterns (defense in depth) |

---

## Quick start

```bash
pip install outclaw
outclaw warmup                                        # download models (~90MB, one time)
UPSTREAM_BASE_URL=https://api.openai.com/v1 outclaw   # start the lobster tank 🦞
# point your agent at localhost:8080. done.
```

**Supported providers:**

| Provider | UPSTREAM_BASE_URL |
|----------|-------------------|
| OpenAI | `https://api.openai.com/v1` |
| Anthropic | `https://api.anthropic.com/v1` |
| Google Gemini | `https://generativelanguage.googleapis.com/v1beta` |
| Groq | `https://api.groq.com/openai/v1` |
| Ollama | `http://127.0.0.1:11434/v1` |

---

## The threat model

AI agents that can run commands, edit files, and fetch URLs are powerful — and exploitable. A prompt injection hidden in a webpage, code comment, or API response can hijack your agent into:

- **Leaking your secrets** — API keys, tokens, credentials sent to an attacker
- **Exfiltrating your code** — proprietary source shipped off to pastebin
- **Exposing your identity** — emails, phone numbers, SSNs riding along in prompts
- **Hitting internal systems** — SSRF attacks against localhost or internal APIs

Even if your agent runs in a sandbox, these data exfiltration attacks still work. The sandbox keeps the agent from wrecking your system — but it doesn't stop the agent from *sending your data out the door*.

Outclaw watches that door. 🚪🦞

---

## How it fits with OpenClaw

OpenClaw gives you access controls: sandboxing, tool policies, allowlists. Those control **who** can act and **where**.

Outclaw inspects **what** is being sent and received. Even with perfect access controls, untrusted content can slip in through web fetches, pasted code, or attachments.

OpenClaw is the bouncer at the door. Outclaw is the sheriff inside. 🦞🤠

---

## Configuration

Outclaw works out of the box — batteries included. To customize:

```bash
outclaw init    # creates config.yaml
```

Key settings:

```yaml
mode: strict    # strict (block) or audit (log only)

network_guard:
  allow_unknown: false          # block domains not in Tranco top 10K
  use_urlhaus: true             # 28K+ malicious domains, auto-refreshed

workspace_guard:
  enforce_strict_subpath: false # true = only allow writes inside workspace_root

ml_guard: light                 # light (PromptGuard 2) or full (llm-guard suite)
```

> **Getting false positives?** Set `allow_unknown: true` to only block known-bad domains.

See [docs/configuration.md](docs/configuration.md) for the full rulebook.

---

## Learn more

- 🔧 **[Configuration](docs/configuration.md)** — customize guards and tune protections
- 🔒 **[Security](SECURITY.md)** — threat model, limitations, and hardening
- ⚙️ **[Architecture](docs/how-it-works.md)** — how each guard works under the hood
- 🗺️ **[Roadmap](docs/roadmap.md)** — what's coming next

## License

MIT — see [LICENSE](LICENSE).

---

> *"There's a new shellriff in town. And never trust a lobster outside its shell."* 🦞🤠
