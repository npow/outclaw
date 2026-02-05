<p align="center">
  🦞🤠 <strong>Outclaw</strong> 🤠🦞<br>
  <em>The shellriff every lobster needs.</em><br>
  <em>Content security for <a href="https://github.com/openclaw/openclaw">OpenClaw</a>.</em>
</p>

---

## The problem

Molty can run commands, edit files, and access the internet. That's what makes Molty useful. It's also what makes Molty *dangerous*. 🌶️

A prompt injection — hidden instructions in a webpage, a comment in code, a crafted API response — can hijack Molty into:

- **Deleting your files** (`rm -rf /`)
- **Stealing your API keys** and sending them to an attacker's server
- **Opening a backdoor** on your machine (reverse shells)
- **Leaking your personal information** — emails, passwords, credit card numbers — to the AI provider
- **Downloading and running malware** from the internet

These aren't hypothetical. They happen today. Even if Molty's access controls are locked down, a single piece of untrusted content — a web page, a pasted log, an email attachment — can slip past the front door.

## The fix

**Outclaw is the shellriff that rides between Molty and the outside world.** 🤠 It watches everything coming in and going out — and anything that looks like trouble gets stopped at the gate.

Your secrets trying to leave town? **Outclawed.** 🔑<br>
A prompt injection sneaking in? **Outclawed.** 🧠<br>
A destructive command about to fire? **Outclawed.** 🛡️

```bash
pip install outclaw
outclaw warmup                                        # download security models (one time)
UPSTREAM_BASE_URL=https://api.openai.com/v1 outclaw   # start the lobster tank 🦞
# point your agent at localhost:8080. done.
```

Six security checks. Every request. Every response. If it's clean, it rides through. If it's not — well, there's a new shellriff in town. 🤠

```
  You --> Molty --> Outclaw --> AI Service
                    🦞🤠
             watches everything
             stops the bad stuff
             lets the rest ride
```

### How it fits with OpenClaw

OpenClaw already gives you strong controls: sandboxing, tool policies, DM pairing, allowlists. Those control **who** can talk to Molty and **where** Molty can act.

Outclaw adds a different layer — it inspects **what** is actually being sent and received. Even with perfect access controls, untrusted content can still sneak in through web fetches, browser pages, pasted code, or attachments. Outclaw catches that stuff.

OpenClaw is the bouncer at the door. Outclaw is the shellriff inside. 🦞🤠

---

## Quick start

### 1. Install

```bash
pip install outclaw
outclaw warmup        # downloads security models (~90MB, one time)
```

### 2. Start Outclaw

Tell Outclaw which AI service Molty uses:

| AI Service | Command |
|---|---|
| OpenAI | `UPSTREAM_BASE_URL=https://api.openai.com/v1 outclaw` |
| Anthropic | `UPSTREAM_BASE_URL=https://api.anthropic.com/v1 outclaw` |
| Google Gemini | `UPSTREAM_BASE_URL=https://generativelanguage.googleapis.com/v1beta outclaw` |
| Groq | `UPSTREAM_BASE_URL=https://api.groq.com/openai/v1 outclaw` |
| Ollama (local) | `UPSTREAM_BASE_URL=http://127.0.0.1:11434/v1 outclaw` |

### 3. Point Molty at Outclaw

Tell Molty to route through Outclaw. You can either run the config command yourself:

```bash
openclaw config set models.providers.openai.baseUrl http://localhost:8080/v1
```

Or just ask Molty to do it:

> *"Update your OpenAI provider base URL to `http://localhost:8080/v1` so requests go through the Outclaw security proxy."*

Restart the gateway to apply, and you're done. Molty works exactly like before — but now every request rides through the shellriff first. 🤠🦞

---

## What it protects against

Six guards riding patrol, all on by default. Batteries included — no configuration needed.

| Protection | What it stops | Example |
|---|---|---|
| 🛡️ **Dangerous commands** | Blocks destructive shell commands, reverse shells, privilege escalation | Molty told to run `rm -rf /` or open a backdoor |
| 📁 **File system escape** | Keeps Molty inside its project folder | Molty told to write to `/etc/passwd` or `~/.ssh/authorized_keys` |
| 🌐 **Data exfiltration** | Blocks connections to unknown or malicious websites | Molty told to send your code to `pastebin.com` |
| 🔑 **Secret leaks** | Catches API keys, tokens, and credentials before they leave your machine | Your `.env` file contents about to be sent to the AI |
| 🙈 **Personal info leaks** | Scrubs emails, SSNs, phone numbers, and 30+ types of personal data | Your real name and email about to be included in a prompt |
| 🧠 **Prompt injection** | Detects attempts to manipulate Molty into doing harmful things | Malicious instructions hidden in a webpage Molty reads |

---

## Learn more

- 🔧 **[Configuration](docs/configuration.md)** — customize guards, set environment variables, tune each protection
- 🔒 **[Security](SECURITY.md)** — what Outclaw doesn't cover, roadmap, and hardening your setup
- ⚙️ **[How it works](docs/how-it-works.md)** — technical architecture and what each guard does under the hood
- 🧑‍💻 **[Development](docs/development.md)** — building from source and running tests

## License

MIT — see [LICENSE](LICENSE).

---

> *"There's a new shellriff in town. And never trust a lobster outside its shell."* 🦞🤠
