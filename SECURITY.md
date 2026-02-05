# 🔒 Security

Outclaw is one layer of defense — not the only one you need. Here's an honest look at what it covers, what's coming, and what you need to handle yourself.

As [OpenClaw's security docs](https://docs.openclaw.ai/gateway/security) put it: *"There is no 'perfectly secure' setup."* The goal is deliberate, layered defense. Outclaw is the content inspection layer.

## What Outclaw covers

Outclaw inspects traffic between Molty and the AI service. It catches:

- 🔑 **Secrets in transit** — API keys, tokens, credentials being sent to the AI
- 🙈 **PII in transit** — emails, SSNs, phone numbers being included in prompts
- 🛡️ **Dangerous tool calls** — destructive commands, reverse shells, privilege escalation
- 📁 **Workspace escape** — tool calls trying to write outside the project folder
- 🌐 **Data exfiltration** — connections to unknown or malicious domains
- 🧠 **Prompt injection** — ML-based detection of adversarial instructions

## What Outclaw doesn't cover

### On the roadmap 🗺️

These are things Outclaw *could* do and we plan to build:

| Gap | What can go wrong | Status |
|---|---|---|
| **Stealth exfiltration** | An attacker encodes your secrets into git commit messages, base64 strings in URLs, or paraphrases credentials in plain English. These slip through because they use legitimate channels. | Planned |
| **Per-tool permissions** | Outclaw blocks dangerous command *patterns*, but can't say "this tool should only read files, never write." A compromised Molty could misuse a tool in ways that don't match known bad patterns. | Planned |
| **Behavioral anomaly detection** | If Molty suddenly starts accessing unusual files or making 10x more API calls, Outclaw won't notice. There's no baseline of "normal" to compare against. | Planned |
| **Instruction file integrity** | If someone tampers with Molty's config files (like `.cursorrules` or `CLAUDE.md`), Outclaw won't detect it. These files shape Molty's behavior and are a real attack surface. | Planned |

### Out of scope 🦞

These are things a content inspection proxy fundamentally can't solve. You need other tools — and OpenClaw already has most of them built in.

---

**Credential storage.** Outclaw catches secrets *in transit*, but if your API keys sit in a plaintext `.env` file in the workspace, any shell command Molty runs can read them — no network request needed, nothing for Outclaw to intercept.

What to do instead: keep secrets out of your workspace. In OpenClaw, sandbox Molty and restrict filesystem access:

```yaml
agents:
  defaults:
    sandbox:
      mode: "all"
      workspaceAccess: "ro"    # Molty can't modify or snoop around the filesystem
```

See: [OpenClaw docs — Secrets & sensitive data](https://docs.openclaw.ai/gateway/security#secrets--sensitive-data-management)

---

**Filesystem permissions.** Outclaw blocks Molty from *writing* outside its workspace via AI tool calls. But any shell command Molty runs has your full user permissions — `cat ~/.ssh/id_rsa` doesn't go through Outclaw.

What to do instead: use OpenClaw's built-in Docker sandboxing. Every command runs inside a container, isolated from your host:

```yaml
agents:
  defaults:
    sandbox:
      mode: "all"              # sandbox everything
      scope: "agent"           # each agent gets its own container
    tools:
      deny: ["browser", "process"]   # restrict what tools Molty can use
```

Run `openclaw security audit --fix` to auto-tighten permissions.

See: [OpenClaw docs — Sandboxing](https://docs.openclaw.ai/gateway/security#sandboxing-architecture)

---

**Adaptive prompt injection.** Outclaw's ML Guard catches many prompt injection attempts, but as OpenClaw's own docs state: *"Even with strong system prompts, prompt injection is not solved."* No single guardrail guarantees 100% detection. Determined attackers can evade ML-based detection with enough attempts.

What to do instead: defense in depth. Use Outclaw as one layer, and also:

- **Sandbox everything** so a successful injection can't do real damage
- **Restrict tools** to the minimum needed (`tools.deny` / `tools.allow`)
- **Use `requireMention: true`** in group chats so Molty ignores unsolicited messages
- **Use the strongest model available** — weaker models are significantly easier to manipulate
- **Treat all external content as untrusted** — web fetches, browser pages, pasted code, attachments

See: [OpenClaw docs — Prompt injection](https://docs.openclaw.ai/gateway/security#prompt-injection--content-attacks)

---

**Access control.** Outclaw doesn't manage who can talk to Molty. That's OpenClaw's job — DM pairing, channel allowlists, group policies.

See: [OpenClaw docs — DM security model](https://docs.openclaw.ai/gateway/security#dm-security-model)

## The full picture

OpenClaw's defense-in-depth model has three layers:

1. **Identity & access** — who can talk to Molty (DM pairing, allowlists)
2. **Scope control** — where Molty can act (sandbox, tool policies, permissions)
3. **Model robustness** — assume the model can be manipulated, limit blast radius

Outclaw adds a fourth:

4. **Content inspection** — what is actually being sent and received (secrets, PII, injections, exfiltration)

No single layer is enough. Together, they make your lobster much harder to crack. 🦞🤠

## Reporting vulnerabilities

If you find a security issue in Outclaw, please open a GitHub issue or email the maintainers directly. We take these seriously.
