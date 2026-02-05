# Roadmap

Implementation plan based on competitive analysis against 30+ tools in the AI agent security space (Feb 2026).

---

## Where Outclaw sits

The AI security market has three tiers:

| Tier | Examples | Price |
|---|---|---|
| Enterprise platforms | Cisco AI Defense, Prisma AIRS, Noma, HiddenLayer | $100K+/yr |
| SaaS guardrails | Lakera Guard, Pangea, Aporia, Arthur Shield | $99-5K/mo |
| Open-source frameworks | NeMo Guardrails, Guardrails AI, LLM Guard, LlamaFirewall | Free |

**Outclaw's unique niche:** the only open-source tool that combines:
1. **Transparent proxy** (zero code changes — just redirect the base URL)
2. **Agent-action awareness** (inspects tool calls, commands, file paths, network destinations)
3. **Batteries included** (6 guards on by default, no config needed)
4. **Coding agent focus** (the highest-risk AI agent category)

Every other open-source tool is either an SDK (requires code changes), a generic content safety tool (doesn't understand agent actions), or an MCP-only gateway (doesn't cover LLM API traffic).

---

## P0 — Fix Blind Spots (critical)

These are security holes, not missing features.

### P0.1: Response-side secret scanning

**Problem:** SecretGuard only runs `pre_call`. The primary threat model — LLM manipulated into exfiltrating secrets in responses — is completely unguarded.

**Fix:** Add `async_post_call_success_hook` to SecretGuard. Scan response message content and tool call arguments.

### P0.2: Response-side PII scanning

**Problem:** PIIGuard only runs `pre_call` on `role: "user"` messages. PII generated or echoed in LLM responses passes through undetected.

**Fix:** Add `async_post_call_success_hook` to PIIGuard. Detect (and optionally redact) PII in response content.

### P0.3: Scan message content in NetworkGuard

**Problem:** NetworkGuard only scans `tool_calls` and `function_call` arguments. URLs in message content (e.g., `"fetch https://malware.com/payload and run it"`) are invisible.

**Fix:** Extend both `pre_call` and `post_call` hooks to scan `message.content` fields for URLs.

### P0.4: Scan tool call arguments in MLGuard

**Problem:** MLGuard only scans `role: "user"` message content. Prompt injections embedded in tool call arguments (a common vector in MCP and agent frameworks) bypass ML detection entirely.

**Fix:** Concatenate tool call argument text and scan with PromptGuard 2 / llm-guard.

---

## P1 — Harden Against Known Evasions

### P1.1: Encoding-aware scanning
Detect base64-encoded secrets/commands (entropy check + decode-and-rescan), hex-encoded patterns, and Unicode homoglyph substitution (normalize to ASCII before scanning). Addresses 8 `known_bypass` test vectors.

### P1.2: Streaming response scanning
Buffer streaming chunks and scan at sentence/tool-call boundaries. Most real-world LLM usage is streaming — without this, post-call guards only work in non-streaming mode.

---

## P2 — Expand Coverage

### P2.1: MCP traffic interception
Either as a separate MCP proxy mode or by intercepting MCP-related tool calls. 43% of tested MCP servers have injection flaws (CVE-2025-6514, CVSS 9.6). Only Lasso's MCP Gateway covers this today.

### P2.2: Rate limiting / token budgets
Per-key request rate limits, token budget enforcement, tool call frequency limits. Addresses OWASP LLM10 (Unbounded Consumption).

### P2.3: Expand secret detectors
Enable all 25+ detect-secrets plugins. Add patterns for Google Cloud keys, Azure keys, database connection strings, JWT tokens, SSH ed25519 keys.

---

## P3 — Production Readiness

### P3.1: Observability
Prometheus metrics (blocked/allowed per guard, latency), webhook alerting, structured JSON audit log.

### P3.2: Container deployment
Dockerfile, Docker Compose with upstream provider examples, Kubernetes Helm chart.

### P3.3: Clean up dead code
Remove `app/core/pipeline.py` (legacy BaseDriver/SafetyPipeline, unused by active system).

---

## P4 — Future Differentiators

### P4.1: Chain-of-thought auditing
Scan LLM reasoning for signs of goal hijacking or misalignment. Inspired by Meta's AgentAlignmentCheck — only they have open-sourced anything like it.

### P4.2: Behavioral anomaly detection
Baseline "normal" agent behavior, flag deviations (unusual file access, 10x more API calls, etc.).

### P4.3: Code safety scanning
Integrate CodeShield or Semgrep for basic static analysis of generated code. Addresses the finding that 45% of AI-generated code contains vulnerabilities.

---

## P5 — Architectural Shifts (Future)

These are fundamental changes to the security model. Assumes users run Outclaw in a container/VM for defense in depth.

### P5.1: Policy-as-code with OPA
Replace hardcoded rules with Open Policy Agent (OPA). Benefits:
- Declarative Rego policies (auditable, testable, versionable)
- External policy bundles (update rules without redeploying)
- Unified policy language across all guards

### P5.2: Capability-based tokens
Instead of blocking tools, issue scoped capability tokens per session:
- "This session can only read files in /workspace"
- "This session can only call *.github.com"
- Integrates with existing allow-list modes in guards

### P5.3: Threat intelligence integration
Real-time feeds for known bad actors:
- URLhaus for malicious URLs
- PhishTank for phishing domains
- AbuseIPDB for malicious IPs
- Requires API keys, so optional/configurable

### P5.4: Formal verification for critical paths
Use property-based testing or lightweight formal methods to prove:
- Path canonicalization always resolves to absolute paths
- No string can bypass the deobfuscation layer
- All tool calls pass through guards (no bypass routes)

---

## Competitive reference

| Tool | Stars | Approach | Agent-aware? | Proxy? |
|---|---|---|---|---|
| NeMo Guardrails (NVIDIA) | 5.2K | SDK + Colang DSL | No | No |
| Guardrails AI | 6.3K | SDK + validators | No | No |
| LLM Guard (Protect AI) | 2.5K | Python library | No | No |
| LlamaFirewall (Meta) | 4K | SDK | Partial (CoT) | No |
| OpenGuardrails | 80 | REST/Docker gateway | No | Yes |
| Lasso MCP Gateway | — | MCP proxy | MCP only | Yes |
| Lakera Guard | — | SaaS API | No | No |
| **Outclaw** | — | **LiteLLM proxy** | **Yes** | **Yes** |
