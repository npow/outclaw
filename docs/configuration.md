# Configuration

Outclaw works out of the box with zero configuration. If you want to customize it, edit `config.yaml`:

```yaml
mode: strict       # strict = block threats, audit = log only

drivers:
  tool_guard: true       # dangerous commands
  workspace_guard: true  # file system escape
  network_guard: true    # data exfiltration
  secret_guard: true     # API key leaks
  pii_guard: true        # personal info leaks
  llm_guard: true        # prompt injection (ML-based)
```

## Guards

<details>
<summary>Network Guard — control which websites the agent can access</summary>

```yaml
network_guard:
  allow_unknown: false             # block websites not on any list
  use_community_list: true         # auto-allow top 10,000 popular websites
  allowed_domains:
    - 'localhost'
    - 'api.openai.com'
  blocked_domains:
    - 'pastebin.com'
    - 'ngrok.io'
```
</details>

<details>
<summary>Workspace Guard — control where the agent can write files</summary>

```yaml
workspace_guard:
  workspace_root: "."              # the folder the agent is allowed to work in
  enforce_strict_subpath: false    # when true, blocks ALL writes outside workspace_root
```
</details>

<details>
<summary>Tool Guard — customize which commands are blocked</summary>

```yaml
tool_guard_blocklist:
  - 'rm\s+-[rRf]+'      # recursive delete
  - 'bash\s+-i'          # interactive bash (reverse shell)
  - '\bssh\b'            # SSH connections
  # see config.yaml for the full list
```
</details>

<details>
<summary>PII Guard — choose which personal info to scrub</summary>

```yaml
pii_redact:
  - email
  - phone_us
  - ssn
```
</details>

## Environment variables

| Variable | Default | What it does |
|---|---|---|
| `UPSTREAM_BASE_URL` | `https://api.openai.com/v1` | The AI service to connect to |
| `API_KEY` | (none) | Your API key for the AI service (Outclaw passes it through) |
| `OUTCLAW_TOKEN` | (none) | Password-protect the Outclaw proxy itself |
| `PORT` | `8080` | Port Outclaw listens on |
