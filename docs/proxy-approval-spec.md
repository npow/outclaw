# Proxy Approval Artifacts Spec

This spec defines a non-interactive approval model for Outclaw when running purely as an HTTP proxy.

Outclaw cannot pause and ask a user for runtime approval. High-risk actions must be authorized ahead of time using signed artifacts that the proxy can verify.

## Goals

- Keep the proxy non-interactive and deterministic.
- Avoid broad, long-lived allowlist changes.
- Allow narrowly scoped temporary approvals for high-risk operations.
- Make all approvals auditable and revocable.

## Non-goals

- Human-in-the-loop UI prompts.
- Persistent global bypass flags.
- Implicit trust from prompt text.

## Terms

- Risk class: normalized category derived from guard decisions (`network.unknown_domain`, `workspace.sensitive_path`, etc.).
- Approval artifact: signed token or bundle proving prior authorization.
- Decision ID: unique ID for each Outclaw enforcement decision.

## Approval Model

Outclaw supports three artifact types:

1. Capability token (single-session, short TTL)
- Best for one-off high-risk actions.
- Attached per request in header.

2. Exception bundle (batched policy exceptions, short TTL)
- Best for controlled rollout windows.
- Signed by policy control plane and loaded by proxy.

3. Elevated API key / endpoint split
- Best for separate privileged automation path.
- Uses dedicated credentials and stricter audit thresholds.

## Artifact Format

Capability token payload (JWT/PASETO equivalent):

```json
{
  "iss": "outclaw-policy",
  "sub": "agent:build-bot",
  "aud": "outclaw-proxy",
  "jti": "cap_01J...",
  "iat": 1735600000,
  "exp": 1735600300,
  "tenant_id": "tnt_123",
  "session_id": "sess_abc",
  "risk_classes": [
    "network.unknown_domain",
    "workspace.outside_root_write"
  ],
  "constraints": {
    "domains": ["api.vendor.com"],
    "paths": ["/workspace/tmp/release-notes.md"],
    "tools": ["write_file"],
    "max_uses": 1
  }
}
```

Required verification checks:

- Signature valid and key not revoked.
- `aud`, `tenant_id`, `session_id` match request context.
- `exp` still valid.
- Requested action in `risk_classes`.
- Action-specific constraints match normalized decision evidence.
- `max_uses` not exceeded (server-side counter).

## Request Contract

Headers:

- `Authorization: Bearer <outclaw_master_or_tenant_key>`
- `X-Outclaw-Capability: <signed_token>` (optional; required for high-risk allow)
- `X-Outclaw-Session-Id: <session_id>` (required when capability token used)
- `X-Outclaw-Intent-Id: <client_generated_id>` (recommended for retries/idempotency)

Behavior:

- If no high-risk decision: process normally.
- If high-risk decision and valid capability exists: allow and log `approved=true`.
- If high-risk decision and no valid capability: block with deterministic error payload.

## Block Response Contract

HTTP status:

- `403` for policy denial (preferred)
- `400` for malformed risk context/capability (validation)

Body:

```json
{
  "error": {
    "type": "security_error",
    "code": "outclaw.approval_required",
    "message": "High-risk action requires prior authorization artifact.",
    "decision_id": "dec_01J...",
    "risk_class": "network.unknown_domain",
    "guard": "NetworkGuard",
    "rule_id": "network-unknown-domain",
    "remediation": {
      "action": "provide_capability",
      "header": "X-Outclaw-Capability",
      "constraints": {
        "domains": ["api.vendor.com"],
        "ttl_max_seconds": 900,
        "max_uses": 1
      }
    }
  }
}
```

Required properties:

- Stable `code` for machine handling.
- `decision_id` for incident/audit correlation.
- Exact minimal constraints needed to succeed safely.

## Retry Flow

1. Client sends request without capability token.
2. Outclaw blocks with `outclaw.approval_required`.
3. Client requests capability token from policy service (out-of-band).
4. Client retries same request with `X-Outclaw-Capability`.
5. Outclaw validates token, allows once, emits approval event.

Rules:

- Same `X-Outclaw-Intent-Id` should be reused across retries.
- Capability token should be single-use by default.

## Exception Bundle Contract

Bundle payload:

```json
{
  "bundle_id": "exb_01J...",
  "tenant_id": "tnt_123",
  "issued_at": 1735600000,
  "expires_at": 1735603600,
  "exceptions": [
    {
      "risk_class": "network.unknown_domain",
      "domains": ["api.vendor.com"]
    }
  ],
  "signature": "..."
}
```

Loading model:

- Proxy polls signed bundles from control plane.
- Bundle cache keyed by `tenant_id`.
- Expired bundles auto-removed.

Safety constraints:

- Max bundle TTL enforced server-side.
- Wildcards forbidden for high-risk classes.
- Bundle changes are append-only audited events.

## Elevated Path Contract

Optional split:

- `/v1/chat/completions` -> standard key, strict default policy.
- `/v1/high-risk/chat/completions` -> elevated key required, stricter logging and rate limits.

Use cases:

- CI release jobs.
- Controlled migrations.
- Security-reviewed maintenance tasks.

## Error Code Taxonomy

Required initial codes:

- `outclaw.approval_required`
- `outclaw.capability_invalid`
- `outclaw.capability_expired`
- `outclaw.capability_scope_mismatch`
- `outclaw.capability_use_exhausted`
- `outclaw.exception_bundle_missing`
- `outclaw.exception_bundle_expired`

## Audit Events

Emit structured event for each high-risk decision:

```json
{
  "event_type": "security.decision",
  "decision_id": "dec_01J...",
  "tenant_id": "tnt_123",
  "session_id": "sess_abc",
  "risk_class": "network.unknown_domain",
  "guard": "NetworkGuard",
  "rule_id": "network-unknown-domain",
  "decision": "BLOCK",
  "approved": false,
  "capability_id": null,
  "intent_id": "intent_456",
  "timestamp": "2026-02-26T18:00:00Z"
}
```

If approved:

- `decision: "ALLOW"`
- `approved: true`
- `capability_id` populated.

## Minimum Implementation Plan

1. Add stable error schema and decision IDs.
2. Add capability verifier interface in proxy request pipeline.
3. Add `X-Outclaw-Capability` parsing and verification.
4. Add single-use token replay protection.
5. Add audit event emission with approval metadata.
6. Add signed exception bundle loader with TTL enforcement.
7. Add endpoint split + elevated key path (optional).

## Security Invariants

- No high-risk allow without valid artifact.
- Artifact scope must be narrower than the blocked action, never broader.
- Expired/revoked artifacts fail closed.
- Every approval must be attributable and replayable from logs.

