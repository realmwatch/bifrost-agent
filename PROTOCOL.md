# Protocol

The contract between the hub, the agent and the approver app. Version 1. Both repositories keep a copy of this file; change both together.

All JSON is UTF-8. Times are RFC 3339 UTC (`2026-11-01T00:00:00Z`). `b64u` means base64url without padding. Ids are ULIDs unless noted.

## Transport (v1)

The agent makes HTTPS requests to the hub; the hub never connects to the agent. The agent polls for work every few seconds (`poll_interval`, default 5s) and sends a heartbeat every 60s. A WebSocket channel and mTLS can replace polling later without changing any payload below.

- Base path: `{hub}/api/agent/v1`.
- Auth: `Authorization: Bearer <agent token>`, issued once at enrollment. The hub stores only its SHA-256.
- Errors: non-2xx with `{"error": "<code>", "message": "..."}`. `401` means the token is revoked: the agent stops and logs it.

### `POST /enroll` (no bearer)

```json
{
  "enrollment_key": "bfe_...",
  "machine_id": "<contents of /etc/machine-id>",
  "hostname": "web-01",
  "os": {"id": "ubuntu", "version_id": "24.04", "pretty_name": "Ubuntu 24.04.1 LTS"},
  "agent_version": "0.1.0",
  "operations": ["package.upgrade@1", "service.restart@1"]
}
```

Response `201`: `{"agent_id": "...", "server_id": "...", "token": "bfa_..."}`. Enrollment keys belong to an organization; the hub creates or links the `Server` by machine id within that organization.

### `POST /heartbeat`

```json
{
  "agent_version": "0.1.0",
  "operations": ["package.upgrade@1"],
  "facts": {
    "hostname": "web-01",
    "os": {"id": "ubuntu", "version_id": "24.04", "pretty_name": "..."},
    "kernel": "6.8.0-45-generic",
    "uptime_seconds": 12345,
    "package_manager": "apt"
  }
}
```

Response `200`: `{"ok": true}`.

### `GET /work`

Response `200`:

```json
{
  "executions": [
    {
      "id": "<execution id>",
      "envelope": "<b64u of the envelope bytes>",
      "approvals": [ /* see Approvals */ ]
    }
  ],
  "queries": [
    {"id": "<query id>", "tool": "service_status", "args": {"unit": "nginx.service"}}
  ]
}
```

The hub hands out each execution and query once; it marks them `dispatched` when returned.

### `POST /executions/{id}/events`

Body: `{"events": [ {event}, ... ]}`, in order. Each event has `seq` (per execution, from 1), `at`, `type` and type-specific fields:

| `type` | Fields |
| --- | --- |
| `verified` | — |
| `rejected` | `reason`: why the agent refused to run it (bad signature, expired, wrong host, replayed nonce, unknown operation, denied by agent rule) |
| `step_started` | `phase`: `operations` or `rollback`; `index`; `op` (`name@version`); `argv` (the exact argument list) |
| `output` | `phase`, `index`, `stream` (`stdout` or `stderr`), `data` (text chunk) |
| `step_finished` | `phase`, `index`, `exit_code`, `duration_ms` |
| `health` | `index`, `ok`, `detail` |
| `files_written` | `index`, `files`: `[{"path": "...", "sha256": "..."}]` |
| `finished` | `result`: `succeeded`, `failed`, `rolled_back` or `rejected`; `before` and `after` (optional state snapshots) |

The agent batches events and sends at least every second while running.

### `POST /queries/{id}/result`

`{"ok": true, "result": { ... }}` or `{"ok": false, "error": "..."}`. Results are redacted on the agent before sending.

## State tools

Read-only. Unknown tools or bad args return `ok: false`.

| Tool | Args | Result |
| --- | --- | --- |
| `os` | — | `/etc/os-release` fields, kernel, uptime, machine id, hostname |
| `packages` | `names` (optional list) | `[{"name", "version", "arch"}]` |
| `pending_updates` | — | `[{"name", "current", "candidate", "security": bool}]` |
| `service_status` | `unit` | `{"unit", "active_state", "sub_state", "load_state", "unit_file_state", "since"}` |
| `journal` | `unit`, `lines` (≤ 500, default 100) | `{"lines": ["..."]}` |
| `disk` | — | `[{"mount", "fs", "size_bytes", "used_bytes", "avail_bytes"}]` |
| `memory` | — | `{"total_bytes", "available_bytes", "swap_total_bytes", "swap_free_bytes"}` |
| `ports` | — | `[{"proto", "address", "port", "process"}]` |
| `sessions` | — | `[{"user", "tty", "from", "since"}]` |

## Operations catalog

The agent repository's `operations/*.json` is the source of truth: one file per `name@version`. `bifrost-agent operations export` prints the hub-facing catalog, which the hub pins at `resources/operations/catalog.json`:

```json
{
  "catalog_version": "0.1.0",
  "operations": [
    {
      "name": "package.upgrade",
      "version": 1,
      "description": "Upgrade one installed package to a given version.",
      "min_tier": "medium",
      "params": { /* JSON Schema, type object */ },
      "dry_run": true,
      "rollback": "package.install",
      "irreversible": false,
      "health_check": "The package is installed at the requested version.",
      "files_written": []
    }
  ]
}
```

The agent-only part of each definition adds `argv` per package manager (`apt`, `dnf`), with `{param}` placeholders that each fill exactly one argument and are never passed to a shell, plus `dry_run_argv` and `sudo`. Every parameter must match its schema (types, `pattern`, `enum`, `maxLength`) on both sides before use.

Risk tiers, lowest first: `low`, `medium`, `high`, `critical`.

## Envelope

The thing that gets approved. The hub builds it once, when a proposal reaches `awaiting_approval`, and stores the exact bytes. The approver app and the agent both work from those bytes, never from a re-serialization, so no canonical JSON is needed across languages.

```json
{
  "v": 1,
  "kind": "bifrost.envelope",
  "proposal_id": "01J...",
  "organization_id": "01J...",
  "hosts": [{"server_id": "01J...", "name": "web-01", "machine_id": "..."}],
  "operations": [
    {"op": "package.upgrade", "version": 1, "params": {"name": "openssl", "to": "3.0.13-0ubuntu3.4"}}
  ],
  "rollback": [
    {"op": "package.install", "version": 1, "params": {"name": "openssl", "version": "3.0.13-0ubuntu3.1"}}
  ],
  "irreversible": false,
  "intent": "Fix CVE-2026-1234 in openssl on web-01",
  "risk_tier": "medium",
  "not_before": null,
  "expires_at": "2026-11-01T00:00:00Z",
  "nonce": "<32 random bytes, hex>"
}
```

`hash = SHA-256(envelope bytes)`. `intent` and `risk_tier` are the hub's words: the approver app labels them as such, and the agent ignores them.

## Approvals

Each item in `approvals`:

```json
{"kind": "passkey", "key_id": "<b64u credential id>", "authenticator_data": "<b64u>", "client_data_json": "<b64u>", "signature": "<b64u>"}
{"kind": "policy", "key_id": "<policy key id>", "signature": "<b64u Ed25519 signature over the envelope bytes>"}
```

### Passkey signatures

The approver app calls `navigator.credentials.get` with `challenge = hash` and `userVerification: "required"`. A passkey approval is valid when, for a trusted passkey key with that `key_id`:

1. `client_data_json` parses with `type == "webauthn.get"`, `challenge == b64u(hash)`, and `origin` equal to the trusted key's `origin`.
2. `authenticator_data[0:32] == SHA-256(rp_id)`, and its flags have user presence (`0x01`) and user verification (`0x04`).
3. `signature` verifies over `authenticator_data || SHA-256(client_data_json)` with the key's algorithm: ES256 (COSE `-7`, ASN.1 ECDSA P-256 with SHA-256), EdDSA (`-8`, Ed25519) or RS256 (`-257`, PKCS#1 v1.5 with SHA-256).

## Trusted keys

The agent reads its trusted keys from a local file (default `/etc/bifrost-agent/trusted-keys.json`, root-owned, read-only to the agent's user). An admin installs it; the hub can't change it. The hub's admin UI exports this file for an organization.

```json
{
  "v": 1,
  "keys": [
    {"kind": "passkey", "key_id": "<b64u credential id>", "owner": "user:01J...", "label": "Alex's phone", "alg": -7, "public_key": "<b64u SPKI DER>", "rp_id": "approve.example.com", "origin": "https://approve.example.com"},
    {"kind": "policy", "key_id": "policy-1", "public_key": "<b64u raw 32-byte Ed25519 key>"}
  ]
}
```

## What the agent checks before running

In order; the first failure is a `rejected` event and nothing runs.

1. The envelope parses, `v == 1`, `kind == "bifrost.envelope"`.
2. Its own machine id is in `hosts`.
3. Now is after `not_before` (if set) and before `expires_at`.
4. The nonce hasn't been seen (the agent keeps seen nonces until their envelope expires).
5. Every operation and rollback step is compiled into this agent, and its params match the schema.
6. No operation hits a deny rule compiled into the agent.
7. Approvals satisfy the agent's own rules, with the tier taken from the agent's compiled `min_tier` of each operation (never the envelope's `risk_tier`):
   - at least one valid passkey approval, from a key in the trusted file;
   - `critical`: valid passkey approvals from two different `owner`s;
   - a policy approval alone is enough only if every operation is in the agent's compiled auto-approval list.

Then it runs the operations in order. If one fails or its health check fails, it runs the rollback steps (if any) and reports `rolled_back`, otherwise `failed`.

## Approver app ↔ hub

The approver app is static and has no session with the hub. The hub gives it temporary signed URLs, opened as `{approver}/#register=<url-encoded signed URL>` or `{approver}/#approve=<url-encoded signed URL>`. The hub allows CORS from the approver origin on `/api/approver/v1/*`.

### Registering a passkey

`GET <signed register URL>` returns:

```json
{
  "rp": {"id": "approve.example.com", "name": "Bifrost"},
  "user": {"id": "<b64u stable user handle>", "name": "alex@example.com", "display_name": "Alex"},
  "challenge": "<b64u>",
  "exclude_credentials": ["<b64u>"],
  "complete_url": "<signed URL>"
}
```

The app calls `navigator.credentials.create` (`pubKeyCredParams` ES256, EdDSA, RS256; `residentKey: "preferred"`; `userVerification: "required"`), then `POST complete_url`:

```json
{"credential_id": "<b64u>", "public_key": "<b64u SPKI DER from response.getPublicKey()>", "alg": -7, "client_data_json": "<b64u>", "authenticator_data": "<b64u>", "transports": ["internal"], "label": "Alex's phone"}
```

The hub checks the challenge, `type == "webauthn.create"` and the origin, then stores the credential.

### Approving

`GET <signed approve URL>` returns:

```json
{
  "proposal_id": "01J...",
  "envelope": "<b64u envelope bytes>",
  "rp_id": "approve.example.com",
  "allow_credentials": ["<b64u>"],
  "hub_context": {"intent": "...", "source": "heimdall", "reviews": [{"layer": "system1", "verdict": "...", "summary": "..."}]},
  "submit_url": "<signed URL>"
}
```

The app decodes the envelope bytes, renders the hosts, operations, parameters, rollback and expiry from those bytes, shows `hub_context` second and labelled as the hub's, computes the hash from the same bytes, calls `navigator.credentials.get`, and `POST submit_url` with `{"key_id", "authenticator_data", "client_data_json", "signature"}`. The hub verifies it the same way the agent does and records the approval.
