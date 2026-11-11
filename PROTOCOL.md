# Protocol

The contract between the hub, the agent and the approver app. Version 1. The `bifrost-hub`, `bifrost-agent` and `bifrost-approver` repositories each keep a copy of this file; change all three together.

All JSON is UTF-8. Times are RFC 3339 UTC (`2026-11-01T00:00:00Z`). `b64u` means base64url without padding. Ids are ULIDs unless noted.

## Transport (v1)

The agent makes HTTPS requests to the hub; the hub never connects to the agent. The agent polls for work every few seconds (`poll_interval`, default 5s) and sends a heartbeat every 60s. A WebSocket channel and mTLS can replace polling later without changing any payload below.

- Base path: `{hub}/api/agent/v1`.
- Auth: `Authorization: Bearer <agent token>`, issued once at enrollment. The hub stores only its SHA-256.
- Errors: non-2xx with `{"error": "<code>", "message": "..."}`. Codes: `401 unauthorized` (unknown token) and `401 revoked`, on which the agent stops and logs it; `403 invalid_enrollment_key`; `409 server_already_enrolled`, on which the agent stops trying to enroll and logs it; `404` for an execution or query that isn't this agent's or wasn't dispatched; `422 validation_failed` with an extra `errors` object.

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

Enrolling never silently takes over a server:

- A new machine id, or a server whose agents are all revoked, enrolls with any usable key of the organization.
- A server that has an active agent is refused with `409 server_already_enrolled`, unless the key is a **re-enrollment key** for that server. The hub logs the refused attempt (`enroll_refused`, with the key, hostname and address) and notifies the organization's admins, at most once an hour per server.
- A re-enrollment key is issued by an admin from the server's page in the hub (or `bifrost:enrollment-key {org} {name} --server=web-01`). It is single-use, expires after an hour (`BIFROST_AGENT_REENROLL_KEY_TTL`, minutes), and is refused (`403 invalid_enrollment_key`) for any other machine id. Enrolling with it revokes the server's previous agent, is logged as `replaced` with the revoked agent ids, and notifies the admins.

Creating an enrollment key in the hub shows the commands that use it: one line that downloads `install.sh` from the agent's GitHub release (`BIFROST_AGENT_RELEASE`, default `v0.3.0`) and runs it with `--hub`, the organization's trusted keys (`--trusted-keys-b64`) and `--enroll`, which asks for the key; an SSH loop that pipes the key to `--enroll-stdin`; and cloud-init user data, the only one that contains the key. `install.sh` checks the release's signature and checksums before installing. A re-enrollment key comes with `bifrost-agent enroll --key-stdin --force` instead, since `install.sh` keeps an enrolled agent's identity.

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
    "package_manager": "apt",
    "boot_id": "8a1c2f3e-...",
    "reboot_required": "no",
    "collector_version": "0.5.5"
  },
  "trusted_keys_serial": 3
}
```

`boot_id` changes on every boot; the hub uses it to check a reboot happened. `reboot_required` is `"yes"` or `"no"` on apt systems (`/run/reboot-required`) and left out elsewhere. Agents before v0.3.0 leave both out. `collector_version` is the Heimdall collector installed on the server, read from its script (v0.5.0); it's left out when there is none.

`trusted_keys_serial` is the `serial` of the key set the agent trusts now (see [Trusted keys](#trusted-keys)), `0` for a file without one. Agents before v0.2.0 leave it out.

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
  ],
  "keysets": [
    {"keyset": "<b64u of the key set bytes>", "approvals": [ /* passkey approvals, see Approvals */ ]}
  ]
}
```

`keysets` holds the organization's approved key set updates with a `serial` above the one the agent last reported in a heartbeat, oldest first; it is empty when the agent is current or has never reported a serial. Serial 1 is never sent: nothing signs it. The agent applies them in order before running anything else in the response, then sends a heartbeat so the hub sees the new serial.

The hub hands out each execution and query once; it marks them `dispatched` when returned. It holds an execution back until the proposal's `not_before` has passed (the agent refuses an early envelope anyway, see below), so a scheduled proposal stays `approved` and is handed out on the first poll after that time.

Each dispatched execution gets a deadline: the dispatch time, plus a grace period (`BIFROST_EXECUTION_GRACE`, default 300 s), plus each operation and rollback step's `timeout_seconds` from the catalog, or `BIFROST_EXECUTION_STEP_TIMEOUT` (default 900 s) for a step without one. A one-step proposal with a one-step rollback therefore has 35 minutes. An execution that hasn't reported `finished` or `rejected` by its deadline is marked `timed_out` by the hub, which records a hub event with `seq` 0 (agents number theirs from 1), fails the proposal, cancels the hosts still waiting and notifies the approvers. A queued execution still not picked up when its running proposal expires times out the same way. Events the agent sends after that are accepted and stored, but never change the execution's or the proposal's state.

### `POST /executions/{id}/events`

Body: `{"events": [ {event}, ... ]}`, in order. Each event has `seq` (per execution, from 1), `at`, `type` and type-specific fields:

| `type` | Fields |
| --- | --- |
| `verified` | — |
| `rejected` | `reason`: why the agent refused to run it (bad signature, expired, wrong host, replayed nonce, unknown operation, denied by agent rule) |
| `step_started` | `phase`: `operations` or `rollback`; `index`; `op` (`name@version`); `argv` (the exact argument list) |
| `output` | `phase`, `index`, `stream` (`stdout` or `stderr`), `data` (text chunk) |
| `step_finished` | `phase`, `index`, `exit_code`, `duration_ms` |
| `health` | `phase`, `index`, `ok`, `detail`; for an operation that reboots, `boot_id` (the boot ID before the reboot) |
| `files_written` | `index`, `files`: `[{"path": "...", "sha256": "..."}]` |
| `finished` | `result`: `succeeded`, `failed`, `rolled_back` or `rejected`; `before` and `after` (optional state snapshots) |

The agent batches events and sends at least every second while running. Ingestion is idempotent by `seq`. Response `200`: `{"ok": true, "accepted": <count of new events>}`.

`rolled_back` means every rollback step and its health check succeeded; if a rollback step fails the result is `failed`. Executions handed to an agent that shuts down before starting them are reported `rejected` with reason `agent shut down before running it`.

### `POST /queries/{id}/result`

`{"ok": true, "result": { ... }}` or `{"ok": false, "error": "..."}`. Results are redacted on the agent before sending.

## State tools

Read-only. Unknown tools or bad args return `ok: false`.

| Tool | Args | Result |
| --- | --- | --- |
| `os` | — | `/etc/os-release` fields, kernel, uptime, machine id, hostname |
| `packages` | `names` (optional list) | `[{"name", "version", "arch"}]` |
| `pending_updates` | `refresh` (optional boolean: refresh the package lists first, through the same exact sudo rule as `package.refresh`; v0.3.0); `fallback` (optional boolean, v0.6.1: see below) | `[{"name", "current", "candidate", "security": bool, "held": bool}]`; `held` is a package held at its version (`apt-mark hold`, dnf versionlock), which upgrades skip (agents before v0.3.0 leave it out). With `fallback`, `{"updates": [...], "refresh": {...}}` instead |
| `service_status` | `unit` | `{"unit", "active_state", "sub_state", "load_state", "unit_file_state", "since"}` |
| `journal` | `unit`, `lines` (≤ 500, default 100) | `{"lines": ["..."]}` |
| `disk` | — | `[{"mount", "fs", "size_bytes", "used_bytes", "avail_bytes"}]` |
| `memory` | — | `{"total_bytes", "available_bytes", "swap_total_bytes", "swap_free_bytes"}` |
| `ports` | — | `[{"proto", "address", "port", "process"}]` |
| `sessions` | — | `[{"user", "tty", "from", "since"}]` |
| `boot` | — | `{"boot_id", "uptime_seconds", "kernel", "reboot_required": bool or null, "reboot_required_by": ["package"], "scheduled_shutdown": {"mode", "at"} or null}`; `reboot_required` is null where the system can't tell (v0.3.0) |
| `services_needing_restart` | — | `{"services": ["nginx.service"]}`: services still running old copies of upgraded libraries, from `needrestart` (apt) or `dnf needs-restarting -s`, run through an exact sudo rule (v0.3.0) |

**`pending_updates` with `fallback` (v0.6.1).** A failed refresh doesn't fail the query: the agent lists the updates from the package lists the server already has and says so, as `{"updates": [<as above>], "refresh": {"requested": bool, "ok": bool, "error": "...", "lists_updated_at": "<RFC 3339, or empty>"}}`. `error` says why the refresh failed: `apt is busy: another process (apt-get, PID 900941, from <unit>) holds /var/lib/apt/lists/lock` when something else holds apt's lock, or `apt-get took longer than 45s and was stopped` at the time limit. `lists_updated_at` is the newest apt `Release` file's time (empty on dnf). A refresh stops 15 s before the query's time limit, so the listing still has time. Without `fallback` the answer and errors are as before, so older hubs see no change; the hub sends `fallback` only to agents from v0.6.1, because older agents refuse arguments they don't know.

A command stopped at the query's time limit gets SIGTERM first, which sudo relays, so the command it started (such as `apt-get update`) exits and releases its locks; SIGKILL follows 10 s later.

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

`timeout_seconds` (optional, a positive integer) is how long one run of the step may take; the hub uses it for execution deadlines.

`reboots` (optional, only present when true) marks an operation that restarts the host, such as `system.reboot`. It may only be the last operation of an envelope and never a rollback step; the agent rejects anything else. It schedules the reboot a minute ahead so the agent can report first, and refuses unless the agent's own unit starts at boot. The hub then checks that the host comes back with a new boot ID (the `boot` tool).

`restarts_agent` (optional, only present when true) marks an operation that replaces the running agent, such as `agent.upgrade`. It has the same placement rules as `reboots`. The hub then checks that the agent reports the new version.

The agent-only part of each definition adds `argv` per package manager (`apt`, `dnf`), with `{param}` placeholders that each fill exactly one argument and are never passed to a shell, plus `dry_run_argv` and `sudo`. A list argument, `{*param:template}`, fills one argument per item of a list param (for `packages.upgrade`, `{*packages:{name}={version}}`); it must be the last argument. Every parameter must match its schema (types, `pattern`, `enum`, `maxLength`) on both sides before use.

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

`hash = SHA-256(envelope bytes)`. The hub encodes the envelope with unescaped slashes and Unicode, never emits duplicate keys, writes empty `params` as `{}`, and uses second-precision times. `intent` and `risk_tier` are the hub's words: the approver app labels them as such, and the agent ignores them.

## Approvals

Each item in `approvals`:

```json
{"kind": "passkey", "key_id": "<b64u credential id>", "authenticator_data": "<b64u>", "client_data_json": "<b64u>", "signature": "<b64u>"}
{"kind": "policy", "key_id": "<policy key id>", "signature": "<b64u Ed25519 signature over the envelope bytes>"}
```

### Passkey signatures

The approver app calls `navigator.credentials.get` with `challenge = hash` and `userVerification: "required"`. A passkey approval is valid when, for a trusted passkey key with that `key_id`:

1. `client_data_json` parses with `type == "webauthn.get"`, `challenge == b64u(hash)`, `origin` equal to the trusted key's `origin`, and `crossOrigin` absent or false.
2. `authenticator_data[0:32] == SHA-256(rp_id)`, and its flags have user presence (`0x01`) and user verification (`0x04`).
3. `signature` verifies over `authenticator_data || SHA-256(client_data_json)` with the key's algorithm: ES256 (COSE `-7`, ASN.1 ECDSA P-256 with SHA-256), EdDSA (`-8`, Ed25519) or RS256 (`-257`, PKCS#1 v1.5 with SHA-256).

## Trusted keys

The agent trusts a **key set**: the passkeys (and policy keys) whose approvals it accepts, plus how many people must sign a change to the set itself. A key set is a document with exact bytes, like an envelope:

```json
{
  "v": 1,
  "kind": "bifrost.keyset",
  "organization_id": "01J...",
  "serial": 3,
  "update_threshold": 2,
  "issued_at": "2026-11-05T00:00:00Z",
  "keys": [
    {"kind": "passkey", "key_id": "<b64u credential id>", "owner": "user:01J...", "label": "Alex's phone", "alg": -7, "public_key": "<b64u SPKI DER>", "rp_id": "approve.example.com", "origin": "https://approve.example.com"},
    {"kind": "policy", "key_id": "policy-1", "public_key": "<b64u raw 32-byte Ed25519 key>"}
  ]
}
```

`hash = SHA-256(key set bytes)`. `serial` starts at 1 and goes up by one with every change. `update_threshold` is how many different `owner`s must approve the *next* key set.

### The anchor

The trusted keys file (default `/etc/bifrost-agent/trusted-keys.json`, root-owned, read-only to the agent's user) is the **anchor**: a key set an admin installed, trusted because root put it there. `install.sh --trusted-keys-b64` writes it from the hub's install command, which carries the organization's current key set; the hub's admin UI also exports it. An older file of the form `{"v": 1, "keys": [...]}` still loads, as serial 0 with an `update_threshold` of 1 and no organization.

### Updates

After installation, key sets change without touching the server. The hub builds the next key set when the organization's approvers or their passkeys change, approvers sign it in the approver app exactly as they sign an envelope (`challenge = hash`), and once enough have signed, the hub hands it to every agent in `GET /work`. The hub can deliver a key set but can't make one an agent accepts: only the people the agent already trusts can.

The agent accepts an update `U` while trusting key set `C` when, in order (the first failure leaves `C` in place and is logged):

1. `U` parses strictly, the same way as an envelope (no duplicate keys, no unknown fields), with `v == 1` and `kind == "bifrost.keyset"`.
2. `U.serial == C.serial + 1`. A lower or equal serial is ignored without a log line; a gap waits for the missing update.
3. If `C` has an `organization_id`, `U` has the same one.
4. `U` is usable: at least one passkey, no duplicate `key_id`s, every key well-formed, and `1 <= U.update_threshold <=` the number of different owners in `U`.
5. Valid passkey approvals over `U`'s hash, from passkeys in **`C`** (checked as in [Passkey signatures](#passkey-signatures)), come from at least `C.update_threshold` different owners. Policy keys can't approve a key set.

The agent stores each accepted update under its state directory (`keysets/<serial>.json`, holding the key set bytes and their approvals) and, whenever it loads its keys, starts from the anchor and re-checks each stored update in serial order, so a tampered file only stops the chain where it was changed. Stored updates at or below the anchor's serial are ignored, so installing a newer anchor by hand always wins: root on the server stays the last word, and is the recovery path if every approver loses their passkeys.

### The hub's side

- The hub creates serial 1 itself when an organization's first approver registers a passkey, and rewrites it in place on every change until the organization's first agent enrolls: until then no server trusts it, so there is nothing to sign for. Nothing signs serial 1; servers get it only through the install command or by hand. An agent installed with no key set never accepts an update, because nobody it trusts can sign one: install it again with the current command.
- When the approvers or their passkeys change, the hub replaces any unapproved key set with a new one for `serial + 1` and asks the approvers who hold keys in the current set to approve it. If the change is undone first, it cancels the pending one.
- `update_threshold` is `BIFROST_KEYSET_UPDATE_THRESHOLD` (default 2), capped at the number of different owners in the new set.
- The hub accepts an approval of a proposal only from a passkey in the current key set, since agents reject the others.
- One person can hold several passkeys (a phone and a hardware key kept somewhere safe). They count as one owner, but a spare is how someone who loses their phone signs the update that removes it.

## What the agent checks before running

In order; the first failure is a `rejected` event and nothing runs.

1. The envelope parses with no duplicate object keys at any depth (`duplicate JSON key`) and no unknown fields, `v == 1`, `kind == "bifrost.envelope"`, and `nonce` is exactly 64 lowercase hex characters. The trusted keys file and key set updates are parsed the same strict way.
2. Its own machine id is in `hosts`.
3. Now is after `not_before` (if set) and before `expires_at`.
4. The nonce hasn't been seen (the agent keeps seen nonces until their envelope expires).
5. Every operation and rollback step is compiled into this agent, and its params match the schema.
6. No operation hits a deny rule compiled into the agent.
7. Approvals satisfy the agent's own rules, with the tier taken from the agent's compiled `min_tier` of each operation and rollback step (never the envelope's `risk_tier`):
   - at least one valid passkey approval, from a key in the current key set;
   - `critical`: valid passkey approvals from two different `owner`s;
   - a policy approval alone is enough only if every operation and rollback step is in the agent's compiled auto-approval list (v0.1: `service.restart@1`).

Then it runs the operations in order. If one fails or its health check fails, it runs the rollback steps (if any) and reports `rolled_back`, otherwise `failed`.

## Approver app ↔ hub

The approver app is static and has no session with the hub. The hub gives it temporary signed URLs, opened as `{approver}/#register=<url-encoded signed URL>`, `{approver}/#approve=<url-encoded signed URL>`, `{approver}/#keyset=<url-encoded signed URL>` or `{approver}/#notify=<url-encoded signed URL>`. The hub allows CORS from the approver origin on `/api/approver/v1/*`.

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
  "hub_context": {
    "intent": "...",
    "source": "mcp",
    "client": "Claude Code",
    "agent_evidence": {"client": "Claude Code", "user": "dev@example.com", "items": [{"source": "...", "detail": "..."}]},
    "reviews": [{"layer": "system1", "verdict": "...", "summary": "..."}]
  },
  "submit_url": "<signed URL>"
}
```

The app decodes the envelope bytes, renders the hosts, operations, parameters, rollback and expiry from those bytes, shows `hub_context` second and labelled as the hub's, computes the hash from the same bytes, calls `navigator.credentials.get`, and `POST submit_url` with `{"key_id", "authenticator_data", "client_data_json", "signature"}`. The hub verifies it the same way the agent does and records the approval.

`client` is the MCP client's name for a proposal made through MCP, otherwise `null`. `agent_evidence` is `null` unless the proposal came through MCP; then it holds the agent's evidence as data, and the app shows it under its own fixed warning that it is an AI agent's claim, unverified, and may have been steered by text the agent read. The hub sends no warning text: everything in `hub_context` is unsigned.

### Approving a key set

`{approver}/#keyset=<url-encoded signed URL>`. `GET` returns:

```json
{
  "key_set_id": "01J...",
  "keyset": "<b64u key set bytes>",
  "current": "<b64u bytes of the key set agents trust now>",
  "rp_id": "approve.example.com",
  "allow_credentials": ["<b64u>"],
  "submit_url": "<signed URL>"
}
```

The app parses both, renders the new key set from its own bytes (serial, organization, update threshold, and each key's label, owner, kind and origin), marks the keys it adds and lists the keys it removes compared with `current`, labelled as the hub's copy of the current set, then hashes and signs the new key set's bytes and `POST submit_url` the same assertion fields as for a proposal. The hub verifies the signature against the passkeys in the current key set.

### Notifications

The hub sends Web Push notifications to the approver app on the devices people turn them on for, so approvers don't need the hub's admin name to hear about work.

`{approver}/#notify=<url-encoded signed URL>` turns them on for one device. `GET` returns:

```json
{
  "user": {"name": "alex@example.com", "display_name": "Alex"},
  "vapid_public_key": "<b64u 65-byte uncompressed P-256 point>",
  "subscribe_url": "<signed URL>"
}
```

The app asks for notification permission, calls `pushManager.subscribe({userVisibleOnly: true, applicationServerKey: vapid_public_key})` on its service worker registration, and `POST subscribe_url`:

```json
{"endpoint": "https://fcm.googleapis.com/fcm/send/...", "keys": {"p256dh": "<b64u>", "auth": "<b64u>"}, "label": "Alex's phone"}
```

Response `201`: `{"device_id": "01J..."}`.

**Pairing code.** An app installed on an iPhone's Home Screen can't be opened by a link: links open Safari, which keeps separate storage, and iOS allows push only in the installed app. So a person can instead get a pairing code from the hub (8 characters from `0-9A-Z` without `I L O U`, shown as `K7QM-4XRP`; single use; valid 10 minutes) and type it into the app. The app knows its hub's origin (set at deploy, like the CSP) and sends `POST {hub}/api/approver/v1/pairing` with `{"code": "K7QM4XRP"}`, case and dashes ignored. The response is the same as the `GET` above, and the app continues the same way. A wrong or used code gets `404 invalid_code`; the endpoint allows 10 attempts a minute per address. The hub accepts only `https` endpoints on known push services (`BIFROST_PUSH_HOSTS`), so a subscription can't make it call anything else.

Each push is encrypted to the device (RFC 8291, `aes128gcm`) and signed by the hub's VAPID key (RFC 8292). The decrypted payload:

```json
{"v": 1, "title": "Approval needed", "body": "Restart nginx on web-01 (risk: low)", "url": "/#approve=<url-encoded signed URL>", "tag": "proposal:01J..."}
```

`url` is a path on the approver's own origin: an `#approve=` or `#keyset=` link whose signed URL lasts until the proposal expires, at most 24 hours. The service worker shows the notification and, on a tap, opens or focuses the app at that path; it ignores a `url` that isn't on its own origin. A notification only says that something is waiting: what gets signed is still shown from the signed bytes, as always.

