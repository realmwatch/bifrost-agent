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
    "reboot_required": "yes",
    "reboot_required_by": ["linux-image-6.8.0-50-generic"],
    "livepatch": {"applied": true, "patches": ["lkp_Ubuntu_6_8_0_45_generic_105"]},
    "collector_version": "0.5.34",
    "collector_settings": {"privilege_watch": "users", "login_watch": "on", "tripwires": "off"}
  },
  "trusted_keys_serial": 3
}
```

`boot_id` changes on every boot; the hub uses it to check a reboot happened. `reboot_required` is `"yes"` or `"no"` on apt systems (`/run/reboot-required`) and left out elsewhere. Agents before v0.3.0 leave both out. From v0.18.0, `reboot_required_by` lists the packages asking for the reboot (`/run/reboot-required.pkgs`), left out when there are none or no reboot is needed, and `livepatch` says whether the kernel has a live patch loaded: `applied` is true when one is enabled and finished applying, and `patches` names the loaded patch modules (`/sys/kernel/livepatch`). `livepatch` is left out where the kernel can't take live patches. `collector_version` is the Heimdall collector installed on the server (agent v0.5.0), left out when there is none. `collector_settings` (v0.13.0) says which of its optional reports are on, read from its `collect.env`: `privilege_watch` is `on`, `users` or `off`, and `login_watch` and `tripwires` are `on` or `off` (a setting the file lacks is `off`). It's left out with no collector or no `collect.env`.

**Turning on collector reports (v0.13.0).** `collector.upgrade@1` takes an optional `turn_on`, a comma-separated list of `tripwires` (collector v0.5.34 or later), `logins` and `privilege-users`. The agent's helper upgrades the collector first, on its own, then runs the new collector's `upgrade` again with `--tripwires`, `--watch-logins` or `--watch-privilege-users`, because an older collector refuses options it doesn't know. With `turn_on`, `version` may be the installed version, so a collector that's already current can turn reports on. It checks `collect.env` shows each one on afterwards. Agents before v0.13.0 refuse `turn_on`.

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
| `boot` | — | `{"boot_id", "uptime_seconds", "kernel", "reboot_required": bool or null, "reboot_required_by": ["package"], "scheduled_shutdown": {"mode", "at"} or null, "livepatch": {"applied", "patches", "client": {"patch_state", "version", "fixes": ["CVE-…"], "support", "upgrade_required_by", "error"} or null} or null}`; `reboot_required` is null where the system can't tell (v0.3.0). `livepatch` (v0.18.0) is null where the kernel can't take live patches; `client` is Canonical Livepatch's own status for the running kernel, null when it isn't installed |
| `services_needing_restart` | — | `{"services": ["nginx.service"]}`: services still running old copies of upgraded libraries, from `needrestart` (apt) or `dnf needs-restarting -s`, run through an exact sudo rule (v0.3.0) |
| `release_leftovers` | — | What an in-place release upgrade left behind (apt; v0.10.0), gathered as root through an exact sudo rule (`bifrost-agent release leftovers`): `{"codename", "sources": [{"file", "uri", "suite", "new_suite", "available", "action": "retarget"|"disable"}], "disabled": [{"file", "line"}], "obsolete": [{"name", "version", "built_for", "replacement"}], "local": [...], "old_builds": [...], "used_by": [{"pid", "command", "unit", "library", "package"}], "truncated"}`. `sources` are entries in `/etc/apt/sources.list.d` naming an older release; `available` means the source offers the current release at the same URI. `disabled` are lines the upgrader commented out. `obsolete` are installed packages no source offers, built for an older release (`built_for` names it, or `older`); `local` are other packages no source offers, such as a vendor's `.deb`, never proposed for removal. `old_builds` are packages built for an older release that a source still offers. `replacement` is a version a source offers for the current release with the same epoch and an upstream version at least as new. `used_by` are running processes that map a library from any of them. |
| `php_sites` | — | The host's PHP versions and the sites nginx serves with PHP (apt; v0.12.0), gathered as root through an exact sudo rule (`bifrost-agent php sites`): `{"versions": {"installed": ["8.1"], "fpm": {"8.1": {"active", "enabled"}}, "installable": ["8.1", "8.3"], "alternative": "8.1"}, "sites": [{"root", "server_names", "vhosts", "php", "repo", "require_php", "platform_php", "cli": [{"kind": "cron"\|"supervisor"\|"systemd", "file", "php"}], "forge", "lock_php": [{"package", "constraint"}], "lock_truncated"}], "truncated"}`. `installed` are minors with an FPM or CLI package; `installable` those whose FPM package apt has a candidate for; `alternative` the minor the `php` alternative points at (empty if none). A site is an enabled nginx vhost's `root` without `/public`; `php` is the minor of its `fastcgi_pass` socket. `repo` is the root's origin remote as `host/path`, credentials stripped. `require_php` and `platform_php` are composer.json's `require.php` and `config.platform.php`; `lock_php` is every composer.lock package's own `require.php` (deduped, at most 500). `cli` are cron, supervisor and systemd files whose lines name the root and run PHP (`php` for a bare `php`). `forge` means Laravel Forge manages the host. At most 200 sites. |
| `nginx_http2` | — | What `nginx.http2_off` would change, and what `nginx.http2_restore` would put back (v0.14.0), gathered as root through an exact sudo rule (`bifrost-agent nginx http2-plan`): `{"changes": [{"file", "line", "before", "after"}], "files_read", "skipped_includes", "restorable": [{"backup", "changes"}]}`. It reads nginx's configuration the way nginx does: `nginx.conf`, then each `include` in place, globs sorted, relative paths under `/etc/nginx`. |
| `nginx_source` | — | What `nginx.source.nginx_org` would change, or why it would refuse (apt; v0.14.0), through `bifrost-agent nginx source-plan`: `{"nginx_version", "ppa_build", "os", "codename", "refusal", "remove_sources", "write", "source_line", "load_module_lines": [{"file", "line", "text"}], "remove_links", "steps", "restorable"}`. `refusal` is empty when it can run. |
| `php_source` | — | What `php.source.sury_org` would change, or why it would refuse (apt; v0.15.0), through `bifrost-agent php source-plan`: `{"os", "codename", "refusal", "ppa_sources", "sury_enabled", "sury_sources", "php_packages", "source_file", "steps", "restorable"}`. `ppa_sources` are the files in `/etc/apt/sources.list.d` that enable the ondrej/php PPA (or its ppa.setup-php.com mirror), `sury_sources` those that enable packages.sury.org/php, `php_packages` counts installed packages built by Ondřej Surý (version has `deb.sury.org` or `debsuryorg`), and `restorable` names the backups `php.source.restore` can put back. `refusal` is empty when it can run. |
| `node_installs` | — | The host's Node.js (apt; v0.21.0), gathered as root through an exact sudo rule (`bifrost-agent node report`): `{"default": {"path": "/usr/bin/node", "version": "22.11.0", "major": "22", "source": "nodesource"\|"other"\|""} or null, "installs": [{"path": "/opt/node/20", "version": "20.18.1", "major": "20"}], "uses": [{"kind": "supervisor"\|"systemd"\|"cron", "file", "name", "binary", "line"}]}`. `default` is `/usr/bin/node` (null when there is none): `version` from its `--version`, `source` `nodesource` when the `nodejs` package's version names NodeSource, `other` for another package, empty when no package installed it. `installs` are the side installs `/opt/node/NN`, with `version` read from `include/node/node_version.h` (empty if unreadable). `uses` are the command lines that run node: supervisor `command=` lines in `/etc/supervisor/conf.d/*.conf` (`name` is the program), `ExecStart`/`ExecStop`/`ExecReload` lines in `/etc/systemd/system/*.service` and their `*.service.d/*.conf` drop-ins (`name` is the unit), and lines of `/etc/crontab`, `/etc/cron.d/*` and `/var/spool/cron/crontabs/*` (`name` empty). `binary` is each absolute path ending in `/bin/node` the line runs, or `node` for a bare `node`; `line` is the line, redacted, at most 300 bytes. At most 500 uses. |
| `site_plan` | `action` (`disable` or `enable`), `root`, optional `vhost` | What `site.disable` or `site.enable` would change, or why it would refuse (apt; v0.19.0), through `bifrost-agent site plan ACTION ROOT [VHOST]` with a sudo rule ending in `*`: `{"action", "root", "refusal", "disabled", "disabled_at", "vhosts": [{"path", "kind": "symlink"\|"file", "target", "held_at", "server_names"}], "supervisor": [{"file", "program", "running"}], "cron": [{"file", "line"}], "units": [{"unit", "active", "enabled"}], "fpm_pools": [{"file", "socket"}], "drift": ["…"], "notes": ["…"]}`. `refusal` is empty when it can run. `disabled` means a restore record exists; `drift` lists enabled vhosts serving the root again after it was disabled. `fpm_pools` are pools only this site uses, which are left running. |

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

**nginx (v0.14.0).** `nginx.http2_off@1` (no params) turns HTTP/2 off everywhere nginx reads config: it removes the `http2` flag from every `listen` in an http `server` (except QUIC listens) and changes `http2 on` to `http2 off` in `http{}` and each server. It refuses if `nginx -t` already fails, backs up each changed file under `/var/backups/nginx-http2` with the exact lines changed, then runs `nginx -t` and reloads, putting every file back if either fails. `nginx.http2_restore@1` (its rollback, and the later "nginx is fixed" change) puts back exactly those lines, newest backup first, refusing if any has changed since. `nginx.check@1` runs `nginx -t` and warns, without failing, when nginx.org's `conf.d/default.conf` has become an address's default server ahead of a host site. `nginx.source.nginx_org@1` moves an Ubuntu 22.04+ host from the removed ondrej/nginx PPA to nginx.org's mainline packages: it drops `load_module` lines for modules nginx.org doesn't ship and checks `nginx -t` with the old nginx, swaps the apt sources (nginx.org's key is compiled into the agent) with a priority 900 pin, refreshes and simulates, and only then upgrades with `--force-confold`, runs `nginx -t` and restarts. Until the upgrade any failure puts every file back. `nginx.source.restore@1` is its rollback: the apt files always, the nginx configuration only while the PPA's nginx is still installed, because its package can't be reinstalled.

**Retiring a site (v0.19.0).** `site.disable@1` (`root`, optional `vhost`, tier high) retires one site without deleting anything. `vhost` is a hint (a file directly in `/etc/nginx/sites-enabled`, `sites-available` or `conf.d`): the agent finds every enabled file serving `root` itself (a server block whose `root`, less `/public`, is `root` or under it). It removes each `sites-enabled` symlink, or moves a regular file in `sites-enabled` or `conf.d` to `/etc/nginx/bifrost-disabled/` (from v0.19.1 the folder is 0755 and each held file 0644, so Heimdall's unprivileged collector can read them; the record keeps the file's mode and `site.enable` puts it back), then runs `nginx -t` and reloads; comments out cron lines (`/etc/cron.d`, `/var/spool/cron/crontabs`) that name `root`, prefixing `# bifrost site.disable: `; sets supervisor programs whose `command` or `directory` names `root` to `autostart=false` and stops them; and runs `systemctl disable --now` on services in `/etc/systemd/system` whose `ExecStart` or `WorkingDirectory` names `root`. Files, databases, certificates, DNS, the firewall and PHP-FPM pools are left alone. It refuses when a file serving `root` also serves another root, or holds a `default_server`. Every change is recorded, with what was there before, in `/var/lib/bifrost-agent/disabled-sites/<first 16 hex of sha256(root)>.json`; a later disable (after drift) adds to that record without overwriting the original state. It checks afterwards that no enabled vhost serves `root` and the programs and units are stopped, and puts back everything it changed on any failure. `site.enable@1` (same params, tier high) replays the record: links or moves the vhosts back (leaving any that exist again), `nginx -t` and reload (undone on failure), uncomments the marked lines, restores `autostart` and starts the programs that were running, enables and starts the units as they were, then removes the record. Without a record it links the `sites-available` file serving only `root` (the `vhost` hint first) into `sites-enabled` and uncomments marked cron lines, and says workers and units weren't restored. Each is the other's rollback.

**Node.js versions (v0.21.0).** The host default is NodeSource's `nodejs` package at `/usr/bin/node`. Side installs are nodejs.org's official linux tarballs at `/opt/node/NN` (NN the two-digit major), root:root, directories 0755 and no group or other write, with the tarball's layout kept (`bin/node`, `bin/npm`, `include/node/node_version.h`, which Heimdall reads). A site's long-running processes run the binary by absolute path. All six operations are apt only, run as `/usr/local/bin/bifrost-agent node <sub> ...` through sudo, and check everything at execution time.

- `nodejs.install@1` (`major`, tier low) reads `https://nodejs.org/dist/index.json`, takes the newest `vX.Y.Z` of that major (no prereleases), fetches `SHASUMS256.txt` and `SHASUMS256.txt.sig` and checks them with `gpgv` against the Node.js release keys compiled into the agent. The keyring is `gpg-only-active-keys/pubring.kbx` from [nodejs/release-keys](https://github.com/nodejs/release-keys) (commit 481637f8, 2026-09-01), exported as a plain OpenPGP keyring; when Node.js adds a release key, trusting it takes an agent release, and until then a release signed only by the new key fails to install, with an error saying so. It then downloads `node-vX.Y.Z-linux-x64.tar.gz` (amd64) or `-linux-arm64` (arm64; any other architecture is refused), at most 200 MB, and checks its SHA-256 against the signed line. It unpacks it in Go into `/opt/node/.NN.new`, stripping the top directory and refusing absolute paths, `..`, entries outside the top directory, symlinks that aren't relative or point outside the tree (`bin/npm`, `npx` and `corepack` link into `lib/node_modules`), entries below a symlink, and anything but files, directories and symlinks, with at most 1 GB and 100,000 entries unpacked. It checks `include/node/node_version.h` exists and `bin/node --version` prints the release, then renames it to `/opt/node/NN`. It refuses if `/opt/node/NN` exists, and removes `.NN.new` on any failure. No rollback: nothing uses a new install until `nodejs.switch_site` moves a site to it.
- `nodejs.update@1` (`major`, tier medium) refuses unless `/opt/node/NN` is installed and does nothing (exit 0, saying so) when it is already at the newest release. Otherwise it stages the new release as install does, moves the current tree to `/opt/node/.NN.previous` (replacing an older one) and the new one into place, restarts the running supervisor programs and systemd units whose command runs `/opt/node/NN/bin/node` (or whose `PATH` names its `bin`), waits 10 s and checks each program is `RUNNING` and each unit `active` with `NRestarts` unchanged. If one isn't, it swaps the old tree back, restarts them again and fails. No catalog rollback: it rolls itself back.
- `nodejs.remove@1` (`major`, tier high) refuses while a running process's `/proc/*/exe` is under `/opt/node/NN/`, or a line in `/etc/supervisor/conf.d`, `/etc/systemd/system` (drop-ins included), `/etc/cron.d`, `/var/spool/cron/crontabs`, `/etc/crontab`, `/home/*/.pm2/dump.pm2` or `/root/.pm2/dump.pm2` names `/opt/node/NN` (comment lines don't count, except in pm2 dumps). It then moves the tree to `/var/backups/node-remove/NN-vX.Y.Z-<UTC stamp>` (a rename, or copy and remove across filesystems). Its rollback is `nodejs.restore@1` (`major`, tier medium), which moves the newest such backup back. When `/opt/node/NN` exists (the remove refused, so nothing was removed) it changes nothing and succeeds, like `php.restore`, so a refused remove ends as `rolled_back`; with no install and no backup it refuses.
- `nodejs.switch_site@1` (`root`, `from`, `to`, tier high) moves one site between node binaries (`/usr/bin/node`, `/opt/node/NN/bin/node` or an nvm `~/.nvm/versions/node/vX.Y.Z/bin/node`). It refuses unless `root` is an existing directory (not `/`) and `to` exists and is executable. A supervisor program or systemd unit (with its drop-ins) belongs to the site when its command or working directory names a path under `root`; a cron line (`/etc/crontab`, `/etc/cron.d`, `/var/spool/cron/crontabs`) when it does itself. In those, a command token equal to `from` (or, when `from` is `/usr/bin/node`, a bare `node` that resolves to it on the program's `PATH`) becomes `to`, and the program's or unit's `PATH` entry for `from`'s directory moves to `to`'s (`/usr/bin` stays: the new directory goes before it, and moving back to `/usr/bin` drops the other). When nothing under `root` runs `from` but something runs `to`, it does nothing (exit 0); when nothing runs either it refuses, saying so when only pm2 runs the site (`dump.pm2` names `root`), since pm2 processes aren't moved. Every file is backed up under `/var/backups/node-switch/<stamp>/` with its mode and owner; a user's crontab stays 0600. If `root/node_modules` holds a `*.node` addon, it is copied into the backup and `npm rebuild` runs in `root` as its owner (`runuser -u <owner> -- env -C <root> HOME=<home> PATH=<to's dir>:/usr/bin:/bin <to's dir>/npm rebuild`, 10 minute limit). Then `supervisorctl reread` and `update` (when a supervisor file changed), `systemctl daemon-reload` and a restart of the changed units that were running, and 10 s later each changed program that was running must be `RUNNING` and each unit `active` without restarting. On any failure every file and `node_modules` is put back and reloaded. Its rollback is itself with `from` and `to` swapped, which after a failed switch (already put back) does nothing.
- `nodejs.default_switch@1` (`from`, `to` majors, tier high) moves NodeSource's host node. It finds `/etc/apt/sources.list.d/nodesource.list` (one-line) or `nodesource.sources` (deb822), which must name `deb.nodesource.com/node_FROM.x` and no other major, and `/usr/bin/node --version` must be major `from` from the installed `nodejs` package; when both already say `to` it does nothing (exit 0). It backs up the source file and the installed `nodejs` version under `/var/backups/node-default/<stamp>/`, rewrites the source to `node_TO.x`, runs `apt-get update` and `apt-get install -y --allow-downgrades -o Dpkg::Options::=--force-confold nodejs` (`DEBIAN_FRONTEND=noninteractive`; downgrades are allowed because the rollback is this operation swapped), checks `/usr/bin/node --version` is major `to`, restarts the running supervisor programs and systemd units whose command runs `/usr/bin/node` or a bare `node` resolving to it, and checks them 10 s later. On any failure it puts the source back, runs `apt-get update`, reinstalls `nodejs=<recorded version>` (or the newest the old source has, if that version is gone) and restarts them again. Its rollback is itself with `from` and `to` swapped.

**PHP from packages.sury.org (v0.15.0).** `php.source.sury_org@1` (no params, tier high) moves PHP's apt source from the ondrej/php PPA, which is deprecated and frozen (its Release Label changed, so `apt-get update` fails on it), to packages.sury.org/php, the migration the PPA's notice documents, on Ubuntu jammy, noble or resolute. It backs up the PPA's source files, `/etc/apt/sources.list.d/php.sources` and `/etc/apt/preferences.d/php.pref` under `/var/backups/php-source`, refreshes only the PPA's lists accepting the Label change (and nothing else), installs `debsuryorg-repository-php` from the PPA (refusing if apt would remove anything or touch a PHP package; its postinst writes `php.sources`), checks packages.sury.org/php is enabled, removes the PPA's files, refreshes only packages.sury.org/php's list and checks `apt-cache policy` finds an installed PPA-built package's candidate there. It installs, upgrades or removes no PHP package and restarts nothing. Any failure puts every file back and purges `debsuryorg-repository-php` if it installed it. `php.source.restore@1` (tier high) is its rollback: it puts back the newest backup's files and purges `debsuryorg-repository-php` if the move installed it, leaving `debsuryorg-archive-keyring`.

**Upgrading a site's PHP (v0.12.0).** `php.install@1` (`version`, `like`) installs a PHP version alongside another without switching anything: its FPM and CLI plus the counterpart of each `php{like}-*` package, the old version's FPM pools (socket names renamed) and its own `conf.d` files, and the tuned `php.ini` settings that differ, in `conf.d/99-bifrost-ported.ini`. It puts back any PHP alternative the install moved, so the host's `php` command doesn't change. It has no catalog rollback; the hub's proposal rolls it back with `service.stop` and `service.disable` of the new FPM, then `php.remove`. `php.switch_site@1` (`root`, `from`, `to`) moves one site: the FPM socket in only that site's nginx server blocks, then the cron, supervisor and systemd lines that name its root (`php{from}`, or a bare `php`, becomes `php{to}`); it never touches the `php` alternative. It backs up every file under `/var/backups/php-switch`, and puts them all back unless `nginx -t`, the reloads and a smoke check (nginx on the host answers the site's first `server_name` without a 5xx, and the new FPM logs no errors) pass. Its rollback is itself with `from` and `to` swapped; for a site nginx already serves on `to` it moves only lines that name `from` explicitly, so a rollback after a failed switch (which already put everything back) does nothing.

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

### Batch approvals

One passkey assertion can approve several proposals at once, for patching many servers. It signs a **batch**, a short document listing the envelopes it covers, and each agent checks that its own envelope is on the list. Every proposal keeps its own envelope, nonce, expiry and execution, so one host failing or rolling back doesn't touch the others.

```json
{
  "v": 1,
  "kind": "bifrost.batch",
  "organization_id": "01J...",
  "envelopes": ["<lowercase hex SHA-256 of an envelope>", "..."]
}
```

The hub encodes it as it encodes envelopes and stores the exact bytes. `envelopes` holds 1 to 100 distinct hashes. The approver app calls `navigator.credentials.get` with `challenge = SHA-256(batch bytes)`, and the approval item carries the batch with it:

```json
{"kind": "passkey_batch", "key_id": "<b64u credential id>", "authenticator_data": "<b64u>", "client_data_json": "<b64u>", "signature": "<b64u>", "batch": "<b64u batch bytes>"}
```

A `passkey_batch` approval is valid for an envelope when:

1. The batch parses as strictly as an envelope (no duplicate keys at any depth, no unknown fields), with `v == 1`, `kind == "bifrost.batch"`, and 1 to 100 distinct entries in `envelopes`, each 64 lowercase hex characters.
2. Its `organization_id` equals the envelope's.
3. The envelope's hash, as lowercase hex, is in `envelopes`.
4. The assertion is a valid passkey signature, as above, with `SHA-256(batch bytes)` as the challenge.
5. Every operation in the envelope is in the agent's compiled batch list, and so is every rollback step, whatever the hub puts in it:
   - operations: `package.upgrade@1`, `packages.upgrade@1`, `agent.upgrade@1`, `collector.upgrade@1`, `package.refresh@1`, `package.hold@1`, `package.unhold@1`, `service.restart@1`, `service.reload@1`, `kernel.remove@1` and `system.reboot@1`, and from v0.17.0 every other operation in the catalog: `package.install@1`, `packages.remove_obsolete@1`, `apt.source.disable@1`, `apt.source.restore@1`, `apt.source.retarget@1`, `nginx.check@1`, `nginx.http2_off@1`, `nginx.http2_restore@1`, `nginx.source.nginx_org@1`, `nginx.source.restore@1`, `php.install@1`, `php.remove@1`, `php.restore@1`, `php.source.sury_org@1`, `php.source.restore@1`, `php.switch_site@1`, `service.start@1`, `service.stop@1`, `service.enable@1` and `service.disable@1`, and from v0.19.0 `site.disable@1` and `site.enable@1`, and from v0.21.0 `nodejs.install@1`, `nodejs.update@1`, `nodejs.remove@1`, `nodejs.restore@1`, `nodejs.switch_site@1` and `nodejs.default_switch@1`;
   - rollback steps: `package.install@1`, `package.hold@1` and `package.unhold@1`, and from v0.17.0 `apt.source.restore@1`, `nginx.http2_off@1`, `nginx.http2_restore@1`, `nginx.source.restore@1`, `php.restore@1`, `php.source.restore@1`, `php.switch_site@1`, `service.start@1`, `service.stop@1`, `service.enable@1` and `service.disable@1`, and from v0.19.0 `site.disable@1` and `site.enable@1`, and from v0.21.0 `nodejs.restore@1`, `nodejs.switch_site@1` and `nodejs.default_switch@1`.

   Agents before v0.9.0 allow only `package.upgrade@1` and `packages.upgrade@1`, with `package.install@1` as rollback.

A valid batch approval counts as a passkey approval from that key's owner. Agents before v0.7.0 don't know the kind and ignore it, so the hub only offers batches when every server's agent is at v0.7.0 or later. For the operations added in v0.9.0 it requires v0.9.0.

Reboots in a batch run one server at a time, in the batch's order: the hub hands a batched reboot to its agent only once the batch's previous reboot is back with a new boot ID, and stops the roll if one isn't. That ordering is the hub's; each agent checks only its own envelope.

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
   - a policy approval alone is enough only if every operation and rollback step is in the agent's compiled auto-approval list (`service.restart@1`, from v0.16.0 `collector.upgrade@1`, and from v0.20.0 `agent.upgrade@1`);
   - a `passkey_batch` approval counts as a passkey approval only when it passes the [batch checks](#batch-approvals), which include the compiled batch list.

Then it runs the operations in order. If one fails or its health check fails, it runs the rollback steps (if any) and reports `rolled_back`, otherwise `failed`.

From v0.11.0, the agent also lists the failed systemd services (leaving out oneshot ones, which timers run) before the operations and again a few seconds after they all succeed. A service failed afterwards that wasn't before (for example one needrestart restarted after an upgrade, which then couldn't start) fails the change: the agent sends a second `health` event for the last operation with `ok: false` and a `detail` naming the services, then rolls back as for any failed health check. It skips this for envelopes that reboot or replace the agent, and when it can't read the list.

## Approver app ↔ hub

The approver app is static and has no session with the hub. The hub gives it temporary signed URLs, opened as `{approver}/#register=<url-encoded signed URL>`, `{approver}/#approve=<url-encoded signed URL>`, `{approver}/#keyset=<url-encoded signed URL>`, `{approver}/#batch=<url-encoded signed URL>` or `{approver}/#notify=<url-encoded signed URL>`. The hub allows CORS from the approver origin on `/api/approver/v1/*`.

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

### Approving a batch

`{approver}/#batch=<url-encoded signed URL>`. `GET` returns:

```json
{
  "batch_id": "01J...",
  "batch": "<b64u batch bytes>",
  "proposals": [
    {"proposal_id": "01J...", "envelope": "<b64u envelope bytes>", "hub_context": {"intent": "...", "source": "heimdall", "client": null, "agent_evidence": null, "reviews": []}}
  ],
  "rp_id": "approve.example.com",
  "allow_credentials": ["<b64u>"],
  "submit_url": "<signed URL>"
}
```

The app parses the batch and every envelope from their own bytes, hashes each envelope, and refuses the batch unless the set of hashes it computed is exactly the batch's `envelopes`: same count, nothing missing, nothing extra. Every envelope's `organization_id` must equal the batch's. It then shows the batch's size and, for each proposal, its hosts, operations, parameters, rollback and expiry from the envelope bytes, with `hub_context` second and labelled as the hub's, as for one proposal. It hashes the batch bytes, calls `navigator.credentials.get` with that hash as the challenge, and `POST submit_url` with `{"key_id", "authenticator_data", "client_data_json", "signature"}`. The hub verifies the signature against the batch, then records a `passkey_batch` approval on every proposal in it that is still awaiting approval.

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
{"v": 1, "title": "Acme Bifrost: Approval needed", "body": "Restart nginx on web-01 (risk: low)", "url": "/#approve=<url-encoded signed URL>", "tag": "proposal:01J..."}
```

`url` is a path on the approver's own origin: an `#approve=` or `#keyset=` link whose signed URL lasts until the proposal expires, at most 24 hours. The service worker shows the notification and, on a tap, opens or focuses the app at that path; it ignores a `url` that isn't on its own origin. The title names the organization, so someone who approves for several can tell them apart. A notification only says that something is waiting: what gets signed is still shown from the signed bytes, as always.

