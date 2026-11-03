# Operations

One definition per operation and version (for example `package.upgrade@1`). This directory is the source of truth: the agent compiles these definitions in, and each release publishes the hub-facing part (names, versions, parameter schemas, risk tiers, rollbacks, dry runs, health checks) as a signed `operations-vX.Y.Z.json` that the hub pins. Argument lists and sudo rules are agent-only.

A definition holds:

- **Name and version.**
- **Parameter schema:** types, patterns and allowed values. Parameters are never interpolated into a shell string.
- **Distro support:** Debian and Ubuntu (`apt`), RHEL family (`dnf`), each mapped to an exact argument list.
- **Dry run,** if the operation has one.
- **Health check:** what proves it worked.
- **Rollback:** the inverse operation, or irreversible.
- **Minimum risk tier:** a floor nothing can lower.
- **Files written:** paths whose content hashes each execution records.
- **Sudo rule:** the exact command the agent's user may run for it.

Adding an operation means a new agent release, which is intentional: what Bifrost can do to a server is reviewed code, not configuration.

## File format

One JSON file per operation, named `name@version.json`, embedded into the binary (`embed.go`). The loader rejects unknown fields, and any check below that fails stops the agent from building its catalog (tests cover the embedded set).

```json
{
  "name": "service.restart",
  "version": 1,
  "description": "Restart one systemd service.",
  "min_tier": "low",
  "params": {"type": "object", "additionalProperties": false, "required": ["unit"], "properties": {"unit": {"type": "string", "pattern": "^...$", "maxLength": 128}}},
  "rollback": null,
  "irreversible": false,
  "health_check": "The unit's ActiveState is active after the restart.",
  "files_written": [],
  "agent": {
    "privileged": true,
    "argv": {"apt": ["/usr/bin/systemctl", "restart", "{unit}"], "dnf": ["/usr/bin/systemctl", "restart", "{unit}"]},
    "dry_run_argv": {},
    "env": {},
    "sudo": {"apt": "/usr/bin/systemctl restart *", "dnf": "/usr/bin/systemctl restart *"},
    "health": {"check": "service_state", "args": {"unit": "{unit}", "state": "active"}}
  }
}
```

Everything outside `agent` is the hub-facing part `bifrost-agent operations export` prints (`dry_run` is derived from `dry_run_argv`). Rules the loader enforces:

- `params` uses only the supported JSON Schema subset (`type` object/string/integer/boolean/array, `properties`, `required`, `additionalProperties: false`, `pattern`, `enum`, `minLength`, `maxLength`, `minimum`, `maximum`, `items`, plus `description` and `title`); any other keyword fails. The top level must be a closed object, and string params need an anchored `pattern` (or `enum`) and a `maxLength`.
- `argv[0]` is an absolute path. A `{param}` placeholder names a required string or integer param and fills part of exactly one argument; an argument built from a placeholder may not be empty or start with `-`.
- `sudo` must equal the argv with every placeholder argument replaced by `*`; `bifrost-agent operations sudoers` renders the rules (and `deploy/sudoers.example`, which a test keeps in sync; run `make sudoers`).
- `health.check` names a check implemented in Go: `package_version` (`name`, `version`) or `service_state` (`unit`, `state`).
- `rollback` names a known operation; an `irreversible` operation has none.
