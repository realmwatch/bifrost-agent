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
