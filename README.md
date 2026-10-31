# Bifrost agent

The agent that runs on each server managed by a Bifrost hub. It dials out to the hub, answers read-only questions about the server, and runs only typed operations carrying an approval signature it can verify itself. A hub that is taken over can propose changes, but can't approve them.

> **Status: scaffolding.** No agent code yet.

- **Dials out** over a WebSocket with mTLS and the hub's pinned key. No port is opened on the server.
- **Read-only state tools:** packages and pending updates, service status, journal lines, disk and memory, listening ports, sessions, redacted config files.
- **Typed operations** run as argument lists, never through a shell, under the agent's own user with sudo rules limited to the operations it knows.
- **Verifies approvals:** the signature over the exact operations, its own host id, the approver's origin, the expiry and a nonce.
- **Hard rules of its own:** a short deny list compiled into the binary that no hub can change.

## Operations

[`operations/`](operations/) is the source of truth for every operation Bifrost can run on a server. Each release compiles them into the binary and publishes the hub-facing part as a signed release file, which the hub pins.

## License

[AGPL-3.0](LICENSE).
