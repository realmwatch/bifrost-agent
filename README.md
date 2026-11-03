# Bifrost agent

The agent that runs on each server managed by a Bifrost hub. It dials out to the hub, answers read-only questions about the server, and runs only typed operations carrying an approval signature it can verify itself. A hub that is taken over can propose changes, but can't approve them.

> **Status: v0.1.** Enrollment, heartbeats, polling, state tools, six operations and full approval verification. [`PROTOCOL.md`](PROTOCOL.md) is the contract with the hub and the approver app.

- **Dials out** over HTTPS and polls for work (a WebSocket channel and mTLS can replace polling later without changing payloads). No port is opened on the server.
- **Read-only state tools:** os, packages, pending updates, service status, journal lines (redacted), disk, memory, listening ports, sessions.
- **Typed operations** run as argument lists, never through a shell, under the agent's own user with sudo rules limited to the operations it knows. Each parameter is checked against its schema and fills exactly one argument.
- **Verifies approvals** itself: WebAuthn passkey signatures (ES256, EdDSA, RS256) over the exact envelope bytes, its own machine id, the approver's origin and rp id, user verification, the expiry and a single-use nonce. The risk tier comes from the compiled operation, never from the hub.
- **Hard rules of its own:** a deny-rule hook and an auto-approval list compiled into the binary that no hub can change.

## Commands

```
bifrost-agent enroll --hub URL (--key KEY | --key-stdin) [--config PATH] [--force]
bifrost-agent run [--config PATH]
bifrost-agent operations export          # hub-facing catalog JSON
bifrost-agent operations sudoers [--user bifrost]
bifrost-agent state <tool> [--arg key=value ...]
bifrost-agent verify --envelope FILE --approvals FILE [--machine-id ID]
bifrost-agent trusted-keys check FILE    # validate a trusted keys file
bifrost-agent version
```

`state` runs a tool locally and prints its JSON (for example `bifrost-agent state service_status --arg unit=nginx.service`, or `--arg lines=50` for `journal`). `verify` runs every pre-run check on an envelope (its exact bytes, or their base64url) and a JSON array of approvals, without recording the nonce.

## Configuration

`/etc/bifrost-agent/config.json` (JSON, unknown fields rejected):

| Field | Default | |
| --- | --- | --- |
| `hub_url` | — | `https://...`; `http://` only for localhost |
| `state_dir` | `/var/lib/bifrost-agent` | `state.json` (agent id and token, mode 0600) and `nonces.json` |
| `trusted_keys_path` | `/etc/bifrost-agent/trusted-keys.json` | root-owned, read-only to the agent; see PROTOCOL.md |
| `poll_interval_seconds` | `5` | |
| `heartbeat_interval_seconds` | `60` | |
| `package_manager` | `auto` | `auto`, `apt` or `dnf` |
| `use_sudo` | `true` | prefix privileged steps with `sudo -n --` |
| `simulate` | `false` | log each argv and report success without running it (development) |
| `insecure_skip_tls_verify` | `false` | development only, logged loudly |

## Install

**Quickest:** **Servers → Add a server** in the hub gives a one-line command that runs `install.sh` from a release:

```sh
curl -fsSLO https://github.com/realmwatch/bifrost-agent/releases/download/vX.Y.Z/install.sh &&
  sudo sh install.sh --hub https://bifrost.example.com --trusted-keys-b64 <from the hub> --enroll
```

Paste the enrollment key when asked; it isn't echoed or put on a command line. The installer verifies the release's Sigstore signature (with a pinned cosign, accepting only this repository's release workflow) and `SHA256SUMS`, then creates the `bifrost` user and directories, installs the binary, unit, sudoers rules and trusted keys, enrolls, and starts the service. Re-running it is an upgrade: config and enrollment are kept. Flags: `--enroll-stdin` (key on stdin), `--trusted-keys FILE`, `--version vX.Y.Z|latest`, `--from-dir DIR` (release files on disk), `--skip-signature-check` (checksums only; not advised).

Many servers at once, from your machine (needs passwordless sudo):

```sh
read -rs KEY   # paste the enrollment key (it isn't shown), then Enter
for h in web-01 web-02 web-03; do
  printf '%s\n' "$KEY" | ssh "$h" 'cd "$(mktemp -d)" && curl -fsSLO https://github.com/realmwatch/bifrost-agent/releases/download/vX.Y.Z/install.sh && sudo sh install.sh --hub https://bifrost.example.com --trusted-keys-b64 <from the hub> --enroll-stdin'
done
unset KEY
```

For new VMs, cloud-init (the user data holds the key, so keep that key short-lived and limited):

```yaml
#cloud-config
runcmd:
  - [sh, -c, "cd /root && curl -fsSLO https://github.com/realmwatch/bifrost-agent/releases/download/vX.Y.Z/install.sh && printf '%s\n' 'bfe_...' | sh install.sh --hub https://bifrost.example.com --trusted-keys-b64 <from the hub> --enroll-stdin"]
```

To replace an agent on a server that already has one (a re-enrollment key from the server's page in the hub):

```sh
printf '%s\n' 'bfe_...' | sudo bifrost-agent enroll --hub https://bifrost.example.com --key-stdin --force && sudo systemctl restart bifrost-agent
```

Run as root, `enroll` gives `state.json` the owner of its directory (`bifrost`), so the running service can still read it.

### By hand

```sh
make build-all                                   # or take the files from a release and check SHA256SUMS
sudo install -m 0755 bin/bifrost-agent-linux-amd64 /usr/local/bin/bifrost-agent
sudo useradd --system --home-dir /var/lib/bifrost-agent --shell /usr/sbin/nologin bifrost
sudo install -d -m 0700 -o bifrost -g bifrost /var/lib/bifrost-agent
sudo install -d -m 0755 /etc/bifrost-agent
sudo install -m 0644 trusted-keys.json /etc/bifrost-agent/   # exported from the hub's admin UI
bifrost-agent operations sudoers | sudo tee /etc/sudoers.d/bifrost-agent >/dev/null
sudo chmod 0440 /etc/sudoers.d/bifrost-agent && sudo visudo -cf /etc/sudoers.d/bifrost-agent
read -rs KEY && printf '%s\n' "$KEY" | sudo bifrost-agent enroll --hub https://bifrost.example.com --key-stdin; unset KEY
sudo install -m 0644 deploy/bifrost-agent.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now bifrost-agent
```

## Releases

`make dist VERSION=vX.Y.Z` builds the release files into `dist/`: static `bifrost-agent-linux-{amd64,arm64}` binaries (reproducible: `make reproducible`), the unit, `install.sh`, the hub-facing `catalog.json`, and `SHA256SUMS`. Pushing a `vX.Y.Z` tag (matching `internal/version`) runs `.github/workflows/release.yml`: tests and govulncheck, a reproducibility check, then a GitHub release with `SHA256SUMS` signed keylessly with Sigstore (`SHA256SUMS.sigstore.json`) and build provenance attestations. To check a release by hand:

```sh
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/realmwatch/bifrost-agent/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c --ignore-missing SHA256SUMS
```

The agent exits with status 3 when the hub revokes its token (the unit does not restart it); re-enroll with `--force`.

## Running against a local hub

Simulate mode runs nothing on your machine: each operation step logs its argv and reports `simulated`. State tools still read the real system.

```sh
make build
mkdir -p /tmp/bifrost-agent-dev
cp dev/config.json /tmp/bifrost-agent-dev/config.json
# Point hub_url at your hub: http://localhost:8000 (php artisan serve), or an
# https dev domain with "insecure_skip_tls_verify": true for a self-signed cert.
$EDITOR /tmp/bifrost-agent-dev/config.json
# Trusted keys: export them from the hub's admin UI (format in dev/trusted-keys.example.json).
cp ~/Downloads/trusted-keys.json /tmp/bifrost-agent-dev/trusted-keys.json
# Create an enrollment key in the hub, then:
bin/bifrost-agent enroll --config /tmp/bifrost-agent-dev/config.json --hub http://localhost:8000 --key bfe_...
bin/bifrost-agent run --config /tmp/bifrost-agent-dev/config.json
```

Delete `/tmp/bifrost-agent-dev/state` to enroll again from scratch.

## Development

`make test` (or `go test ./...`, about a second), `make lint` (gofmt and `go vet`), `make build`. Tests never touch the network, package managers or systemd: commands go through an injectable runner and file paths through an injectable root. Standard library only.

## Operations

[`operations/`](operations/) is the source of truth for every operation Bifrost can run on a server. Each release compiles them into the binary and publishes the hub-facing part (`bifrost-agent operations export`) as a signed release file, which the hub pins.

## License

[AGPL-3.0](LICENSE).
