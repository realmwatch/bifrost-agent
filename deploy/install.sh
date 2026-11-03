#!/bin/sh
# Install the Bifrost agent on a Linux server, in one step.
#
#   curl -fsSLO https://github.com/realmwatch/bifrost-agent/releases/download/vX.Y.Z/install.sh &&
#     sudo sh install.sh --hub https://bifrost.example.com --trusted-keys-b64 <base64> --enroll
#   (then paste the enrollment key when asked; it's never echoed, logged or
#   put on a command line). For many servers: --enroll-stdin.
#
# What it does (as root):
#   1. downloads the agent binary and its systemd unit from the SAME GitHub
#      release and verifies them against SHA256SUMS, and SHA256SUMS against
#      its Sigstore signature, checked with a pinned cosign. Never from the hub.
#   2. creates the unprivileged `bifrost` user, /var/lib/bifrost-agent (0700)
#      and /etc/bifrost-agent, installs the binary, the unit, the sudoers
#      rules for the compiled operations, the trusted keys and config.json
#   3. enrolls with the hub (unless this server is already enrolled), then
#      enables and starts the service and checks it's running.
# Re-running it is an upgrade: config and enrollment are kept.
set -eu
umask 022
export LC_ALL=C
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

AGENT_VERSION=dev # set by `make dist`
REPO=realmwatch/bifrost-agent
RELEASES=${BIFROST_AGENT_RELEASES:-https://github.com/$REPO/releases/download}

BIN=/usr/local/bin/bifrost-agent
UNIT=/etc/systemd/system/bifrost-agent.service
SUDOERS=/etc/sudoers.d/bifrost-agent
ETC=/etc/bifrost-agent
CONFIG=$ETC/config.json
KEYS=$ETC/trusted-keys.json
STATE_DIR=/var/lib/bifrost-agent
STATE=$STATE_DIR/state.json
LIB=/usr/local/lib/bifrost-agent
USER_NAME=bifrost

die() { printf 'bifrost-agent install: %s\n' "$*" >&2; exit 1; }
say() { printf '==> %s\n' "$*" >&2; }
warn() { printf '!!! %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

# ── Release signature ──
# A release's SHA256SUMS must carry a Sigstore signature made by this repo's
# release workflow for a v* tag. cosign checks it: a pinned build, fetched
# once into /usr/local/lib/bifrost-agent and checked against its hash each use.
COSIGN_VERSION=v3.1.4
RELEASE_SIGNER='^https://github.com/realmwatch/bifrost-agent/\.github/workflows/release\.yml@refs/tags/v'

# cosign_bin: print the path of the cosign to check signatures with,
# fetching the pinned build first if it's missing or doesn't match.
cosign_bin() {
	case $(uname -m) in
	x86_64 | amd64) c=amd64 s=424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa ;;
	aarch64 | arm64) c=arm64 s=ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2 ;;
	*) command -v cosign; return ;; # no pinned build: an installed cosign, if any
	esac
	b=$LIB/cosign-$COSIGN_VERSION-$c
	if [ ! -x "$b" ] || ! printf '%s  %s\n' "$s" "$b" | sha256sum -c - >/dev/null 2>&1; then
		printf '==> Fetching cosign %s (once) to check the release signature\n' "$COSIGN_VERSION" >&2
		u=https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/cosign-linux-$c
		install -d -m 0755 "$LIB"
		if have curl; then
			curl -fsSL --proto '=https' --tlsv1.2 -o "$b.tmp" "$u" || return 1
		else
			wget -q -O "$b.tmp" "$u" || return 1
		fi
		if ! printf '%s  %s\n' "$s" "$b.tmp" | sha256sum -c - >/dev/null 2>&1; then
			rm -f "$b.tmp"
			echo "the cosign download doesn't match its pinned hash" >&2
			return 1
		fi
		chmod 0755 "$b.tmp" && mv "$b.tmp" "$b"
	fi
	echo "$b"
}

# verify_release DIR: check DIR/SHA256SUMS against its Sigstore signature
# (DIR/SHA256SUMS.sigstore.json), or exit.
verify_release() {
	[ -s "$1/SHA256SUMS.sigstore.json" ] || die "the release has no signature (SHA256SUMS.sigstore.json); not installing it"
	cosign=$(cosign_bin) || cosign=''
	[ -n "$cosign" ] || die "can't check the release signature: no cosign for $(uname -m); install cosign, or pass --skip-signature-check"
	HOME=$1 "$cosign" verify-blob "$1/SHA256SUMS" --bundle "$1/SHA256SUMS.sigstore.json" \
		--certificate-identity-regexp "$RELEASE_SIGNER" \
		--certificate-oidc-issuer https://token.actions.githubusercontent.com >"$1/cosign.log" 2>&1 ||
		die "SHA256SUMS signature verification FAILED; not installing it: $(tail -n 1 "$1/cosign.log")"
	say "Sigstore signature verified"
}

usage() {
	cat >&2 <<'EOF'
usage: install.sh --hub https://bifrost.example.com [--enroll | --enroll-stdin]
                  [--trusted-keys FILE | --trusted-keys-b64 B64]
                  [--version vX.Y.Z | latest] [--from-dir DIR] [--skip-signature-check]

  --hub               the hub's URL (https://); needed for the first install
  --enroll            prompt for an enrollment key (from the hub's Add a server
                      page), without echo. A server that's already enrolled
                      keeps its enrollment: re-running is an upgrade.
  --enroll-stdin      read the enrollment key from stdin (ssh loops, cloud-init)
  --trusted-keys      install the trusted keys file exported from the hub
  --trusted-keys-b64  the same file, base64-encoded (the hub's command carries it)
  --version           release to install (default: the release this script came
                      from; "latest" for the newest)
  --from-dir          install from a local directory holding the release files
  --skip-signature-check
                      check checksums only, not the release's Sigstore signature
                      (where cosign can't run; not advised)
EOF
	exit 2
}

hub='' enroll='' key='' keys_file='' keys_b64='' version=$AGENT_VERSION from_dir='' sigcheck=1
while [ $# -gt 0 ]; do
	case $1 in
	--hub) hub=${2:-}; shift ;;
	--enroll) enroll=prompt ;;
	--enroll-stdin) IFS= read -r key || [ -n "$key" ]; enroll=stdin ;;
	--trusted-keys) keys_file=${2:-}; shift ;;
	--trusted-keys-b64) keys_b64=${2:-}; shift ;;
	--version) version=${2:-}; shift ;;
	--from-dir) from_dir=${2:-}; shift ;;
	--skip-signature-check) sigcheck=0 ;;
	-h | --help) usage ;;
	*) usage ;;
	esac
	shift
done

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
have systemctl || die "this installer needs systemd"
have sha256sum || die "need sha256sum"
[ -z "$keys_file" ] || [ -z "$keys_b64" ] || die "use --trusted-keys or --trusted-keys-b64, not both"
[ -z "$keys_file" ] || [ -r "$keys_file" ] || die "cannot read $keys_file"

case $(uname -m) in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) die "no agent build for $(uname -m) (amd64 and arm64 only)" ;;
esac

enrolled=0
[ ! -s "$STATE" ] || enrolled=1
if [ "$enrolled" = 0 ]; then
	[ -n "$enroll" ] || die "this server isn't enrolled yet; pass --enroll (or --enroll-stdin) with --hub"
	[ -n "$hub" ] || die "--hub is needed for the first install"
fi
if [ -n "$hub" ]; then
	case $hub in
	https://*) ;;
	http://127.0.0.1[:/]* | http://127.0.0.1 | http://localhost[:/]* | http://localhost) ;; # local hubs only
	*) die "--hub must be an https:// URL" ;;
	esac
	case $hub in *[!A-Za-z0-9.:/_%-]*) die "malformed --hub $hub" ;; esac
fi

if [ "$enroll" = prompt ] && [ "$enrolled" = 0 ]; then
	[ -r /dev/tty ] || die "no terminal to ask for the enrollment key; use --enroll-stdin"
	printf 'Enrollment key (from the hub'"'"'s Add a server page): ' >/dev/tty
	stty -echo </dev/tty 2>/dev/null || true
	IFS= read -r key </dev/tty || true
	stty echo </dev/tty 2>/dev/null || true
	printf '\n' >/dev/tty
fi
key=$(printf '%s' "$key" | tr -d ' \t\r\n')
if [ "$enrolled" = 0 ]; then
	case $key in
	bfe_*) ;;
	*) die "missing or malformed enrollment key (it starts with bfe_)" ;;
	esac
	case $key in *[!A-Za-z0-9_-]*) die "malformed enrollment key" ;; esac
fi

if [ "$version" = latest ] && [ -z "$from_dir" ]; then
	have curl || die "--version latest needs curl"
	version=$(curl -fsSL --proto '=https' --tlsv1.2 -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest") ||
		die "could not find the latest release"
	version=${version##*/}
fi
case $version in v[0-9]*.[0-9]*.[0-9]* | dev) ;; *) die "bad --version $version" ;; esac
[ -n "$from_dir" ] || [ "$version" != dev ] || die "this script isn't from a release; pass --version vX.Y.Z or --from-dir"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fetch() { # fetch NAME into $work; returns 1 if it's missing
	if [ -n "$from_dir" ]; then
		[ -f "$from_dir/$1" ] || return 1
		cp "$from_dir/$1" "$work/$1"
	elif have curl; then
		curl -fsSL --proto '=https' --tlsv1.2 -o "$work/$1" "$RELEASES/$version/$1"
	elif have wget; then
		wget -q -O "$work/$1" "$RELEASES/$version/$1"
	else
		die "need curl or wget"
	fi
}

say "Fetching Bifrost agent ${version}${from_dir:+ from $from_dir}"
for f in SHA256SUMS "bifrost-agent-linux-$arch" bifrost-agent.service; do
	fetch "$f" || die "download failed: $f"
done
if [ "$sigcheck" = 1 ]; then
	fetch SHA256SUMS.sigstore.json || true
	verify_release "$work"
else
	warn "NOT checking the release signature (--skip-signature-check): checksums only catch corruption, not tampering"
fi
(cd "$work" && sha256sum -c --ignore-missing --strict SHA256SUMS >/dev/null) || die "checksum mismatch; not installing"
for f in "bifrost-agent-linux-$arch" bifrost-agent.service; do
	grep -q "  $f\$" "$work/SHA256SUMS" || die "$f isn't listed in SHA256SUMS; not installing"
done
say "Checksums verified"

# Trusted keys: checked with the new binary's own strict parser before use.
chmod 0755 "$work/bifrost-agent-linux-$arch"
new_bin=$work/bifrost-agent-linux-$arch
if [ -n "$keys_b64" ]; then
	printf '%s' "$keys_b64" | base64 -d >"$work/trusted-keys.json" 2>/dev/null || die "--trusted-keys-b64 isn't valid base64"
	keys_file=$work/trusted-keys.json
fi
if [ -n "$keys_file" ]; then
	"$new_bin" trusted-keys check "$keys_file" >/dev/null || die "the trusted keys file isn't valid; not installing"
fi

say "Installing"
if ! id "$USER_NAME" >/dev/null 2>&1; then
	useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin "$USER_NAME"
fi
install -d -m 0700 -o "$USER_NAME" -g "$USER_NAME" "$STATE_DIR"
install -d -m 0755 "$ETC"
install -m 0755 "$new_bin" "$BIN.new" && mv "$BIN.new" "$BIN"
install -m 0644 "$work/bifrost-agent.service" "$UNIT"

"$BIN" operations sudoers --user "$USER_NAME" >"$work/sudoers"
visudo -cqf "$work/sudoers" >/dev/null || die "the generated sudoers rules don't parse; not installing them"
install -m 0440 -o root -g root "$work/sudoers" "$SUDOERS"

if [ -n "$keys_file" ]; then
	install -m 0644 -o root -g root "$keys_file" "$KEYS"
	say "Trusted keys installed at $KEYS"
elif [ ! -s "$KEYS" ]; then
	warn "no trusted keys at $KEYS: the agent will reject every approved change until an admin installs them (--trusted-keys)"
fi

if [ ! -s "$CONFIG" ]; then
	printf '{\n  "hub_url": "%s"\n}\n' "${hub%/}" >"$work/config.json"
	install -m 0644 -o root -g root "$work/config.json" "$CONFIG"
fi

if [ "$enrolled" = 0 ]; then
	say "Enrolling this server with the hub"
	# The key goes to the agent on stdin, never in process arguments.
	if ! out=$(printf '%s\n' "$key" | "$BIN" enroll --hub "${hub%/}" --key-stdin --config "$CONFIG" 2>&1); then
		printf '%s\n' "$out" >&2
		die "enrollment failed"
	fi
	printf '%s\n' "$out" >&2
	chown "$USER_NAME:$USER_NAME" "$STATE"
	chmod 0600 "$STATE"
elif [ -n "$enroll" ]; then
	say "Already enrolled ($STATE); upgrading in place and keeping the enrollment"
fi
key=''

systemctl daemon-reload
systemctl enable bifrost-agent >/dev/null 2>&1
systemctl restart bifrost-agent
i=0
while [ $i -lt 10 ]; do
	systemctl is-active --quiet bifrost-agent && break
	sleep 1
	i=$((i + 1))
done
if ! systemctl is-active --quiet bifrost-agent; then
	journalctl -u bifrost-agent -n 20 --no-pager >&2 2>/dev/null || true
	die "the agent didn't start; see journalctl -u bifrost-agent"
fi
say "Bifrost agent $("$BIN" version) is running"
