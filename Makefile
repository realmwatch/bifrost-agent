VERSION ?= $(shell sed -n 's/^var Version = "\(.*\)"/\1/p' internal/version/version.go)
# A release tag is vX.Y.Z; the binary and its catalog carry X.Y.Z.
BARE_VERSION := $(patsubst v%,%,$(VERSION))
TAG_VERSION := v$(BARE_VERSION)
# Static, reproducible build: no cgo, no local paths, no build ID.
LDFLAGS := -s -w -buildid= -X github.com/realmwatch/bifrost-agent/internal/version.Version=$(BARE_VERSION)
export CGO_ENABLED := 0

# Dev tools run at pinned versions and never enter go.mod or the binary.
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.9.0

.PHONY: build build-all test lint fmt vuln sudoers catalog reproducible dist clean

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/bifrost-agent ./cmd/bifrost-agent

build-all:
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/bifrost-agent-linux-amd64 ./cmd/bifrost-agent
	GOOS=linux GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/bifrost-agent-linux-arm64 ./cmd/bifrost-agent

test:
	go test ./...

lint:
	@test -z "$$(gofmt -l .)" || (gofmt -l .; echo "gofmt needed"; exit 1)
	go vet ./...

fmt:
	gofmt -w .

vuln:
	go run $(GOVULNCHECK) ./...

# Regenerate deploy/sudoers.example after changing operations (a test fails if it is stale).
sudoers:
	go run ./cmd/bifrost-agent operations sudoers > deploy/sudoers.example

# Print the hub-facing catalog, for resources/operations/catalog.json in the hub.
catalog:
	@go run ./cmd/bifrost-agent operations export

# Builds the agent twice from clean caches and checks the binaries match
# byte for byte (pinned toolchain via go.mod, -trimpath, no build ID).
reproducible:
	rm -rf bin/repro && mkdir -p bin/repro
	GOCACHE=$$(mktemp -d) GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/repro/a ./cmd/bifrost-agent & a=$$!; \
	GOCACHE=$$(mktemp -d) GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/repro/b ./cmd/bifrost-agent & b=$$!; \
	wait $$a && wait $$b
	cmp bin/repro/a bin/repro/b && echo "reproducible: $$(sha256sum bin/repro/a | cut -d' ' -f1)"

# Release files: static binaries, the unit, the installer with its default
# version baked in, the hub-facing catalog, and SHA256SUMS over all of them.
# Servers check everything against SHA256SUMS (and its signature) first.
dist:
	rm -rf dist && mkdir -p dist
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/bifrost-agent-linux-amd64 ./cmd/bifrost-agent & a=$$!; \
	GOOS=linux GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/bifrost-agent-linux-arm64 ./cmd/bifrost-agent & b=$$!; \
	wait $$a && wait $$b
	cp deploy/bifrost-agent.service dist/
	sed 's/^AGENT_VERSION=dev /AGENT_VERSION=$(TAG_VERSION) /' deploy/install.sh > dist/install.sh
	grep -q '^AGENT_VERSION=$(TAG_VERSION) ' dist/install.sh
	go run -trimpath -ldflags '$(LDFLAGS)' ./cmd/bifrost-agent operations export > dist/catalog.json
	cd dist && sha256sum * > SHA256SUMS && cat SHA256SUMS

clean:
	rm -rf bin dist
