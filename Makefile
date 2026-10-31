VERSION ?= $(shell sed -n 's/^var Version = "\(.*\)"/\1/p' internal/version/version.go)
LDFLAGS := -s -w -X github.com/realmwatch/bifrost-agent/internal/version.Version=$(VERSION)
export CGO_ENABLED := 0

.PHONY: build build-all test lint fmt sudoers catalog clean

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

# Regenerate deploy/sudoers.example after changing operations (a test fails if it is stale).
sudoers:
	go run ./cmd/bifrost-agent operations sudoers > deploy/sudoers.example

# Print the hub-facing catalog, for resources/operations/catalog.json in the hub.
catalog:
	@go run ./cmd/bifrost-agent operations export

clean:
	rm -rf bin
