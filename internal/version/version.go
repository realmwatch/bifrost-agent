// Package version holds the agent version, overridable at build time with
// -ldflags "-X github.com/realmwatch/bifrost-agent/internal/version.Version=0.1.1".
package version

// Version is the agent version, also used as the operations catalog_version.
var Version = "0.1.0"
