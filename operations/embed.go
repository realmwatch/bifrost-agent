// Package operations embeds the operation definitions in this directory.
// They are the source of truth for what the agent can run; see README.md.
package operations

import "embed"

// FS holds every operation definition, one JSON file per name@version.
//
//go:embed *.json
var FS embed.FS
