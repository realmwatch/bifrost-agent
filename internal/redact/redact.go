// Package redact masks obvious secrets in text the agent sends to the hub.
package redact

import "regexp"

// Mask replaces a redacted value.
const Mask = "[REDACTED]"

var rules = []struct {
	re   *regexp.Regexp
	repl string
}{
	// Authorization headers: keep the scheme name out too.
	{regexp.MustCompile(`(?i)\b((?:proxy-)?authorization)(\s*[:=]\s*)[^\r\n]+`), "${1}${2}" + Mask},
	// key=value and key: value pairs with secret-looking keys.
	{regexp.MustCompile(`(?i)\b([a-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credentials?))(["']?\s*[=:]\s*["']?)([^\s"'&,;]+)`), "${1}${2}" + Mask},
	// Credentials in URLs: scheme://user:pass@host.
	{regexp.MustCompile(`([a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s@/]+@`), "${1}" + Mask + "@"},
	// Bearer tokens anywhere.
	{regexp.MustCompile(`(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]+`), "${1}" + Mask},
	// Bifrost agent and enrollment tokens.
	{regexp.MustCompile(`\bbf[ae]_[A-Za-z0-9_-]+`), Mask},
	// PEM private key bodies.
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`), Mask},
}

// String masks secrets in s.
func String(s string) string {
	for _, r := range rules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}

// Value masks secrets in every string inside a decoded JSON-like value
// (maps, slices and strings), returning a new value.
func Value(v any) any {
	switch tv := v.(type) {
	case string:
		return String(tv)
	case []string:
		out := make([]string, len(tv))
		for i, s := range tv {
			out[i] = String(s)
		}
		return out
	case []any:
		out := make([]any, len(tv))
		for i, e := range tv {
			out[i] = Value(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(tv))
		for k, e := range tv {
			out[k] = Value(e)
		}
		return out
	}
	return v
}
