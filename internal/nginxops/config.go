// Package nginxops changes nginx's configuration for the nginx.* operations:
// turning HTTP/2 off everywhere nginx reads config and back on, and
// checking the configuration after a package upgrade. It reads the
// configuration the way nginx does, from nginx.conf through every include
// in place, and runs as root through sudo.
package nginxops

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// confDir is nginx's prefix for relative includes.
	confDir  = "/etc/nginx"
	mainConf = "/etc/nginx/nginx.conf"
	// maxFiles and maxDepth bound a configuration that includes itself or
	// globs far too much.
	maxFiles = 2000
	maxDepth = 16
)

// token is one word or one of ; { } in a file, with where it starts.
type token struct {
	text   string
	offset int
	line   int // 1-based
	quoted bool
}

// file is one configuration file nginx reads.
type file struct {
	path    string // as nginx names it (an include may go through a symlink)
	real    string // the file itself, symlinks resolved
	content []byte
	tokens  []token
}

// directive is one directive in context: its name, its arguments, the
// blocks it sits in (outermost first, such as ["http", "server"]) and its
// file.
type directive struct {
	name    token
	args    []token
	context []string
	file    *file
	block   int // the innermost block it sits in (0 for none)
	opens   int // the block it opens, if it's a block directive
}

// config is nginx's configuration: every file it reads, in the order it
// reads them, and every directive in that order.
type config struct {
	files      []*file
	directives []directive
	skipped    []string // include patterns that weren't read, and why
	blocks     int
}

// tokenize splits nginx configuration into words and ; { }, dropping
// comments. Quoted strings keep their content without the quotes.
func tokenize(b []byte) ([]token, error) {
	var out []token
	line := 1
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c == '\n':
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '#':
			for i < len(b) && b[i] != '\n' {
				i++
			}
		case c == ';' || c == '{' || c == '}':
			out = append(out, token{text: string(c), offset: i, line: line})
			i++
		case c == '"' || c == '\'':
			start, startLine := i, line
			i++
			var sb strings.Builder
			for i < len(b) && b[i] != c {
				if b[i] == '\\' && i+1 < len(b) {
					i++
				}
				if b[i] == '\n' {
					line++
				}
				sb.WriteByte(b[i])
				i++
			}
			if i >= len(b) {
				return nil, fmt.Errorf("line %d: unterminated quote", startLine)
			}
			i++
			out = append(out, token{text: sb.String(), offset: start, line: startLine, quoted: true})
		default:
			start := i
			for i < len(b) && !strings.ContainsRune(" \t\r\n;{}", rune(b[i])) {
				if b[i] == '\\' && i+1 < len(b) {
					i++
				}
				i++
			}
			out = append(out, token{text: string(b[start:i]), offset: start, line: line})
		}
	}
	return out, nil
}

// load reads nginx's configuration under root ("" in production).
func load(root string) (*config, error) {
	c := &config{}
	seen := map[string]*file{}
	if err := c.walk(root, mainConf, nil, nil, 0, seen); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *config) walk(root, path string, context []string, ids []int, depth int, seen map[string]*file) error {
	if depth > maxDepth {
		return fmt.Errorf("%s: includes nest more than %d deep", path, maxDepth)
	}
	real, err := filepath.EvalSymlinks(filepath.Join(root, path))
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	f, ok := seen[real]
	if !ok {
		if len(seen) >= maxFiles {
			return fmt.Errorf("nginx reads more than %d files; refusing to go on", maxFiles)
		}
		content, err := os.ReadFile(real)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		tokens, err := tokenize(content)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		f = &file{path: path, real: real, content: content, tokens: tokens}
		seen[real] = f
		c.files = append(c.files, f)
	}
	stack := append([]string(nil), context...)
	idStack := append([]int(nil), ids...)
	inner := func() int {
		if len(idStack) == 0 {
			return 0
		}
		return idStack[len(idStack)-1]
	}
	var words []token
	for _, t := range f.tokens {
		if t.quoted || (t.text != ";" && t.text != "{" && t.text != "}") {
			words = append(words, t)
			continue
		}
		switch t.text {
		case ";":
			if len(words) == 0 {
				continue
			}
			d := directive{name: words[0], args: words[1:], context: append([]string(nil), stack...), file: f, block: inner()}
			c.directives = append(c.directives, d)
			if d.name.text == "include" && len(d.args) == 1 {
				if err := c.include(root, d.args[0].text, stack, idStack, depth, seen); err != nil {
					return err
				}
			}
		case "{":
			if len(words) == 0 {
				return fmt.Errorf("%s:%d: a block without a name", path, t.line)
			}
			c.blocks++
			c.directives = append(c.directives, directive{name: words[0], args: words[1:], context: append([]string(nil), stack...), file: f, block: inner(), opens: c.blocks})
			stack = append(stack, words[0].text)
			idStack = append(idStack, c.blocks)
		case "}":
			if len(stack) <= len(context) {
				return fmt.Errorf("%s:%d: unexpected }", path, t.line)
			}
			stack = stack[:len(stack)-1]
			idStack = idStack[:len(idStack)-1]
		}
		words = nil
	}
	if len(stack) != len(context) {
		return fmt.Errorf("%s: a block isn't closed", path)
	}
	return nil
}

// include reads what one include names, in place, as nginx does: a path
// relative to /etc/nginx, and globs in sorted order.
func (c *config) include(root, pattern string, context []string, ids []int, depth int, seen map[string]*file) error {
	if strings.ContainsAny(pattern, "$\x00") {
		c.skipped = append(c.skipped, pattern+" (a variable)")
		return nil
	}
	if !filepath.IsAbs(pattern) {
		pattern = filepath.Join(confDir, pattern)
	}
	if !strings.ContainsAny(pattern, "*?[") {
		return c.walk(root, pattern, context, ids, depth+1, seen)
	}
	matches, err := filepath.Glob(filepath.Join(root, pattern))
	if err != nil {
		return fmt.Errorf("include %s: %w", pattern, err)
	}
	sort.Strings(matches)
	for _, m := range matches {
		if info, err := os.Stat(m); err != nil || info.IsDir() {
			continue
		}
		rel := strings.TrimPrefix(m, filepath.Clean(root))
		if root == "" {
			rel = m
		}
		if err := c.walk(root, rel, context, ids, depth+1, seen); err != nil {
			return err
		}
	}
	return nil
}

// in says whether the directive sits directly in a block with this path,
// such as in("http", "server").
func (d directive) in(blocks ...string) bool {
	if len(d.context) != len(blocks) {
		return false
	}
	for i, b := range blocks {
		if d.context[i] != b {
			return false
		}
	}
	return true
}
