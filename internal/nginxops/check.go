package nginxops

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// packageDefault is the example site nginx.org's package installs. Ubuntu's
// nginx.conf includes conf.d/*.conf before sites-enabled, so when an
// upgrade to nginx.org's package adds it, its server can become the default
// for port 80 in place of the host's own.
const packageDefault = "/etc/nginx/conf.d/default.conf"

var portRe = regexp.MustCompile(`^[0-9]+$`)

// Check runs nginx -t, then warns about anything an nginx package upgrade
// may have changed that nginx -t accepts: nginx.org's conf.d/default.conf
// answering as an address's default server ahead of the host's own sites.
// Warnings don't fail it.
func (e *Env) Check(ctx context.Context) error {
	if _, err := os.Stat(e.path(nginxBin)); err != nil {
		return fmt.Errorf("refused: no nginx at %s", nginxBin)
	}
	if err := e.check(ctx, "nginx -t", nginxBin, "-t"); err != nil {
		return err
	}
	e.say("nginx -t passed")
	c, err := load(e.Root)
	if err != nil {
		e.say("WARNING: couldn't read nginx's configuration to check its default servers: %v", err)
		return nil
	}
	for _, w := range defaultShadows(c) {
		e.say("WARNING: %s", w)
	}
	return nil
}

type server struct {
	file    *file
	line    int
	listens map[string]bool // address -> default_server
}

// defaultShadows says where packageDefault's server is nginx's default
// server for an address that another file's server also listens on: no
// server there is marked default_server, and it comes first.
func defaultShadows(c *config) []string {
	var servers []*server
	byBlock := map[int]*server{}
	for _, d := range c.directives {
		if d.name.text == "server" && d.opens > 0 && d.in("http") {
			s := &server{file: d.file, line: d.name.line, listens: map[string]bool{}}
			servers = append(servers, s)
			byBlock[d.opens] = s
		}
	}
	for _, d := range c.directives {
		s := byBlock[d.block]
		if s == nil || d.name.text != "listen" || !d.in("http", "server") || len(d.args) == 0 {
			continue
		}
		addr := listenAddress(d.args[0].text)
		def := false
		for _, a := range d.args[1:] {
			def = def || a.text == "default_server" || a.text == "default"
		}
		s.listens[addr] = s.listens[addr] || def
	}
	for _, s := range servers {
		if len(s.listens) == 0 {
			s.listens["*:80"] = false // a server without listen gets *:80
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, s := range servers {
		if s.file.path != packageDefault {
			continue
		}
		for addr := range s.listens {
			if seen[addr] {
				continue
			}
			seen[addr] = true
			var first, other *server
			marked := false
			for _, o := range servers {
				def, ok := o.listens[addr]
				if !ok {
					continue
				}
				marked = marked || def
				if first == nil {
					first = o
				}
				if other == nil && o.file.path != packageDefault {
					other = o
				}
			}
			if !marked && first == s && other != nil {
				out = append(out, fmt.Sprintf("%s (from nginx.org's package) is now the default server for %s, ahead of %s:%d, so requests for names no site claims, and plain-IP requests, get its page. Remove it, or mark the host's own server default_server.", packageDefault, addr, other.file.path, other.line))
			}
		}
	}
	return out
}

// listenAddress normalises a listen's address the way nginx groups them:
// 80 and 0.0.0.0:80 are *:80, [::]:443 stays as it is, and a bare host
// means port 80.
func listenAddress(a string) string {
	switch {
	case strings.HasPrefix(a, "unix:"):
		return a
	case portRe.MatchString(a):
		return "*:" + a
	case strings.HasPrefix(a, "["):
		if i := strings.LastIndex(a, "]:"); i >= 0 {
			return a
		}
		return a + ":80"
	}
	host, port, ok := strings.Cut(a, ":")
	if !ok {
		host, port = a, "80"
	}
	if host == "0.0.0.0" {
		host = "*"
	}
	return host + ":" + port
}
