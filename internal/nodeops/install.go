package nodeops

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// releaseKeyring holds the Node.js release team's active signing keys, the
// keys nodejs.org's SHASUMS256.txt.sig is made with. It is the
// gpg-only-active-keys/pubring.kbx keyring from
// https://github.com/nodejs/release-keys (commit 481637f8, 2026-09-01),
// exported as a plain OpenPGP keyring for gpgv. When Node.js adds a
// release key, trusting it takes an agent release: until then a release
// signed only by the new key fails to verify and installs fail closed.
//
//go:embed node-release-keys.gpg
var releaseKeyring []byte

const (
	maxIndexBytes   = 16 << 20
	maxSumsBytes    = 1 << 20
	maxSigBytes     = 64 << 10
	maxTarballBytes = 200 << 20
	maxTreeBytes    = 1 << 30
	maxTreeEntries  = 100000
)

// release is one verified nodejs.org release, downloaded.
type release struct {
	version string // X.Y.Z
	tarball string // the downloaded file
	top     string // the tarball's top directory
}

func nodeArch(goarch string) (string, error) {
	switch goarch {
	case "amd64":
		return "x64", nil
	case "arm64":
		return "arm64", nil
	}
	return "", fmt.Errorf("refused: nodejs.org builds aren't supported on %s here (amd64 and arm64 only)", goarch)
}

// fetch downloads url, at most limit bytes, into w.
func (e *Env) fetch(ctx context.Context, url string, limit int64, w io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := e.client().Do(req)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetching %s: HTTP %d", url, resp.StatusCode)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fmt.Errorf("fetching %s: %w", url, err)
	}
	if n > limit {
		return fmt.Errorf("fetching %s: larger than %d bytes, refused", url, limit)
	}
	return nil
}

func (e *Env) fetchBytes(ctx context.Context, url string, limit int64) ([]byte, error) {
	var b strings.Builder
	if err := e.fetch(ctx, url, limit, &b); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

// newest finds the newest release of major on nodejs.org.
func (e *Env) newest(ctx context.Context, major string) (string, error) {
	b, err := e.fetchBytes(ctx, e.distURL()+"/index.json", maxIndexBytes)
	if err != nil {
		return "", err
	}
	var index []struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(b, &index); err != nil {
		return "", fmt.Errorf("reading nodejs.org's release index: %w", err)
	}
	best := ""
	for _, r := range index {
		m := versionRe.FindStringSubmatch(r.Version)
		if m == nil || m[1] != major {
			continue
		}
		v := strings.TrimPrefix(r.Version, "v")
		if best == "" || versionLess(best, v) {
			best = v
		}
	}
	if best == "" {
		return "", fmt.Errorf("refused: nodejs.org has no release of Node.js %s", major)
	}
	return best, nil
}

// download fetches version's tarball into dir and verifies it: gpgv checks
// SHASUMS256.txt against the compiled-in release keys, then the tarball's
// SHA-256 must match its line there.
func (e *Env) download(ctx context.Context, version, dir string) (*release, error) {
	arch, err := nodeArch(e.arch())
	if err != nil {
		return nil, err
	}
	base := e.distURL() + "/v" + version + "/"
	sums, err := e.fetchBytes(ctx, base+"SHASUMS256.txt", maxSumsBytes)
	if err != nil {
		return nil, err
	}
	sig, err := e.fetchBytes(ctx, base+"SHASUMS256.txt.sig", maxSigBytes)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{"SHASUMS256.txt": sums, "SHASUMS256.txt.sig": sig, "node-release-keys.gpg": releaseKeyring}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			return nil, err
		}
	}
	_, stderr, code, err := e.run(ctx, nil, "/usr/bin/gpgv", "--homedir", dir, "--keyring", filepath.Join(dir, "node-release-keys.gpg"),
		filepath.Join(dir, "SHASUMS256.txt.sig"), filepath.Join(dir, "SHASUMS256.txt"))
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("refused: SHASUMS256.txt for v%s isn't signed by a Node.js release key this agent trusts (gpgv status %d). "+
			"If Node.js has added a release key, trusting it takes an agent release.\n%s", version, code, tail(stderr))
	}
	e.say("SHASUMS256.txt for v%s is signed by a Node.js release key", version)

	top := "node-v" + version + "-linux-" + arch
	name := top + ".tar.gz"
	want := ""
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[1] == name {
			want = strings.ToLower(f[0])
		}
	}
	if len(want) != 64 {
		return nil, fmt.Errorf("refused: SHASUMS256.txt for v%s has no line for %s", version, name)
	}

	tarball := filepath.Join(dir, name)
	f, err := os.OpenFile(tarball, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	err = e.fetch(ctx, base+name, maxTarballBytes, io.MultiWriter(f, h))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return nil, fmt.Errorf("refused: %s has SHA-256 %s, but the signed SHASUMS256.txt says %s", name, got, want)
	}
	e.say("%s matches its signed SHA-256", name)
	return &release{version: version, tarball: tarball, top: top}, nil
}

// extract unpacks a verified tarball into dest (which must not exist),
// stripping its top directory. It refuses absolute paths, "..", links
// that point outside the tree, anything but files, directories and
// symlinks, and entries below a symlink. Everything is root:root,
// directories 0755, files keep their exec bits without group or other
// write.
func (e *Env) extract(r *release, dest string) error {
	f, err := os.Open(r.tarball)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("reading %s: %w", filepath.Base(r.tarball), err)
	}
	tr := tar.NewReader(gz)
	if err := os.Mkdir(dest, 0o755); err != nil {
		return err
	}
	if err := own(dest, 0o755); err != nil {
		return err
	}
	links := map[string]bool{}
	var total int64
	for n := 0; ; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("reading %s: %w", filepath.Base(r.tarball), err)
		}
		if n > maxTreeEntries {
			return fmt.Errorf("refused: the tarball has more than %d entries", maxTreeEntries)
		}
		if h.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		rel, err := entryPath(h.Name, r.top)
		if err != nil {
			return err
		}
		if rel == "" {
			continue // the top directory itself
		}
		for p := path.Dir(rel); p != "."; p = path.Dir(p) {
			if links[p] {
				return fmt.Errorf("refused: tarball entry %q is below the symlink %s", h.Name, p)
			}
		}
		full := filepath.Join(dest, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(full, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
			if info, err := os.Lstat(full); err != nil || !info.IsDir() {
				return fmt.Errorf("refused: tarball entry %q isn't a directory where one was expected", h.Name)
			}
			if err := own(full, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			total += h.Size
			if total > maxTreeBytes {
				return fmt.Errorf("refused: the tarball unpacks to more than %d bytes", maxTreeBytes)
			}
			out, err := os.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return fmt.Errorf("unpacking %q: %w", h.Name, err)
			}
			_, err = io.Copy(out, io.LimitReader(tr, h.Size))
			if cerr := out.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return fmt.Errorf("unpacking %q: %w", h.Name, err)
			}
			if err := own(full, fs.FileMode(h.Mode)&0o777&^0o022|0o400); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := checkLink(rel, h.Linkname); err != nil {
				return fmt.Errorf("refused: tarball entry %q: %w", h.Name, err)
			}
			if err := os.Symlink(h.Linkname, full); err != nil {
				return fmt.Errorf("unpacking %q: %w", h.Name, err)
			}
			if os.Geteuid() == 0 {
				if err := os.Lchown(full, 0, 0); err != nil {
					return err
				}
			}
			links[rel] = true
		default:
			return fmt.Errorf("refused: tarball entry %q has type %q; only files, directories and symlinks are allowed", h.Name, string(h.Typeflag))
		}
	}
	return nil
}

// entryPath checks a tarball entry's name and returns it relative to the
// top directory.
func entryPath(name, top string) (string, error) {
	if strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("refused: tarball entry %q has an absolute or unusual path", name)
	}
	for _, part := range strings.Split(strings.TrimSuffix(name, "/"), "/") {
		if part == ".." {
			return "", fmt.Errorf("refused: tarball entry %q leaves the tree", name)
		}
	}
	clean := path.Clean(name)
	first, rest, _ := strings.Cut(clean, "/")
	if first != top {
		return "", fmt.Errorf("refused: tarball entry %q isn't under %s/", name, top)
	}
	return rest, nil
}

// checkLink allows a symlink only when it is relative and stays inside the
// tree.
func checkLink(rel, target string) error {
	if target == "" || strings.HasPrefix(target, "/") || strings.ContainsRune(target, 0) {
		return fmt.Errorf("symlink to %q isn't relative", target)
	}
	resolved := path.Join(path.Dir(rel), target)
	if resolved == ".." || strings.HasPrefix(resolved, "../") || resolved == "." {
		return fmt.Errorf("symlink to %q points outside the tree", target)
	}
	return nil
}

// own sets root:root (when running as root) and mode.
func own(p string, mode fs.FileMode) error {
	if os.Geteuid() == 0 {
		if err := os.Lchown(p, 0, 0); err != nil {
			return err
		}
	}
	return os.Chmod(p, mode)
}

// stage downloads, verifies and unpacks the newest release of major into
// /opt/node/.NN.new and checks it runs. The caller renames it into place,
// or removes it.
func (e *Env) stage(ctx context.Context, major, version string) (string, error) {
	root := e.path(InstallRoot)
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", err
	}
	staged := filepath.Join(root, "."+major+".new")
	if err := os.RemoveAll(staged); err != nil {
		return "", err
	}
	dl, err := os.MkdirTemp(root, "."+major+".download-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dl)
	r, err := e.download(ctx, version, dl)
	if err != nil {
		return "", err
	}
	if err := e.extract(r, staged); err != nil {
		os.RemoveAll(staged)
		return "", err
	}
	if err := e.checkTree(ctx, staged, version); err != nil {
		os.RemoveAll(staged)
		return "", err
	}
	return staged, nil
}

// checkTree confirms an unpacked tree is Node.js version.
func (e *Env) checkTree(ctx context.Context, dir, version string) error {
	if _, err := os.Stat(filepath.Join(dir, "include/node/node_version.h")); err != nil {
		return errors.New("the unpacked tree has no include/node/node_version.h")
	}
	got, err := e.nodeVersion(ctx, filepath.Join(dir, "bin/node"))
	if err != nil {
		return err
	}
	if got != version {
		return fmt.Errorf("the unpacked node says v%s, not v%s", got, version)
	}
	return nil
}

// Install puts the newest Node.js major release from nodejs.org at
// /opt/node/NN. It refuses if that already exists.
func (e *Env) Install(ctx context.Context, major string) error {
	if err := checkMajor(major); err != nil {
		return err
	}
	if err := e.checkHost(); err != nil {
		return err
	}
	dest := e.path(installDir(major))
	if _, err := os.Lstat(dest); err == nil {
		return fmt.Errorf("refused: %s already exists; use nodejs.update to move it to a newer release", installDir(major))
	}
	version, err := e.newest(ctx, major)
	if err != nil {
		return err
	}
	e.say("Installing Node.js v%s at %s", version, installDir(major))
	staged, err := e.stage(ctx, major, version)
	if err != nil {
		return err
	}
	if err := os.Rename(staged, dest); err != nil {
		os.RemoveAll(staged)
		return err
	}
	e.say("Node.js v%s is installed at %s. Nothing uses it yet.", version, installDir(major))
	return nil
}

// Update moves /opt/node/NN to the newest release of its major, keeping the
// old tree as /opt/node/.NN.previous, and restarts what runs it. If one of
// them isn't running 10 s later, it swaps the old tree back.
func (e *Env) Update(ctx context.Context, major string) error {
	if err := checkMajor(major); err != nil {
		return err
	}
	if err := e.checkHost(); err != nil {
		return err
	}
	dest := e.path(installDir(major))
	if info, err := os.Lstat(dest); err != nil || !info.IsDir() {
		return fmt.Errorf("refused: %s isn't installed; use nodejs.install", installDir(major))
	}
	current, err := e.headerVersion(dest)
	if err != nil {
		return err
	}
	version, err := e.newest(ctx, major)
	if err != nil {
		return err
	}
	if !versionLess(current, version) {
		e.say("%s is already at v%s, the newest Node.js %s release: nothing to do", installDir(major), current, major)
		return nil
	}
	bin := installDir(major) + "/bin/node"
	targets, err := e.targetsFor(ctx, bin, true)
	if err != nil {
		return err
	}
	e.say("Updating %s from v%s to v%s", installDir(major), current, version)
	staged, err := e.stage(ctx, major, version)
	if err != nil {
		return err
	}
	previous := e.path(InstallRoot + "/." + major + ".previous")
	if err := os.RemoveAll(previous); err != nil {
		os.RemoveAll(staged)
		return err
	}
	if err := os.Rename(dest, previous); err != nil {
		os.RemoveAll(staged)
		return err
	}
	if err := os.Rename(staged, dest); err != nil {
		if rerr := os.Rename(previous, dest); rerr != nil {
			return fmt.Errorf("%w; and putting v%s back failed: %v", err, current, rerr)
		}
		os.RemoveAll(staged)
		return err
	}
	e.say("v%s is in place; v%s is kept at %s", version, current, e.host(previous))

	err = e.restart(ctx, targets)
	if err == nil {
		err = e.healthy(ctx, targets)
	}
	if err == nil {
		e.say("%s is at Node.js v%s", installDir(major), version)
		return nil
	}

	// Swap back.
	failed := e.path(InstallRoot + "/." + major + ".failed")
	os.RemoveAll(failed)
	if serr := os.Rename(dest, failed); serr != nil {
		return fmt.Errorf("%w; moving v%s aside failed too: %v", err, version, serr)
	}
	if serr := os.Rename(previous, dest); serr != nil {
		return fmt.Errorf("%w; putting v%s back failed too: %v", err, current, serr)
	}
	os.RemoveAll(failed)
	if rerr := e.restart(ctx, targets); rerr != nil {
		return fmt.Errorf("%w; v%s is back but restarting failed: %v", err, current, rerr)
	}
	return fmt.Errorf("%w; v%s was put back and restarted", err, current)
}
