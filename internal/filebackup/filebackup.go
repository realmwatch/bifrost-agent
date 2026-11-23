// Package filebackup backs up the paths an operation is about to change,
// with a manifest, and puts them back: files with their content, mode and
// owner, symlinks with their target, and absent paths as absent. Every path
// is a host path under root, which tests replace.
package filebackup

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

const (
	// StampLayout names a backup directory by its UTC time.
	StampLayout = "20060102T150405Z"
	// RestoredMark is written into a backup once its paths are back (or
	// were never left changed), so it isn't restored twice.
	RestoredMark = "restored"
	manifestName = "manifest.json"
)

// Entry is one path as it was before the change.
type Entry struct {
	Path   string `json:"path"`
	Group  string `json:"group"`
	Kind   string `json:"kind"` // file, symlink or absent
	Backup string `json:"backup,omitempty"`
	Link   string `json:"link,omitempty"`
	Mode   uint32 `json:"mode,omitempty"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
}

// Backup is one backup directory and its manifest.
type Backup[M any] struct {
	Dir string
	M   M
}

// NewDir creates a new backup directory under backupRoot, named by now,
// with the root directory kept private.
func NewDir(root, backupRoot string, now time.Time) (string, error) {
	dirRoot := filepath.Join(root, backupRoot)
	if err := os.MkdirAll(dirRoot, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(dirRoot, 0o700); err != nil {
		return "", err
	}
	stamp := now.UTC().Format(StampLayout)
	dir := filepath.Join(dirRoot, stamp)
	for i := 2; ; i++ {
		err := os.Mkdir(dir, 0o700)
		if err == nil {
			return dir, nil
		}
		if !errors.Is(err, os.ErrExist) || i > 100 {
			return "", err
		}
		dir = filepath.Join(dirRoot, fmt.Sprintf("%s-%d", stamp, i))
	}
}

// Save records path as it is now, copying a file's content into dir as
// name.
func Save(root, dir, name, path, group string) (Entry, error) {
	full := filepath.Join(root, path)
	en := Entry{Path: path, Group: group, UID: -1, GID: -1}
	info, err := os.Lstat(full)
	switch {
	case errors.Is(err, os.ErrNotExist):
		en.Kind = "absent"
		return en, nil
	case err != nil:
		return en, err
	case info.Mode()&os.ModeSymlink != 0:
		en.Kind = "symlink"
		en.Link, err = os.Readlink(full)
		return en, err
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return en, err
	}
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
		return en, err
	}
	en.Kind, en.Backup, en.Mode = "file", name, uint32(info.Mode().Perm())
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		en.UID, en.GID = int(st.Uid), int(st.Gid)
	}
	return en, nil
}

// Restore puts every entry of the groups (all when nil) back as it was, in
// reverse order.
func Restore(root string, entries []Entry, dir string, groups map[string]bool) error {
	var errs []error
	for i := len(entries) - 1; i >= 0; i-- {
		en := entries[i]
		if groups != nil && !groups[en.Group] {
			continue
		}
		full := filepath.Join(root, en.Path)
		switch en.Kind {
		case "absent":
			if err := os.Remove(full); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
		case "symlink":
			_ = os.Remove(full)
			if err := os.Symlink(en.Link, full); err != nil {
				errs = append(errs, err)
			}
		case "file":
			b, err := os.ReadFile(filepath.Join(dir, en.Backup))
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				errs = append(errs, err)
				continue
			}
			real := full
			if r, err := filepath.EvalSymlinks(full); err == nil {
				real = r
			}
			if err := WriteLike(real, en.Mode, en.UID, en.GID, b); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", en.Path, err))
			}
		}
	}
	return errors.Join(errs...)
}

// WriteManifest writes m as the backup's manifest.
func WriteManifest(dir string, m any) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, manifestName), b, 0o600)
}

// MarkRestored marks the backup as put back, with an optional note.
func MarkRestored(dir string, now time.Time, note string) error {
	line := now.UTC().Format(time.RFC3339)
	if note != "" {
		line += " " + note
	}
	return os.WriteFile(filepath.Join(dir, RestoredMark), []byte(line+"\n"), 0o600)
}

// Unrestored lists the backups under backupRoot that haven't been put
// back, newest first.
func Unrestored[M any](root, backupRoot string) ([]Backup[M], error) {
	dirRoot := filepath.Join(root, backupRoot)
	ents, err := os.ReadDir(dirRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Backup[M]
	for _, ent := range ents {
		dir := filepath.Join(dirRoot, ent.Name())
		if !ent.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, RestoredMark)); err == nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, manifestName))
		if err != nil {
			return nil, fmt.Errorf("reading backup %s: %w", ent.Name(), err)
		}
		var m M
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("reading backup %s: %w", ent.Name(), err)
		}
		out = append(out, Backup[M]{Dir: dir, M: m})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dir > out[j].Dir })
	return out, nil
}

// WriteLike replaces the file at real by renaming a temporary file in the
// same directory over it, with the given mode and, when uid isn't -1,
// owner.
func WriteLike(real string, mode uint32, uid, gid int, content []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(real), ".bifrost-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func(err error) error {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		return cleanup(err)
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(err)
	}
	if err := tmp.Chmod(os.FileMode(mode)); err != nil {
		return cleanup(err)
	}
	if uid >= 0 {
		if err := tmp.Chown(uid, gid); err != nil {
			return cleanup(err)
		}
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, real); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}
