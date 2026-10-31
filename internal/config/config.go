// Package config loads the agent's JSON configuration and its enrollment
// state.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// Default paths.
const (
	DefaultPath            = "/etc/bifrost-agent/config.json"
	DefaultStateDir        = "/var/lib/bifrost-agent"
	DefaultTrustedKeysPath = "/etc/bifrost-agent/trusted-keys.json"
)

// Config is /etc/bifrost-agent/config.json.
type Config struct {
	HubURL                   string `json:"hub_url"`
	StateDir                 string `json:"state_dir"`
	TrustedKeysPath          string `json:"trusted_keys_path"`
	PollIntervalSeconds      int    `json:"poll_interval_seconds"`
	HeartbeatIntervalSeconds int    `json:"heartbeat_interval_seconds"`
	// Simulate logs the argv each step would run and reports success
	// without executing anything. For development only.
	Simulate bool `json:"simulate"`
	// PackageManager is "auto", "apt" or "dnf".
	PackageManager string `json:"package_manager"`
	// UseSudo prefixes privileged steps with "sudo -n". Defaults to true.
	UseSudo *bool `json:"use_sudo,omitempty"`
	// InsecureSkipTLSVerify disables certificate checks. Development only.
	InsecureSkipTLSVerify bool `json:"insecure_skip_tls_verify"`
}

// Defaults returns a config with every default filled in.
func Defaults() Config {
	t := true
	return Config{
		StateDir: DefaultStateDir, TrustedKeysPath: DefaultTrustedKeysPath,
		PollIntervalSeconds: 5, HeartbeatIntervalSeconds: 60, PackageManager: "auto", UseSudo: &t,
	}
}

// Load reads path over the defaults. A missing file is an error unless
// allowMissing is set, in which case the defaults are returned.
func Load(path string, allowMissing bool) (Config, error) {
	c := Defaults()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && allowMissing {
		return c, nil
	}
	if err != nil {
		return c, fmt.Errorf("config: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("config %s: %w", path, err)
	}
	if c.UseSudo == nil {
		t := true
		c.UseSudo = &t
	}
	return c, c.Validate(false)
}

// Validate checks the config. requireHub demands a hub_url.
func (c Config) Validate(requireHub bool) error {
	if c.HubURL != "" || requireHub {
		if _, err := ParseHubURL(c.HubURL); err != nil {
			return err
		}
	}
	if c.StateDir == "" || !filepath.IsAbs(c.StateDir) {
		return fmt.Errorf("config: state_dir must be an absolute path")
	}
	if c.TrustedKeysPath == "" || !filepath.IsAbs(c.TrustedKeysPath) {
		return fmt.Errorf("config: trusted_keys_path must be an absolute path")
	}
	if c.PollIntervalSeconds < 1 || c.PollIntervalSeconds > 3600 {
		return fmt.Errorf("config: poll_interval_seconds must be between 1 and 3600")
	}
	if c.HeartbeatIntervalSeconds < 5 || c.HeartbeatIntervalSeconds > 3600 {
		return fmt.Errorf("config: heartbeat_interval_seconds must be between 5 and 3600")
	}
	switch c.PackageManager {
	case "auto", "apt", "dnf":
	default:
		return fmt.Errorf("config: package_manager must be auto, apt or dnf")
	}
	return nil
}

// ParseHubURL checks a hub URL: https, or http to a loopback host for local
// development.
func ParseHubURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, fmt.Errorf("config: hub_url %q must be an absolute URL without query, fragment or credentials", raw)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && IsLoopback(u.Hostname()):
	default:
		return nil, fmt.Errorf("config: hub_url must use https (http is allowed only for localhost)")
	}
	return u, nil
}

// IsLoopback reports whether host is a loopback name or address.
func IsLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// PollInterval returns the poll interval.
func (c Config) PollInterval() time.Duration {
	return time.Duration(c.PollIntervalSeconds) * time.Second
}

// HeartbeatInterval returns the heartbeat interval.
func (c Config) HeartbeatInterval() time.Duration {
	return time.Duration(c.HeartbeatIntervalSeconds) * time.Second
}

// Sudo reports whether privileged steps go through sudo.
func (c Config) Sudo() bool { return c.UseSudo == nil || *c.UseSudo }

// NoncePath is the seen-nonce store.
func (c Config) NoncePath() string { return filepath.Join(c.StateDir, "nonces.json") }

// StatePath is the enrollment state file.
func (c Config) StatePath() string { return filepath.Join(c.StateDir, "state.json") }

// State is what enrollment leaves in state_dir/state.json.
type State struct {
	HubURL   string `json:"hub_url"`
	AgentID  string `json:"agent_id"`
	ServerID string `json:"server_id"`
	Token    string `json:"token"`
}

// LoadState reads the enrollment state.
func LoadState(path string) (State, error) {
	var s State
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, fmt.Errorf("not enrolled: %s does not exist (run bifrost-agent enroll)", path)
		}
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return s, fmt.Errorf("state %s: %w", path, err)
	}
	if s.Token == "" || s.AgentID == "" {
		return s, fmt.Errorf("state %s: missing agent_id or token", path)
	}
	return s, nil
}

// SaveState writes the state file atomically with mode 0600.
func SaveState(path string, s State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, append(data, '\n'), 0o600)
}

// WriteFileAtomic writes data to path through a temporary file and rename.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
