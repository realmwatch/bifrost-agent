// Package enroll exchanges an enrollment key for an agent token and saves
// it in the state directory.
package enroll

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/realmwatch/bifrost-agent/internal/catalog"
	"github.com/realmwatch/bifrost-agent/internal/config"
	"github.com/realmwatch/bifrost-agent/internal/hubclient"
	"github.com/realmwatch/bifrost-agent/internal/state"
	"github.com/realmwatch/bifrost-agent/internal/version"
)

// Options for Run.
type Options struct {
	HubURL string
	Key    string
	// Force re-enrolls over an existing state file.
	Force   bool
	Config  config.Config
	Env     *state.Env
	Catalog *catalog.Catalog
	Client  *hubclient.Client
}

// Run enrolls and writes state.json. It returns the saved state.
func Run(ctx context.Context, o Options) (config.State, error) {
	var st config.State
	if _, err := config.ParseHubURL(o.HubURL); err != nil {
		return st, err
	}
	if o.Key == "" {
		return st, errors.New("an enrollment key is required")
	}
	if _, err := os.Stat(o.Config.StatePath()); err == nil && !o.Force {
		return st, fmt.Errorf("already enrolled (%s exists); pass --force to enroll again", o.Config.StatePath())
	}
	machineID, err := o.Env.MachineID()
	if err != nil {
		return st, fmt.Errorf("reading machine id: %w", err)
	}
	osInfo, err := o.Env.OSInfo()
	if err != nil {
		return st, err
	}
	hostname := ""
	if o.Env.Hostname != nil {
		hostname, _ = o.Env.Hostname()
	}
	client := o.Client
	if client == nil {
		client = hubclient.New(o.HubURL, "", o.Config.InsecureSkipTLSVerify)
	}
	resp, err := client.Enroll(ctx, hubclient.EnrollRequest{
		EnrollmentKey: o.Key, MachineID: machineID, Hostname: hostname, OS: osInfo,
		AgentVersion: version.Version, Operations: o.Catalog.Keys(),
	})
	if err != nil {
		return st, fmt.Errorf("enrollment failed: %w", err)
	}
	st = config.State{HubURL: o.HubURL, AgentID: resp.AgentID, ServerID: resp.ServerID, Token: resp.Token}
	if err := os.MkdirAll(o.Config.StateDir, 0o700); err != nil {
		return st, err
	}
	if err := config.SaveState(o.Config.StatePath(), st); err != nil {
		return st, fmt.Errorf("saving state: %w", err)
	}
	return st, nil
}
