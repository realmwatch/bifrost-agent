// Command bifrost-agent is the Bifrost server agent. See README.md.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/realmwatch/bifrost-agent/internal/catalog"
	"github.com/realmwatch/bifrost-agent/internal/config"
	"github.com/realmwatch/bifrost-agent/internal/daemon"
	"github.com/realmwatch/bifrost-agent/internal/enroll"
	"github.com/realmwatch/bifrost-agent/internal/executor"
	"github.com/realmwatch/bifrost-agent/internal/hubclient"
	"github.com/realmwatch/bifrost-agent/internal/nonce"
	"github.com/realmwatch/bifrost-agent/internal/runner"
	"github.com/realmwatch/bifrost-agent/internal/state"
	"github.com/realmwatch/bifrost-agent/internal/verify"
	"github.com/realmwatch/bifrost-agent/internal/version"
)

// Exit codes. ExitRevoked tells systemd not to restart (see the unit).
const (
	ExitOK      = 0
	ExitError   = 1
	ExitUsage   = 2
	ExitRevoked = 3
)

const usage = `Usage: bifrost-agent <command> [flags]

Commands:
  enroll --hub URL --key KEY [--config PATH] [--force]
                       Enroll with a hub and save the agent token.
  run [--config PATH]  Run the agent: heartbeat, poll for work, run it.
  operations export    Print the hub-facing operations catalog (JSON).
  operations sudoers [--user NAME]
                       Print the sudoers rules for the compiled operations.
  state <tool> [--arg key=value ...] [--config PATH]
                       Run a read-only state tool and print its JSON result.
                       Tools: %s
  verify --envelope FILE --approvals FILE [--config PATH] [--machine-id ID]
                       Run every pre-run check locally and print the result.
                       FILE holds the exact envelope bytes, or their base64url.
  version              Print the agent version.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, usage, strings.Join(state.ToolNames(), ", "))
		return ExitUsage
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, version.Version)
		return ExitOK
	case "enroll":
		err = cmdEnroll(rest, stdout, stderr)
	case "run":
		err = cmdRun(rest, stderr)
	case "operations":
		err = cmdOperations(rest, stdout, stderr)
	case "state":
		err = cmdState(rest, stdout, stderr)
	case "verify":
		return cmdVerify(rest, stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprintf(stdout, usage, strings.Join(state.ToolNames(), ", "))
		return ExitOK
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", cmd)
		fmt.Fprintf(stderr, usage, strings.Join(state.ToolNames(), ", "))
		return ExitUsage
	}
	var ue usageError
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, flag.ErrHelp):
		return ExitOK
	case errors.As(err, &ue):
		fmt.Fprintln(stderr, "bifrost-agent:", err)
		return ExitUsage
	case errors.Is(err, daemon.ErrRevoked):
		fmt.Fprintln(stderr, "bifrost-agent:", err)
		return ExitRevoked
	default:
		fmt.Fprintln(stderr, "bifrost-agent:", err)
		return ExitError
	}
}

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func newLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func resolvePM(cfg config.Config, env *state.Env) string {
	if cfg.PackageManager == "auto" {
		return env.DetectPackageManager()
	}
	return cfg.PackageManager
}

func cmdEnroll(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("enroll", stderr)
	hub := fs.String("hub", "", "hub base URL, for example https://bifrost.example.com")
	key := fs.String("key", "", "enrollment key (bfe_...)")
	cfgPath := fs.String("config", config.DefaultPath, "config file")
	force := fs.Bool("force", false, "enroll again over an existing state file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *hub == "" || *key == "" {
		return usageError{"enroll needs --hub and --key"}
	}
	cfg, err := config.Load(*cfgPath, true)
	if err != nil {
		return err
	}
	log := newLogger(stderr)
	if cfg.InsecureSkipTLSVerify {
		log.Warn("INSECURE: TLS certificate verification is disabled (insecure_skip_tls_verify); never use this in production")
	}
	env := state.NewEnv(runner.Exec{}, "")
	st, err := enroll.Run(context.Background(), enroll.Options{
		HubURL: *hub, Key: *key, Force: *force, Config: cfg, Env: env, Catalog: catalog.MustEmbedded(),
	})
	if err != nil {
		return err
	}
	if _, statErr := os.Stat(*cfgPath); errors.Is(statErr, os.ErrNotExist) {
		cfg.HubURL = *hub
		data, _ := json.MarshalIndent(cfg, "", "  ")
		if werr := config.WriteFileAtomic(*cfgPath, append(data, '\n'), 0o644); werr != nil {
			log.Warn("could not write a config file; pass the hub URL in one before running", "path", *cfgPath, "err", werr)
		}
	}
	fmt.Fprintf(stdout, "enrolled: agent %s, server %s; state saved to %s\n", st.AgentID, st.ServerID, cfg.StatePath())
	return nil
}

func cmdRun(args []string, stderr io.Writer) error {
	fs := newFlags("run", stderr)
	cfgPath := fs.String("config", config.DefaultPath, "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log := newLogger(stderr)
	slog.SetDefault(log)
	cfg, err := config.Load(*cfgPath, false)
	if err != nil {
		return err
	}
	st, err := config.LoadState(cfg.StatePath())
	if err != nil {
		return err
	}
	hubURL := cfg.HubURL
	if hubURL == "" {
		hubURL = st.HubURL
	} else if st.HubURL != "" && st.HubURL != hubURL {
		log.Warn("config hub_url differs from the hub this agent enrolled with; using the config", "config", hubURL, "enrolled", st.HubURL)
	}
	if _, err := config.ParseHubURL(hubURL); err != nil {
		return err
	}
	if cfg.InsecureSkipTLSVerify {
		log.Warn("INSECURE: TLS certificate verification is disabled (insecure_skip_tls_verify); never use this in production")
	}
	if cfg.Simulate {
		log.Warn("SIMULATE: operations are logged and reported as succeeded without running")
	}

	cat := catalog.MustEmbedded()
	env := state.NewEnv(runner.Exec{}, "")
	env.PackageManager = resolvePM(cfg, env)
	if env.PackageManager == "" {
		log.Warn("no supported package manager detected; package operations and tools are unavailable")
	}
	machineID, err := env.MachineID()
	if err != nil {
		return fmt.Errorf("reading machine id: %w", err)
	}
	store, err := nonce.Open(cfg.NoncePath())
	if err != nil {
		return err
	}
	loadKeys := func() (*verify.TrustedKeys, error) { return verify.LoadTrustedKeys(cfg.TrustedKeysPath) }
	if _, err := loadKeys(); err != nil {
		log.Warn("trusted keys are not usable yet; every execution will be rejected until they are", "err", err)
	}
	v := &verify.Verifier{
		Catalog: cat, MachineID: machineID, PackageManager: env.PackageManager, Nonces: store,
		DenyRules: verify.CompiledDenyRules,
	}
	x := &executor.Executor{
		Verifier: v, Runner: runner.Exec{}, State: env, PackageManager: env.PackageManager,
		UseSudo: cfg.Sudo(), Simulate: cfg.Simulate, Log: log,
	}
	d := &daemon.Daemon{
		Hub: hubclient.New(hubURL, st.Token, cfg.InsecureSkipTLSVerify), State: env, Catalog: cat,
		Executor: x, LoadKeys: loadKeys, Log: log,
		PollInterval: cfg.PollInterval(), HeartbeatInterval: cfg.HeartbeatInterval(),
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		stop()
		// A second signal exits at once, even mid-operation.
		again := make(chan os.Signal, 1)
		signal.Notify(again, syscall.SIGINT, syscall.SIGTERM)
		<-again
		log.Error("second signal: exiting without waiting for running work")
		os.Exit(ExitError)
	}()
	log.Info("bifrost-agent starting", "version", version.Version, "hub", hubURL, "agent_id", st.AgentID,
		"package_manager", env.PackageManager, "operations", cat.Keys())
	err = d.Run(ctx)
	if err == nil {
		log.Info("bifrost-agent stopped")
	}
	return err
}

func cmdOperations(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError{"operations needs a subcommand: export or sudoers"}
	}
	cat := catalog.MustEmbedded()
	switch args[0] {
	case "export":
		out, err := cat.Export(version.Version)
		if err != nil {
			return err
		}
		_, err = stdout.Write(out)
		return err
	case "sudoers":
		fs := newFlags("operations sudoers", stderr)
		user := fs.String("user", "bifrost", "the agent's system user")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		_, err := io.WriteString(stdout, cat.Sudoers(*user))
		return err
	}
	return usageError{fmt.Sprintf("unknown operations subcommand %q", args[0])}
}

type argList []string

func (a *argList) String() string     { return strings.Join(*a, ",") }
func (a *argList) Set(v string) error { *a = append(*a, v); return nil }

// parseArgs turns key=value pairs into tool args. A value that parses as
// JSON (a number, a list) is used as such; otherwise it is a string.
func parseArgs(pairs []string) (map[string]any, error) {
	out := map[string]any{}
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			return nil, usageError{fmt.Sprintf("--arg %q is not key=value", p)}
		}
		var parsed any
		dec := json.NewDecoder(strings.NewReader(v))
		dec.UseNumber()
		if err := dec.Decode(&parsed); err == nil && !dec.More() {
			if _, isString := parsed.(string); !isString {
				out[k] = parsed
				continue
			}
		}
		out[k] = v
	}
	return out, nil
}

func cmdState(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return usageError{"state needs a tool name: " + strings.Join(state.ToolNames(), ", ")}
	}
	tool := args[0]
	fs := newFlags("state", stderr)
	var pairs argList
	fs.Var(&pairs, "arg", "tool argument as key=value (repeatable)")
	cfgPath := fs.String("config", config.DefaultPath, "config file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath, true)
	if err != nil {
		return err
	}
	toolArgs, err := parseArgs(pairs)
	if err != nil {
		return err
	}
	env := state.NewEnv(runner.Exec{}, "")
	env.PackageManager = resolvePM(cfg, env)
	res, err := env.RunTool(context.Background(), tool, toolArgs)
	if err != nil {
		return err
	}
	return writeJSON(stdout, res)
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// readEnvelope returns exact envelope bytes from a file holding either the
// raw JSON or its base64url text.
func readEnvelope(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if t := bytes.TrimSpace(data); len(t) > 0 && t[0] != '{' {
		return verify.DecodeB64U(string(t))
	}
	return data, nil
}

func cmdVerify(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("verify", stderr)
	envPath := fs.String("envelope", "", "file with the envelope bytes (raw JSON or base64url)")
	apprPath := fs.String("approvals", "", "file with the approvals JSON array")
	cfgPath := fs.String("config", config.DefaultPath, "config file")
	machineID := fs.String("machine-id", "", "machine id to check against (default: /etc/machine-id)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if *envPath == "" || *apprPath == "" {
		fmt.Fprintln(stderr, "bifrost-agent: verify needs --envelope and --approvals")
		return ExitUsage
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "bifrost-agent:", err)
		return ExitError
	}
	cfg, err := config.Load(*cfgPath, true)
	if err != nil {
		return fail(err)
	}
	raw, err := readEnvelope(*envPath)
	if err != nil {
		return fail(err)
	}
	apprData, err := os.ReadFile(*apprPath)
	if err != nil {
		return fail(err)
	}
	var approvals []verify.Approval
	if err := json.Unmarshal(apprData, &approvals); err != nil {
		return fail(fmt.Errorf("approvals: %w", err))
	}
	keys, err := verify.LoadTrustedKeys(cfg.TrustedKeysPath)
	if err != nil {
		return fail(err)
	}
	env := state.NewEnv(runner.Exec{}, "")
	mid := *machineID
	if mid == "" {
		if mid, err = env.MachineID(); err != nil {
			return fail(fmt.Errorf("reading machine id: %w (or pass --machine-id)", err))
		}
	}
	store, err := nonce.Open(cfg.NoncePath())
	if err != nil {
		fmt.Fprintln(stderr, "bifrost-agent: warning: nonce store unreadable, checking without it:", err)
		store, _ = nonce.Open("")
	}
	v := &verify.Verifier{
		Catalog: catalog.MustEmbedded(), Keys: keys, MachineID: mid,
		PackageManager: resolvePM(cfg, env), Nonces: store, DenyRules: verify.CompiledDenyRules,
	}
	res, err := v.Verify(raw, approvals)
	if err != nil {
		out := map[string]any{"ok": false, "reason": err.Error()}
		var r *verify.Rejection
		if errors.As(err, &r) {
			out["check"], out["reason"] = r.Check, r.Reason
			if r.Detail != "" {
				out["detail"] = r.Detail
			}
		}
		_ = writeJSON(stdout, out)
		return ExitError
	}
	_ = writeJSON(stdout, map[string]any{
		"ok": true, "hash": verify.B64U(res.Envelope.Hash[:]), "tier": res.Tier.String(),
		"owners": res.Owners, "policy_only": res.PolicyOnly, "ignored_approvals": res.Ignored,
	})
	return ExitOK
}
