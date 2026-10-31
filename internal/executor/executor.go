// Package executor verifies an execution's envelope and runs its operations
// in order, streaming events to the hub, checking health and rolling back
// on failure.
package executor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/catalog"
	"github.com/realmwatch/bifrost-agent/internal/hubclient"
	"github.com/realmwatch/bifrost-agent/internal/runner"
	"github.com/realmwatch/bifrost-agent/internal/state"
	"github.com/realmwatch/bifrost-agent/internal/verify"
)

// Results of an execution.
const (
	ResultSucceeded  = "succeeded"
	ResultFailed     = "failed"
	ResultRolledBack = "rolled_back"
	ResultRejected   = "rejected"
)

// Phases of a step.
const (
	PhaseOperations = "operations"
	PhaseRollback   = "rollback"
)

// SudoArgv prefixes privileged commands.
var SudoArgv = []string{"/usr/bin/sudo", "-n", "--"}

// Executor runs verified envelopes.
type Executor struct {
	Verifier *verify.Verifier
	Runner   runner.Runner
	// State reads package versions and unit states for health checks.
	State          *state.Env
	PackageManager string
	UseSudo        bool
	// Simulate logs each argv and reports success without running it.
	Simulate bool
	Log      *slog.Logger
	Now      func() time.Time

	FlushInterval  time.Duration // default 1s
	HealthAttempts int           // default 10
	HealthDelay    time.Duration // default 1s
	StepTimeout    time.Duration // default 30m
	// MaxOutputBytes caps each step's output; default 1 MiB.
	MaxOutputBytes int
	// SinkRetry is the delay between attempts to deliver the final events.
	SinkRetry time.Duration // default 2s
	// SinkAttempts bounds attempts to deliver the final events; default 150.
	SinkAttempts int
}

func (x *Executor) defaults() {
	if x.Now == nil {
		x.Now = time.Now
	}
	if x.Log == nil {
		x.Log = slog.Default()
	}
	if x.FlushInterval == 0 {
		x.FlushInterval = time.Second
	}
	if x.HealthAttempts == 0 {
		x.HealthAttempts = 10
	}
	if x.HealthDelay == 0 {
		x.HealthDelay = time.Second
	}
	if x.StepTimeout == 0 {
		x.StepTimeout = 30 * time.Minute
	}
	if x.MaxOutputBytes == 0 {
		x.MaxOutputBytes = 1 << 20
	}
	if x.SinkRetry == 0 {
		x.SinkRetry = 2 * time.Second
	}
	if x.SinkAttempts == 0 {
		x.SinkAttempts = 150
	}
}

// Outcome is what Execute returns.
type Outcome struct {
	Result string
	// Reason is set for rejections.
	Reason string
	// Events is every event emitted, in order.
	Events []hubclient.Event
}

// Reject reports an execution that never reached verification (for
// example, an envelope that is not valid base64url).
func (x *Executor) Reject(ctx context.Context, reason string, sink Sink) (Outcome, error) {
	x.defaults()
	s := newStream(sink, x.Now)
	s.emit("rejected", map[string]any{"reason": reason})
	s.emit("finished", map[string]any{"result": ResultRejected})
	err := x.deliver(ctx, s)
	return Outcome{Result: ResultRejected, Reason: reason, Events: s.all}, err
}

// Execute verifies raw and its approvals, then runs the operations. The
// returned error is only about delivering events (for example a revoked
// token); the outcome stands either way.
func (x *Executor) Execute(ctx context.Context, executionID string, raw []byte, approvals []verify.Approval, sink Sink) (Outcome, error) {
	x.defaults()
	log := x.Log.With("execution", executionID)
	res, err := x.Verifier.VerifyAndConsume(raw, approvals)
	if err != nil {
		reason := err.Error()
		var r *verify.Rejection
		if errors.As(err, &r) {
			reason = r.Reason
		}
		log.Warn("execution rejected", "reason", err.Error())
		return x.Reject(ctx, reason, sink)
	}
	env := res.Envelope
	log.Info("execution verified", "proposal", env.ProposalID, "tier", res.Tier.String(),
		"owners", res.Owners, "policy_only", res.PolicyOnly, "ignored_approvals", res.Ignored)

	s := newStream(sink, x.Now)
	s.emit("verified", nil)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(x.FlushInterval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if err := s.flush(ctx); err != nil {
					log.Warn("sending events failed; will retry", "err", err)
				}
			}
		}
	}()

	result := ResultSucceeded
	if !x.runSteps(ctx, s, PhaseOperations, env.Operations, log) {
		result = ResultFailed
		if len(env.Rollback) > 0 {
			log.Warn("operation failed; rolling back")
			if x.runSteps(ctx, s, PhaseRollback, env.Rollback, log) {
				result = ResultRolledBack
			} else {
				log.Error("rollback failed")
			}
		}
	}
	s.emit("finished", map[string]any{"result": result})
	close(stop)
	wg.Wait()
	log.Info("execution finished", "result", result)
	err = x.deliver(ctx, s)
	return Outcome{Result: result, Events: s.all}, err
}

// deliver flushes until every event is sent, giving up on a 401 or after
// SinkAttempts.
func (x *Executor) deliver(ctx context.Context, s *stream) error {
	var err error
	for attempt := 0; attempt < x.SinkAttempts; attempt++ {
		if err = s.flush(ctx); err == nil {
			return nil
		}
		if errors.Is(err, hubclient.ErrUnauthorized) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(x.SinkRetry):
		}
	}
	return fmt.Errorf("giving up delivering events: %w", err)
}

// runSteps runs steps in order and reports whether all succeeded.
func (x *Executor) runSteps(ctx context.Context, s *stream, phase string, steps []verify.Step, log *slog.Logger) bool {
	for i, step := range steps {
		def, ok := x.Verifier.Catalog.Get(step.Op, step.Version)
		if !ok {
			// Unreachable after verification; refuse anyway.
			s.emit("step_finished", map[string]any{"phase": phase, "index": i, "exit_code": -1, "duration_ms": 0})
			return false
		}
		if !x.runStep(ctx, s, phase, i, def, step, log) {
			return false
		}
	}
	return true
}

func (x *Executor) runStep(ctx context.Context, s *stream, phase string, i int, def *catalog.Definition, step verify.Step, log *slog.Logger) bool {
	exp, err := def.Expand(x.PackageManager, step.Params)
	if err != nil {
		s.emit("step_started", map[string]any{"phase": phase, "index": i, "op": def.Key(), "argv": []string{}})
		s.write(phase, i, "stderr", []byte("bifrost-agent: "+err.Error()+"\n"))
		s.emit("step_finished", map[string]any{"phase": phase, "index": i, "exit_code": -1, "duration_ms": 0})
		return false
	}
	argv := exp.Argv
	if exp.Privileged && x.UseSudo {
		argv = append(append([]string{}, SudoArgv...), argv...)
	}
	s.emit("step_started", map[string]any{"phase": phase, "index": i, "op": def.Key(), "argv": argv})
	log.Info("step started", "phase", phase, "index", i, "op", def.Key(), "argv", argv, "simulate", x.Simulate)

	start := x.Now()
	var code int
	if x.Simulate {
		s.write(phase, i, "stdout", []byte("simulated"))
	} else {
		var mu sync.Mutex
		budget, clipped := x.MaxOutputBytes, false
		stdout := &outputWriter{s: s, phase: phase, index: i, name: "stdout", budget: &budget, mu: &mu, clipped: &clipped}
		stderr := &outputWriter{s: s, phase: phase, index: i, name: "stderr", budget: &budget, mu: &mu, clipped: &clipped}
		stepCtx, cancel := context.WithTimeout(ctx, x.StepTimeout)
		code, err = x.Runner.Run(stepCtx, runner.Command{Argv: argv, Env: exp.Env, Stdout: stdout, Stderr: stderr})
		cancel()
		if err != nil {
			s.write(phase, i, "stderr", []byte("bifrost-agent: "+err.Error()+"\n"))
			if code == 0 {
				code = -1
			}
		}
	}
	s.emit("step_finished", map[string]any{
		"phase": phase, "index": i, "exit_code": code, "duration_ms": x.Now().Sub(start).Milliseconds(),
	})
	if code != 0 {
		log.Warn("step failed", "phase", phase, "index", i, "op", def.Key(), "exit_code", code)
		return false
	}

	ok, detail := x.health(ctx, def, step)
	// PROTOCOL.md's health event has no phase; the agent adds one so
	// rollback health checks are not mistaken for operation ones.
	s.emit("health", map[string]any{"phase": phase, "index": i, "ok": ok, "detail": detail})
	if !ok {
		log.Warn("health check failed", "phase", phase, "index", i, "op", def.Key(), "detail", detail)
	}
	return ok
}

func (x *Executor) health(ctx context.Context, def *catalog.Definition, step verify.Step) (bool, string) {
	if x.Simulate {
		return true, "simulated"
	}
	args, err := def.HealthArgs(step.Params)
	if err != nil {
		return false, err.Error()
	}
	switch def.Health.Check {
	case "package_version":
		return x.packageVersion(ctx, args["name"], args["version"])
	case "service_state":
		return x.serviceState(ctx, args["unit"], args["state"])
	}
	return false, fmt.Sprintf("unknown health check %q", def.Health.Check)
}

func (x *Executor) packageVersion(ctx context.Context, name, want string) (bool, string) {
	pkgs, err := x.State.Packages(ctx)
	if err != nil {
		return false, "reading installed packages: " + err.Error()
	}
	for _, p := range pkgs {
		if p.Name != name {
			continue
		}
		if VersionMatches(p.Version, want) {
			return true, fmt.Sprintf("%s is installed at %s", name, p.Version)
		}
		return false, fmt.Sprintf("%s is installed at %s, want %s", name, p.Version, want)
	}
	return false, fmt.Sprintf("%s is not installed", name)
}

// VersionMatches compares an installed version with a requested one. A
// request without an epoch matches an installed version with any epoch.
func VersionMatches(installed, want string) bool {
	if installed == want {
		return true
	}
	if !strings.Contains(want, ":") {
		if _, rest, ok := strings.Cut(installed, ":"); ok {
			return rest == want
		}
	}
	if e, rest, ok := strings.Cut(want, ":"); ok && e == "0" {
		return installed == rest
	}
	return false
}

func (x *Executor) serviceState(ctx context.Context, unit, want string) (bool, string) {
	var last string
	for attempt := 0; attempt < x.HealthAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return false, ctx.Err().Error()
			case <-time.After(x.HealthDelay):
			}
		}
		st, err := x.State.ServiceStatus(ctx, unit)
		if err != nil {
			last = err.Error()
			continue
		}
		last = fmt.Sprintf("ActiveState=%s SubState=%s", st.ActiveState, st.SubState)
		if st.ActiveState == want {
			return true, last
		}
	}
	return false, last + ", want ActiveState=" + want
}
