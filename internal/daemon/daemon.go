// Package daemon is the agent's main loop: heartbeats, polling for work,
// answering queries and running executions one at a time.
package daemon

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/catalog"
	"github.com/realmwatch/bifrost-agent/internal/executor"
	"github.com/realmwatch/bifrost-agent/internal/hubclient"
	"github.com/realmwatch/bifrost-agent/internal/state"
	"github.com/realmwatch/bifrost-agent/internal/verify"
	"github.com/realmwatch/bifrost-agent/internal/version"
)

// ErrRevoked is returned when the hub answers 401.
var ErrRevoked = hubclient.ErrUnauthorized

// Hub is the part of the hub client the daemon uses.
type Hub interface {
	Heartbeat(ctx context.Context, r hubclient.HeartbeatRequest) error
	GetWork(ctx context.Context) (hubclient.Work, error)
	PostEvents(ctx context.Context, executionID string, events []hubclient.Event) error
	PostQueryResult(ctx context.Context, queryID string, r hubclient.QueryResult) error
}

// KeyStore is the key set the agent trusts (keystore.Store).
type KeyStore interface {
	// Load returns the key set trusted now, read again from disk.
	Load() (*verify.TrustedKeys, error)
	// Apply checks and stores an update: the new set, nil and nil for a
	// serial at or below the current one, or why it was not applied.
	Apply(u verify.KeySetUpdate) (*verify.TrustedKeys, error)
}

// Daemon runs the loop.
type Daemon struct {
	Hub      Hub
	State    *state.Env
	Catalog  *catalog.Catalog
	Executor *executor.Executor
	// Keys is loaded for every execution and heartbeat, so an admin's new
	// anchor or an accepted update applies without a restart.
	Keys KeyStore
	Log  *slog.Logger

	PollInterval      time.Duration
	HeartbeatInterval time.Duration
	// HeartbeatOK, if set, is a file touched after every heartbeat the hub
	// accepts. An upgrade watches it to tell that the new agent works.
	HeartbeatOK string
	// MaxBackoff caps the wait after network errors; default 5 minutes.
	MaxBackoff time.Duration
	// QueryTimeout bounds each state tool; default 60s.
	QueryTimeout time.Duration

	mu      sync.Mutex
	queue   []hubclient.Execution
	wake    chan struct{}
	revoked chan struct{}
	once    sync.Once
	// lastKeySetErr suppresses repeating the same key set log line on
	// every poll. Only the polling loop touches it.
	lastKeySetErr string
}

// Run loops until ctx is cancelled (returns nil after finishing the
// current execution) or the hub revokes the token (returns ErrRevoked).
func (d *Daemon) Run(ctx context.Context) error {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.MaxBackoff == 0 {
		d.MaxBackoff = 5 * time.Minute
	}
	if d.QueryTimeout == 0 {
		d.QueryTimeout = 60 * time.Second
	}
	d.wake = make(chan struct{}, 1)
	d.revoked = make(chan struct{})

	// loopCtx stops polling on shutdown or revocation. Executions and event
	// delivery use workCtx, which shutdown does not cancel: an upgrade is
	// never cut off half way. Revocation does cancel it.
	loopCtx, stopLoop := context.WithCancel(ctx)
	defer stopLoop()
	workCtx, stopWork := context.WithCancel(context.WithoutCancel(ctx))
	defer stopWork()
	go func() {
		select {
		case <-d.revoked:
			stopLoop()
			stopWork()
		case <-workCtx.Done():
		}
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.worker(loopCtx, workCtx)
	}()

	d.heartbeat(loopCtx)
	heartbeat := time.NewTicker(d.HeartbeatInterval)
	defer heartbeat.Stop()
	backoff := time.Duration(0)
	nextPoll := time.NewTimer(0)
	defer nextPoll.Stop()

loop:
	for {
		select {
		case <-loopCtx.Done():
			break loop
		case <-heartbeat.C:
			d.heartbeat(loopCtx)
		case <-nextPoll.C:
			err := d.poll(loopCtx, workCtx, &wg)
			wait := d.PollInterval
			switch {
			case err == nil:
				backoff = 0
			case errors.Is(err, hubclient.ErrUnauthorized):
				d.revoke()
				break loop
			case loopCtx.Err() != nil:
				break loop
			default:
				backoff = nextBackoff(backoff, d.PollInterval, d.MaxBackoff)
				wait = backoff
				d.Log.Warn("polling the hub failed", "err", err, "retry_in", wait.String())
			}
			nextPoll.Reset(wait)
		}
	}
	d.Log.Info("stopping: waiting for running work to finish")
	wg.Wait()
	if d.isRevoked() {
		d.Log.Error("the hub rejected this agent's token (401): it was revoked. Re-enroll to continue.")
		return ErrRevoked
	}
	return nil
}

func nextBackoff(cur, base, max time.Duration) time.Duration {
	if cur == 0 {
		cur = base
	}
	cur *= 2
	if cur > max {
		cur = max
	}
	return cur
}

func (d *Daemon) revoke() { d.once.Do(func() { close(d.revoked) }) }

func (d *Daemon) isRevoked() bool {
	select {
	case <-d.revoked:
		return true
	default:
		return false
	}
}

func (d *Daemon) heartbeat(ctx context.Context) {
	serial := 0
	if keys, err := d.Keys.Load(); err == nil {
		serial = keys.Serial
	}
	err := d.Hub.Heartbeat(ctx, hubclient.HeartbeatRequest{
		AgentVersion: version.Version, Operations: d.Catalog.Keys(), Facts: d.State.Facts(),
		TrustedKeysSerial: serial,
	})
	if errors.Is(err, hubclient.ErrUnauthorized) {
		d.revoke()
	} else if err != nil && ctx.Err() == nil {
		d.Log.Warn("heartbeat failed", "err", err)
	} else if err == nil && d.HeartbeatOK != "" {
		if err := touch(d.HeartbeatOK); err != nil {
			d.Log.Warn("could not record the heartbeat", "path", d.HeartbeatOK, "err", err)
		}
	}
}

func touch(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	now := time.Now()
	return os.Chtimes(path, now, now)
}

func (d *Daemon) poll(loopCtx, workCtx context.Context, wg *sync.WaitGroup) error {
	work, err := d.Hub.GetWork(loopCtx)
	if err != nil {
		return err
	}
	// Key set updates come first, so this response's executions verify
	// against the new set; then the hub hears the new serial.
	if d.applyKeySets(work.Keysets) {
		d.heartbeat(loopCtx)
	}
	for _, q := range work.Queries {
		wg.Add(1)
		go func(q hubclient.Query) {
			defer wg.Done()
			d.answer(workCtx, q)
		}(q)
	}
	if len(work.Executions) > 0 {
		d.mu.Lock()
		d.queue = append(d.queue, work.Executions...)
		d.mu.Unlock()
		select {
		case d.wake <- struct{}{}:
		default:
		}
	}
	return nil
}

// applyKeySets applies updates in order and reports whether any was
// accepted. It stops at the first one that fails or skips a serial.
func (d *Daemon) applyKeySets(updates []verify.KeySetUpdate) bool {
	applied := false
	for _, u := range updates {
		next, err := d.Keys.Apply(u)
		if err != nil {
			d.logKeySetErr(err)
			return applied
		}
		if next != nil {
			applied = true
			d.lastKeySetErr = ""
			d.Log.Info("accepted a key set update", "serial", next.Serial, "keys", next.Len(),
				"owners", len(next.Owners()), "update_threshold", next.UpdateThreshold)
		}
	}
	return applied
}

func (d *Daemon) logKeySetErr(err error) {
	if err.Error() == d.lastKeySetErr {
		return
	}
	d.lastKeySetErr = err.Error()
	if errors.Is(err, verify.ErrKeySetGap) {
		d.Log.Info("waiting for a missing key set update", "err", err)
		return
	}
	d.Log.Warn("rejected a key set update; still trusting the current key set", "err", err)
}

func (d *Daemon) answer(ctx context.Context, q hubclient.Query) {
	qctx, cancel := context.WithTimeout(ctx, d.QueryTimeout)
	defer cancel()
	res, err := d.State.RunTool(qctx, q.Tool, q.Args)
	out := hubclient.QueryResult{OK: err == nil, Result: res}
	if err != nil {
		out.Error = err.Error()
		out.Result = nil
	}
	if perr := d.Hub.PostQueryResult(ctx, q.ID, out); perr != nil {
		if errors.Is(perr, hubclient.ErrUnauthorized) {
			d.revoke()
			return
		}
		d.Log.Warn("posting query result failed", "query", q.ID, "err", perr)
	}
	d.Log.Info("answered query", "query", q.ID, "tool", q.Tool, "ok", out.OK)
}

func (d *Daemon) next() (hubclient.Execution, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.queue) == 0 {
		return hubclient.Execution{}, false
	}
	e := d.queue[0]
	d.queue = d.queue[1:]
	return e, true
}

// worker runs queued executions one at a time. After shutdown it rejects
// executions that were dispatched but never started, so the hub is not
// left waiting for them.
func (d *Daemon) worker(loopCtx, workCtx context.Context) {
	for {
		if e, ok := d.next(); ok {
			if loopCtx.Err() != nil {
				d.rejectUnstarted(workCtx, e)
			} else {
				d.execute(workCtx, e)
			}
			continue
		}
		select {
		case <-loopCtx.Done():
			// Drain anything queued in the meantime.
			for {
				e, ok := d.next()
				if !ok {
					return
				}
				d.rejectUnstarted(workCtx, e)
			}
		case <-d.wake:
		}
	}
}

func (d *Daemon) sinkFor(id string) executor.Sink {
	return func(ctx context.Context, evs []hubclient.Event) error {
		return d.Hub.PostEvents(ctx, id, evs)
	}
}

func (d *Daemon) rejectUnstarted(ctx context.Context, e hubclient.Execution) {
	if d.isRevoked() {
		return
	}
	d.Log.Warn("rejecting execution dispatched during shutdown", "execution", e.ID)
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := d.Executor.Reject(dctx, "agent shut down before running it", d.sinkFor(e.ID)); errors.Is(err, hubclient.ErrUnauthorized) {
		d.revoke()
	}
}

func (d *Daemon) execute(ctx context.Context, e hubclient.Execution) {
	sink := d.sinkFor(e.ID)
	var err error
	raw, derr := verify.DecodeB64U(e.Envelope)
	switch {
	case derr != nil:
		_, err = d.Executor.Reject(ctx, "bad envelope: not base64url", sink)
	default:
		keys, kerr := d.Keys.Load()
		if kerr != nil {
			d.Log.Error("cannot load trusted keys", "err", kerr)
			_, err = d.Executor.Reject(ctx, "agent has no usable trusted keys file", sink)
			break
		}
		d.Executor.Verifier.Keys = keys
		_, err = d.Executor.Execute(ctx, e.ID, raw, e.Approvals, sink)
	}
	if errors.Is(err, hubclient.ErrUnauthorized) {
		d.revoke()
	} else if err != nil {
		d.Log.Error("delivering execution events failed", "execution", e.ID, "err", err)
	}
}
