// Package daemon is the agent's main loop: heartbeats, polling for work,
// answering queries and running executions one at a time.
package daemon

import (
	"context"
	"errors"
	"log/slog"
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

// Daemon runs the loop.
type Daemon struct {
	Hub      Hub
	State    *state.Env
	Catalog  *catalog.Catalog
	Executor *executor.Executor
	// LoadKeys reads the trusted keys file; called for every execution so
	// an admin's change applies without a restart.
	LoadKeys func() (*verify.TrustedKeys, error)
	Log      *slog.Logger

	PollInterval      time.Duration
	HeartbeatInterval time.Duration
	// MaxBackoff caps the wait after network errors; default 5 minutes.
	MaxBackoff time.Duration
	// QueryTimeout bounds each state tool; default 60s.
	QueryTimeout time.Duration

	mu      sync.Mutex
	queue   []hubclient.Execution
	wake    chan struct{}
	revoked chan struct{}
	once    sync.Once
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
	err := d.Hub.Heartbeat(ctx, hubclient.HeartbeatRequest{
		AgentVersion: version.Version, Operations: d.Catalog.Keys(), Facts: d.State.Facts(),
	})
	if errors.Is(err, hubclient.ErrUnauthorized) {
		d.revoke()
	} else if err != nil && ctx.Err() == nil {
		d.Log.Warn("heartbeat failed", "err", err)
	}
}

func (d *Daemon) poll(loopCtx, workCtx context.Context, wg *sync.WaitGroup) error {
	work, err := d.Hub.GetWork(loopCtx)
	if err != nil {
		return err
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
		keys, kerr := d.LoadKeys()
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
