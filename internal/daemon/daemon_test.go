package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/catalog"
	"github.com/realmwatch/bifrost-agent/internal/executor"
	"github.com/realmwatch/bifrost-agent/internal/hubclient"
	"github.com/realmwatch/bifrost-agent/internal/nonce"
	"github.com/realmwatch/bifrost-agent/internal/runner"
	"github.com/realmwatch/bifrost-agent/internal/state"
	"github.com/realmwatch/bifrost-agent/internal/testkit"
	"github.com/realmwatch/bifrost-agent/internal/verify"
)

type fakeHub struct {
	mu         sync.Mutex
	works      []hubclient.Work
	workErrs   []error
	heartbeats int
	polls      int
	events     map[string][]hubclient.Event
	results    map[string]hubclient.QueryResult
	unauth     bool
}

func (h *fakeHub) Heartbeat(context.Context, hubclient.HeartbeatRequest) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.heartbeats++
	return nil
}

func (h *fakeHub) GetWork(context.Context) (hubclient.Work, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.polls++
	if h.unauth {
		return hubclient.Work{}, &hubclient.HubError{Status: 401}
	}
	if len(h.workErrs) > 0 {
		err := h.workErrs[0]
		h.workErrs = h.workErrs[1:]
		return hubclient.Work{}, err
	}
	if len(h.works) > 0 {
		w := h.works[0]
		h.works = h.works[1:]
		return w, nil
	}
	return hubclient.Work{}, nil
}

func (h *fakeHub) PostEvents(_ context.Context, id string, evs []hubclient.Event) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events[id] = append(h.events[id], evs...)
	return nil
}

func (h *fakeHub) PostQueryResult(_ context.Context, id string, r hubclient.QueryResult) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.results[id] = r
	return nil
}

func (h *fakeHub) finished(id string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, e := range h.events[id] {
		if e["type"] == "finished" {
			return e["result"].(string), true
		}
	}
	return "", false
}

func newDaemon(t *testing.T, hub *fakeHub, a *testkit.Approver) *Daemon {
	t.Helper()
	hub.events = map[string][]hubclient.Event{}
	hub.results = map[string]hubclient.QueryResult{}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	fake := &runner.Fake{Responses: map[string]runner.Response{"who": {Stdout: "alex pts/0 2026-10-31 09:12 (192.0.2.10)\n"}}}
	env := &state.Env{Runner: fake, Root: t.TempDir(), PackageManager: "apt"}
	store, _ := nonce.Open("")
	v := &verify.Verifier{Catalog: catalog.MustEmbedded(), MachineID: testkit.MachineID, PackageManager: "apt",
		Nonces: store, Now: func() time.Time { return time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC) }}
	x := &executor.Executor{Verifier: v, Runner: fake, State: env, PackageManager: "apt", Simulate: true, Log: quiet,
		FlushInterval: time.Millisecond, SinkRetry: time.Millisecond}
	return &Daemon{
		Hub: hub, State: env, Catalog: v.Catalog, Executor: x, Log: quiet,
		LoadKeys:     func() (*verify.TrustedKeys, error) { return testkit.TrustedKeys(a), nil },
		PollInterval: time.Millisecond, HeartbeatInterval: time.Hour, MaxBackoff: 4 * time.Millisecond,
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRunsWorkAndStops(t *testing.T) {
	a := testkit.NewApprover("user:alex")
	ops := []testkit.Step{{Op: "service.restart", Version: 1, Params: map[string]any{"unit": "nginx.service"}}}
	env := testkit.Envelope(ops, nil, "2026-11-01T00:00:00Z", 1)
	hub := &fakeHub{
		workErrs: []error{errors.New("connection refused"), errors.New("connection refused")},
		works: []hubclient.Work{{
			Executions: []hubclient.Execution{
				{ID: "e1", Envelope: verify.B64U(env), Approvals: []verify.Approval{a.Approve(env)}},
				{ID: "e2", Envelope: "!!not base64!!"},
				{ID: "e3", Envelope: verify.B64U(env), Approvals: []verify.Approval{a.Approve(env)}},
			},
			Queries: []hubclient.Query{
				{ID: "q1", Tool: "sessions", Args: map[string]any{}},
				{ID: "q2", Tool: "nope"},
			},
		}},
	}
	d := newDaemon(t, hub, a)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	waitFor(t, func() bool {
		_, ok := hub.finished("e3")
		hub.mu.Lock()
		defer hub.mu.Unlock()
		return ok && len(hub.results) == 2
	})
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run = %v", err)
	}
	if r, _ := hub.finished("e1"); r != "succeeded" {
		t.Errorf("e1 = %s", r)
	}
	if r, _ := hub.finished("e2"); r != "rejected" || hub.events["e2"][0]["reason"] != "bad envelope: not base64url" {
		t.Errorf("e2 = %s %v", r, hub.events["e2"])
	}
	if r, _ := hub.finished("e3"); r != "rejected" || hub.events["e3"][0]["reason"] != "replayed nonce" {
		t.Errorf("e3 = %s %v", r, hub.events["e3"])
	}
	if !hub.results["q1"].OK || hub.results["q2"].OK || hub.results["q2"].Error == "" {
		t.Errorf("results = %+v", hub.results)
	}
	if hub.heartbeats < 1 || hub.polls < 3 {
		t.Errorf("heartbeats = %d polls = %d", hub.heartbeats, hub.polls)
	}
}

func TestRevokedStops(t *testing.T) {
	hub := &fakeHub{unauth: true}
	d := newDaemon(t, hub, testkit.NewApprover("user:alex"))
	err := d.Run(context.Background())
	if !errors.Is(err, ErrRevoked) {
		t.Fatalf("Run = %v", err)
	}
}

func TestShutdownRejectsUnstarted(t *testing.T) {
	a := testkit.NewApprover("user:alex")
	hub := &fakeHub{}
	d := newDaemon(t, hub, a)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d.wake = make(chan struct{}, 1)
	d.revoked = make(chan struct{})
	d.queue = []hubclient.Execution{{ID: "e9", Envelope: "e30"}}
	d.worker(ctx, context.Background())
	if r, _ := hub.finished("e9"); r != "rejected" || hub.events["e9"][0]["reason"] != "agent shut down before running it" {
		t.Fatalf("e9 = %v", hub.events["e9"])
	}
}

func TestNextBackoff(t *testing.T) {
	b := time.Duration(0)
	var got []time.Duration
	for range 5 {
		b = nextBackoff(b, time.Second, 5*time.Second)
		got = append(got, b)
	}
	want := []time.Duration{2 * time.Second, 4 * time.Second, 5 * time.Second, 5 * time.Second, 5 * time.Second}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("backoff = %v", got)
		}
	}
}
