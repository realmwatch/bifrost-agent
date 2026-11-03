package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/catalog"
	"github.com/realmwatch/bifrost-agent/internal/hubclient"
	"github.com/realmwatch/bifrost-agent/internal/nonce"
	"github.com/realmwatch/bifrost-agent/internal/runner"
	"github.com/realmwatch/bifrost-agent/internal/state"
	"github.com/realmwatch/bifrost-agent/internal/testkit"
	"github.com/realmwatch/bifrost-agent/internal/verify"
)

const (
	dpkgArgv    = "dpkg-query -W -f ${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n"
	upgradeArgv = "/usr/bin/sudo -n -- /usr/bin/apt-get -q -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install --only-upgrade openssl=3.0.13-0ubuntu3.4"
	installArgv = "/usr/bin/sudo -n -- /usr/bin/apt-get -q -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install --allow-downgrades openssl=3.0.13-0ubuntu3.1"
	showNginx   = "systemctl show nginx.service --no-pager -p Id -p ActiveState -p SubState -p LoadState -p UnitFileState -p ActiveEnterTimestamp"
)

var now = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

type recorder struct {
	mu     sync.Mutex
	events []hubclient.Event
	fail   int // fail this many calls first
	err    error
}

func (r *recorder) sink(_ context.Context, evs []hubclient.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	if r.fail > 0 {
		r.fail--
		return errors.New("network down")
	}
	r.events = append(r.events, evs...)
	return nil
}

func (r *recorder) types() string {
	var out []string
	for _, e := range r.events {
		out = append(out, e["type"].(string))
	}
	return strings.Join(out, ",")
}

func setup(t *testing.T, fake *runner.Fake) (*Executor, *testkit.Approver) {
	t.Helper()
	a := testkit.NewApprover("user:alex")
	store, _ := nonce.Open("")
	v := &verify.Verifier{
		Catalog: catalog.MustEmbedded(), Keys: testkit.TrustedKeys(a), MachineID: testkit.MachineID,
		PackageManager: "apt", Nonces: store, Now: func() time.Time { return now },
	}
	x := &Executor{
		Verifier: v, Runner: fake, State: &state.Env{Runner: fake, PackageManager: "apt"},
		PackageManager: "apt", UseSudo: true, Now: func() time.Time { return now },
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		FlushInterval: 5 * time.Millisecond, HealthAttempts: 3, HealthDelay: time.Millisecond,
		SinkRetry: time.Millisecond, SinkAttempts: 5,
	}
	return x, a
}

var upgrade = []testkit.Step{{Op: "package.upgrade", Version: 1, Params: map[string]any{"name": "openssl", "to": "3.0.13-0ubuntu3.4"}}}
var rollback = []testkit.Step{{Op: "package.install", Version: 1, Params: map[string]any{"name": "openssl", "version": "3.0.13-0ubuntu3.1"}}}

func run(t *testing.T, x *Executor, env []byte, approvals []verify.Approval) (Outcome, *recorder) {
	t.Helper()
	rec := &recorder{}
	out, err := x.Execute(context.Background(), "01JEXEC", env, approvals, rec.sink)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range rec.events {
		if e["seq"] != i+1 {
			t.Fatalf("event %d has seq %v", i, e["seq"])
		}
		if e["at"] != "2026-10-31T12:00:00Z" {
			t.Fatalf("event at = %v", e["at"])
		}
	}
	return out, rec
}

func TestUpgradeSucceeds(t *testing.T) {
	fake := &runner.Fake{Responses: map[string]runner.Response{
		upgradeArgv: {Stdout: "Reading package lists...\nSetting up openssl\n", Stderr: "warning: x\n"},
		dpkgArgv:    {Stdout: "openssl\t3.0.13-0ubuntu3.4\tamd64\tii \n"},
	}}
	x, a := setup(t, fake)
	env := testkit.Envelope(upgrade, rollback, "2026-11-01T00:00:00Z", 1)
	out, rec := run(t, x, env, []verify.Approval{a.Approve(env)})
	if out.Result != ResultSucceeded {
		t.Fatalf("result = %s; events %v", out.Result, rec.events)
	}
	if got := rec.types(); got != "verified,step_started,output,output,step_finished,health,finished" {
		t.Fatalf("events = %s", got)
	}
	started := rec.events[1]
	if strings.Join(started["argv"].([]string), " ") != upgradeArgv || started["op"] != "package.upgrade@1" || started["phase"] != "operations" {
		t.Fatalf("step_started = %v", started)
	}
	if rec.events[2]["stream"] != "stdout" || rec.events[3]["stream"] != "stderr" {
		t.Fatalf("output = %v %v", rec.events[2], rec.events[3])
	}
	if rec.events[4]["exit_code"] != 0 || rec.events[5]["ok"] != true || rec.events[6]["result"] != "succeeded" {
		t.Fatalf("tail = %v", rec.events[4:])
	}
	if !strings.Contains(fake.Calls[0].Env[0], "DEBIAN_FRONTEND=noninteractive") {
		t.Fatalf("env = %v", fake.Calls[0].Env)
	}
}

func TestFailedStepRollsBack(t *testing.T) {
	fake := &runner.Fake{Responses: map[string]runner.Response{
		upgradeArgv: {Stderr: "E: broken\n", ExitCode: 100},
		installArgv: {Stdout: "ok\n"},
		dpkgArgv:    {Stdout: "openssl\t3.0.13-0ubuntu3.1\tamd64\tii \n"},
	}}
	x, a := setup(t, fake)
	env := testkit.Envelope(upgrade, rollback, "2026-11-01T00:00:00Z", 2)
	out, rec := run(t, x, env, []verify.Approval{a.Approve(env)})
	if out.Result != ResultRolledBack {
		t.Fatalf("result = %s", out.Result)
	}
	if got := rec.types(); got != "verified,step_started,output,step_finished,step_started,output,step_finished,health,finished" {
		t.Fatalf("events = %s", got)
	}
	if rec.events[3]["exit_code"] != 100 || rec.events[4]["phase"] != "rollback" || rec.events[7]["phase"] != "rollback" {
		t.Fatalf("events = %v", rec.events)
	}
}

func TestHealthFailureRollsBackAndRollbackFailure(t *testing.T) {
	fake := &runner.Fake{Responses: map[string]runner.Response{
		upgradeArgv: {},
		installArgv: {ExitCode: 1},
		dpkgArgv:    {Stdout: "openssl\t3.0.13-0ubuntu3.1\tamd64\tii \n"},
	}}
	x, a := setup(t, fake)
	env := testkit.Envelope(upgrade, rollback, "2026-11-01T00:00:00Z", 3)
	out, rec := run(t, x, env, []verify.Approval{a.Approve(env)})
	if out.Result != ResultFailed {
		t.Fatalf("result = %s", out.Result)
	}
	if got := rec.types(); got != "verified,step_started,step_finished,health,step_started,step_finished,finished" {
		t.Fatalf("events = %s", got)
	}
	if rec.events[3]["ok"] != false || !strings.Contains(rec.events[3]["detail"].(string), "want 3.0.13-0ubuntu3.4") {
		t.Fatalf("health = %v", rec.events[3])
	}
}

func TestFailureWithoutRollback(t *testing.T) {
	fake := &runner.Fake{Responses: map[string]runner.Response{upgradeArgv: {ExitCode: 1}}}
	x, a := setup(t, fake)
	env := testkit.Envelope(upgrade, nil, "2026-11-01T00:00:00Z", 4)
	out, _ := run(t, x, env, []verify.Approval{a.Approve(env)})
	if out.Result != ResultFailed {
		t.Fatalf("result = %s", out.Result)
	}
}

func TestServiceRestartHealthPolls(t *testing.T) {
	restartArgv := "/usr/bin/sudo -n -- /usr/bin/systemctl restart nginx.service"
	fake := &runner.Fake{
		Responses: map[string]runner.Response{restartArgv: {}, showNginx: {Stdout: "ActiveState=active\nSubState=running\n"}},
		Queue:     map[string][]runner.Response{showNginx: {{Stdout: "ActiveState=activating\n"}}},
	}
	x, a := setup(t, fake)
	ops := []testkit.Step{{Op: "service.restart", Version: 1, Params: map[string]any{"unit": "nginx.service"}}}
	env := testkit.Envelope(ops, nil, "2026-11-01T00:00:00Z", 5)
	out, rec := run(t, x, env, []verify.Approval{a.Approve(env)})
	if out.Result != ResultSucceeded {
		t.Fatalf("result = %s, events %v", out.Result, rec.events)
	}
	if n := strings.Count(strings.Join(fake.Argvs(), "\n"), "systemctl show"); n != 2 {
		t.Fatalf("polled %d times", n)
	}
}

func TestServiceStopNeverInactive(t *testing.T) {
	fake := &runner.Fake{Responses: map[string]runner.Response{
		"/usr/bin/systemctl stop nginx.service": {},
		showNginx:                               {Stdout: "ActiveState=active\n"},
	}}
	x, a := setup(t, fake)
	x.UseSudo = false
	ops := []testkit.Step{{Op: "service.stop", Version: 1, Params: map[string]any{"unit": "nginx.service"}}}
	env := testkit.Envelope(ops, nil, "2026-11-01T00:00:00Z", 6)
	out, rec := run(t, x, env, []verify.Approval{a.Approve(env)})
	if out.Result != ResultFailed {
		t.Fatalf("result = %s", out.Result)
	}
	h := rec.events[3]
	if h["type"] != "health" || !strings.Contains(h["detail"].(string), "want ActiveState=inactive") {
		t.Fatalf("health = %v", h)
	}
}

func TestRejectedRunsNothing(t *testing.T) {
	fake := &runner.Fake{}
	x, _ := setup(t, fake)
	env := testkit.Envelope(upgrade, rollback, "2026-11-01T00:00:00Z", 7)
	out, rec := run(t, x, env, nil)
	if out.Result != ResultRejected || len(fake.Calls) != 0 {
		t.Fatalf("result = %s calls = %v", out.Result, fake.Calls)
	}
	if rec.types() != "rejected,finished" || rec.events[0]["reason"] != "no valid passkey approval from a trusted key" || rec.events[1]["result"] != "rejected" {
		t.Fatalf("events = %v", rec.events)
	}
}

func TestReplayRejected(t *testing.T) {
	fake := &runner.Fake{Default: &runner.Response{Stdout: "openssl\t3.0.13-0ubuntu3.4\tamd64\tii \n"}}
	x, a := setup(t, fake)
	env := testkit.Envelope(upgrade, rollback, "2026-11-01T00:00:00Z", 8)
	approvals := []verify.Approval{a.Approve(env)}
	if out, _ := run(t, x, env, approvals); out.Result != ResultSucceeded {
		t.Fatalf("first run = %s", out.Result)
	}
	out, rec := run(t, x, env, approvals)
	if out.Result != ResultRejected || rec.events[0]["reason"] != "replayed nonce" {
		t.Fatalf("replay = %s %v", out.Result, rec.events)
	}
}

func TestSimulate(t *testing.T) {
	fake := &runner.Fake{}
	x, a := setup(t, fake)
	x.Simulate = true
	env := testkit.Envelope(upgrade, rollback, "2026-11-01T00:00:00Z", 9)
	out, rec := run(t, x, env, []verify.Approval{a.Approve(env)})
	if out.Result != ResultSucceeded || len(fake.Calls) != 0 {
		t.Fatalf("result = %s calls = %v", out.Result, fake.Argvs())
	}
	if rec.events[2]["data"] != "simulated" || rec.events[4]["detail"] != "simulated" {
		t.Fatalf("events = %v", rec.events)
	}
}

func TestDeliveryRetriesAndUnauthorized(t *testing.T) {
	fake := &runner.Fake{}
	x, a := setup(t, fake)
	x.Simulate = true
	x.FlushInterval = time.Hour
	env := testkit.Envelope(upgrade, nil, "2026-11-01T00:00:00Z", 10)
	rec := &recorder{fail: 2}
	if _, err := x.Execute(context.Background(), "e", env, []verify.Approval{a.Approve(env)}, rec.sink); err != nil {
		t.Fatal(err)
	}
	if rec.types() != "verified,step_started,output,step_finished,health,finished" {
		t.Fatalf("events after retries = %s", rec.types())
	}
	rec = &recorder{err: &hubclient.HubError{Status: 401}}
	env = testkit.Envelope(upgrade, nil, "2026-11-01T00:00:00Z", 11)
	_, err := x.Execute(context.Background(), "e", env, []verify.Approval{a.Approve(env)}, rec.sink)
	if !errors.Is(err, hubclient.ErrUnauthorized) {
		t.Fatalf("err = %v", err)
	}
}

func TestOutputBatchingAndCap(t *testing.T) {
	s := newStream(func(context.Context, []hubclient.Event) error { return nil }, func() time.Time { return now })
	budget, clipped := 10, false
	var mu sync.Mutex
	w := &outputWriter{s: s, phase: "operations", index: 0, name: "stdout", budget: &budget, mu: &mu, clipped: &clipped}
	_, _ = w.Write([]byte("hello "))
	_, _ = w.Write([]byte("world, token=abc"))
	_, _ = w.Write([]byte("more"))
	s.emit("step_finished", nil)
	if len(s.all) != 2 {
		b, _ := json.Marshal(s.all)
		t.Fatalf("events = %s", b)
	}
	if got := s.all[0]["data"]; got != "hello worl\n[output truncated by bifrost-agent]\n" {
		t.Fatalf("data = %q", got)
	}
	s2 := newStream(nil, func() time.Time { return now })
	s2.write("operations", 0, "stdout", []byte("password=hunter2"))
	s2.emit("x", nil)
	if s2.all[0]["data"] != "password=[REDACTED]" {
		t.Fatalf("output not redacted: %v", s2.all[0])
	}
}

func TestVersionMatches(t *testing.T) {
	cases := []struct {
		installed, want string
		ok              bool
	}{
		{"3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.4", true},
		{"1:3.0.7-28.el9", "3.0.7-28.el9", true},
		{"1:3.0.7-28.el9", "1:3.0.7-28.el9", true},
		{"3.0.7-28.el9", "0:3.0.7-28.el9", true},
		{"3.0.7-27.el9", "3.0.7-28.el9", false},
		{"1:3.0.7", "2:3.0.7", false},
	}
	for _, c := range cases {
		if got := VersionMatches(c.installed, c.want); got != c.ok {
			t.Errorf("VersionMatches(%q, %q) = %v", c.installed, c.want, got)
		}
	}
}
