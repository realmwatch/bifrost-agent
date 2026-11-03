package hubclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClient(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen = append(seen, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization")+" "+string(body))
		switch r.URL.Path {
		case "/api/agent/v1/enroll":
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"agent_id":"01JAGENT","server_id":"01JSERVER","token":"bfa_secret"}`)
		case "/api/agent/v1/work":
			_, _ = io.WriteString(w, `{"executions":[{"id":"e1","envelope":"e30","approvals":[{"kind":"policy","key_id":"p","signature":"x"}]}],"queries":[{"id":"q1","tool":"journal","args":{"unit":"nginx.service","lines":20}}]}`)
		case "/api/agent/v1/heartbeat", "/api/agent/v1/executions/e%2F1/events", "/api/agent/v1/queries/q1/result":
			_, _ = io.WriteString(w, `{"ok":true}`)
		default:
			if r.URL.RawPath == "/api/agent/v1/executions/e%2F1/events" {
				_, _ = io.WriteString(w, `{"ok":true}`)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":"not_found","message":"nope"}`)
		}
	}))
	defer srv.Close()
	ctx := context.Background()

	enr, err := New(srv.URL+"/", "", false).Enroll(ctx, EnrollRequest{EnrollmentKey: "bfe_k", MachineID: "m"})
	if err != nil || enr.Token != "bfa_secret" {
		t.Fatalf("enroll = %+v, %v", enr, err)
	}
	if !strings.HasPrefix(seen[0], "POST /api/agent/v1/enroll  {") {
		t.Fatalf("enroll request = %q", seen[0])
	}

	c := New(srv.URL, "bfa_secret", false)
	w, err := c.GetWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Executions) != 1 || w.Executions[0].Approvals[0].Kind != "policy" || w.Queries[0].Args["lines"] != json.Number("20") {
		t.Fatalf("work = %+v", w)
	}
	if !strings.Contains(seen[1], "Bearer bfa_secret") {
		t.Fatalf("no bearer: %q", seen[1])
	}
	if err := c.PostEvents(ctx, "e/1", []Event{{"seq": 1, "type": "verified"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(seen[2], `{"events":[{"seq":1,"type":"verified"}]}`) {
		t.Fatalf("events = %q", seen[2])
	}
	if err := c.PostQueryResult(ctx, "q1", QueryResult{OK: false, Error: "bad"}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(seen[3], `{"ok":false,"error":"bad"}`) {
		t.Fatalf("query result = %q", seen[3])
	}
	if err := c.do(ctx, http.MethodGet, "/missing", nil, nil); err == nil || !strings.Contains(err.Error(), "404 not_found: nope") {
		t.Fatalf("404 err = %v", err)
	}
}

func TestUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"revoked","message":"token revoked"}`)
	}))
	defer srv.Close()
	err := New(srv.URL, "bfa_x", false).Heartbeat(context.Background(), HeartbeatRequest{})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v", err)
	}
}
