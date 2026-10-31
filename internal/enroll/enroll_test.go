package enroll

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/realmwatch/bifrost-agent/internal/catalog"
	"github.com/realmwatch/bifrost-agent/internal/config"
	"github.com/realmwatch/bifrost-agent/internal/state"
)

func TestRun(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/v1/enroll" || r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"agent_id":"01JAGENT","server_id":"01JSERVER","token":"bfa_tok"}`)
	}))
	defer srv.Close()

	root := t.TempDir()
	for p, c := range map[string]string{"etc/machine-id": "abc123\n", "etc/os-release": "ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12\"\n"} {
		_ = os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755)
		_ = os.WriteFile(filepath.Join(root, p), []byte(c), 0o644)
	}
	cfg := config.Defaults()
	cfg.StateDir = filepath.Join(t.TempDir(), "state")
	o := Options{
		HubURL: "http://127.0.0.1", Key: "bfe_key", Config: cfg, Catalog: catalog.MustEmbedded(),
		Env: &state.Env{Root: root, Hostname: func() (string, error) { return "web-01", nil }},
	}
	o.HubURL = srv.URL
	st, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if st.Token != "bfa_tok" || got["machine_id"] != "abc123" || got["hostname"] != "web-01" || got["enrollment_key"] != "bfe_key" {
		t.Fatalf("state = %+v, request = %v", st, got)
	}
	if osm := got["os"].(map[string]any); osm["id"] != "debian" || osm["version_id"] != "12" {
		t.Fatalf("os = %v", osm)
	}
	if ops := got["operations"].([]any); len(ops) != 6 {
		t.Fatalf("operations = %v", ops)
	}
	saved, err := config.LoadState(cfg.StatePath())
	if err != nil || saved != st {
		t.Fatalf("saved = %+v, %v", saved, err)
	}
	if _, err := Run(context.Background(), o); err == nil {
		t.Fatal("second enrollment without --force succeeded")
	}
	o.Force = true
	if _, err := Run(context.Background(), o); err != nil {
		t.Fatalf("forced enrollment: %v", err)
	}
	o.Key = ""
	if _, err := Run(context.Background(), o); err == nil {
		t.Fatal("empty key accepted")
	}
}
