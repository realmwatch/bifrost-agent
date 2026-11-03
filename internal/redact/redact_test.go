package redact

import (
	"reflect"
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	cases := []struct{ in, want string }{
		{"user login ok", "user login ok"},
		{"db password=hunter2 host=db-01", "db password=" + Mask + " host=db-01"},
		{`DB_PASSWORD="s3cr3t"`, `DB_PASSWORD="` + Mask + `"`},
		{"token: abc.def", "token: " + Mask},
		{"api_key=XYZ&x=1", "api_key=" + Mask + "&x=1"},
		{"Authorization: Bearer abc123", "Authorization: " + Mask},
		{"sent bearer abc123 to hub", "sent bearer " + Mask + " to hub"},
		{"https://alex:pa55@example.com/repo", "https://alex:" + Mask + "@example.com/repo"},
		{"token bfa_0123456789abcdef leaked", "token " + Mask + " leaked"},
		{"client_secret: x1", "client_secret: " + Mask},
		{"-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----", Mask},
	}
	for _, tc := range cases {
		if got := String(tc.in); got != tc.want {
			t.Errorf("String(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestValue(t *testing.T) {
	in := map[string]any{
		"lines": []string{"password=a", "ok"},
		"list":  []any{"token=b", 3, map[string]any{"x": "secret=c"}},
		"n":     5,
	}
	got := Value(in).(map[string]any)
	if !reflect.DeepEqual(got["lines"], []string{"password=" + Mask, "ok"}) {
		t.Fatalf("lines = %v", got["lines"])
	}
	list := got["list"].([]any)
	if list[0] != "token="+Mask || list[1] != 3 || !strings.Contains(list[2].(map[string]any)["x"].(string), Mask) {
		t.Fatalf("list = %v", list)
	}
	if in["lines"].([]string)[0] != "password=a" {
		t.Fatal("input mutated")
	}
}
