// Package hubclient talks to the hub's agent API (PROTOCOL.md, Transport).
package hubclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/state"
	"github.com/realmwatch/bifrost-agent/internal/verify"
	"github.com/realmwatch/bifrost-agent/internal/version"
)

// BasePath is the agent API prefix.
const BasePath = "/api/agent/v1"

const maxResponse = 16 << 20

// ErrUnauthorized means the hub revoked (or never issued) the token.
var ErrUnauthorized = errors.New("hub rejected the agent token (401): it is revoked or invalid")

// HubError is a non-2xx response.
type HubError struct {
	Status  int
	Code    string `json:"error"`
	Message string `json:"message"`
}

func (e *HubError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("hub returned %d %s: %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("hub returned %d", e.Status)
}

// Is makes errors.Is(err, ErrUnauthorized) true for 401s.
func (e *HubError) Is(target error) bool {
	return target == ErrUnauthorized && e.Status == http.StatusUnauthorized
}

// Client is an agent API client.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// New returns a client for hubURL. token may be empty for enrollment.
func New(hubURL, token string, insecureSkipVerify bool) *Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecureSkipVerify} //nolint:gosec // opt-in dev setting, logged loudly
	return &Client{
		base:  strings.TrimRight(hubURL, "/") + BasePath,
		token: token,
		http:  &http.Client{Transport: tr, Timeout: 30 * time.Second},
	}
}

// WithHTTPClient replaces the HTTP client (tests).
func (c *Client) WithHTTPClient(h *http.Client) *Client {
	c.http = h
	return c
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "bifrost-agent/"+version.Version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		he := &HubError{Status: resp.StatusCode}
		_ = json.Unmarshal(data, he)
		he.Status = resp.StatusCode
		return he
	}
	if out == nil {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("hub response for %s: %w", path, err)
	}
	return nil
}

// EnrollRequest is the POST /enroll body.
type EnrollRequest struct {
	EnrollmentKey string       `json:"enrollment_key"`
	MachineID     string       `json:"machine_id"`
	Hostname      string       `json:"hostname"`
	OS            state.OSInfo `json:"os"`
	AgentVersion  string       `json:"agent_version"`
	Operations    []string     `json:"operations"`
}

// EnrollResponse is the 201 body.
type EnrollResponse struct {
	AgentID  string `json:"agent_id"`
	ServerID string `json:"server_id"`
	Token    string `json:"token"`
}

// Enroll exchanges an enrollment key for an agent token.
func (c *Client) Enroll(ctx context.Context, r EnrollRequest) (EnrollResponse, error) {
	var out EnrollResponse
	if err := c.do(ctx, http.MethodPost, "/enroll", r, &out); err != nil {
		return out, err
	}
	if out.Token == "" || out.AgentID == "" {
		return out, errors.New("hub enrollment response is missing agent_id or token")
	}
	return out, nil
}

// HeartbeatRequest is the POST /heartbeat body.
type HeartbeatRequest struct {
	AgentVersion string      `json:"agent_version"`
	Operations   []string    `json:"operations"`
	Facts        state.Facts `json:"facts"`
}

// Heartbeat reports liveness and facts.
func (c *Client) Heartbeat(ctx context.Context, r HeartbeatRequest) error {
	return c.do(ctx, http.MethodPost, "/heartbeat", r, nil)
}

// Execution is one envelope to verify and run.
type Execution struct {
	ID        string            `json:"id"`
	Envelope  string            `json:"envelope"`
	Approvals []verify.Approval `json:"approvals"`
}

// Query is one state tool call.
type Query struct {
	ID   string         `json:"id"`
	Tool string         `json:"tool"`
	Args map[string]any `json:"args"`
}

// Work is the GET /work body.
type Work struct {
	Executions []Execution `json:"executions"`
	Queries    []Query     `json:"queries"`
}

// GetWork fetches pending executions and queries.
func (c *Client) GetWork(ctx context.Context) (Work, error) {
	var w Work
	err := c.do(ctx, http.MethodGet, "/work", nil, &w)
	return w, err
}

// Event is one execution event; see PROTOCOL.md for fields per type.
type Event map[string]any

// PostEvents sends execution events in order.
func (c *Client) PostEvents(ctx context.Context, executionID string, events []Event) error {
	return c.do(ctx, http.MethodPost, "/executions/"+url.PathEscape(executionID)+"/events", map[string]any{"events": events}, nil)
}

// QueryResult is the POST /queries/{id}/result body.
type QueryResult struct {
	OK     bool   `json:"ok"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

// PostQueryResult sends a state tool result.
func (c *Client) PostQueryResult(ctx context.Context, queryID string, r QueryResult) error {
	return c.do(ctx, http.MethodPost, "/queries/"+url.PathEscape(queryID)+"/result", r, nil)
}
