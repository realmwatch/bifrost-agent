package executor

import (
	"context"
	"sync"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/hubclient"
	"github.com/realmwatch/bifrost-agent/internal/redact"
)

// Sink delivers a batch of events for one execution, in order.
type Sink func(ctx context.Context, events []hubclient.Event) error

// maxChunk caps the data of one output event.
const maxChunk = 32 << 10

type chunk struct {
	phase  string
	index  int
	stream string
	data   []byte
}

// stream numbers events, buffers them with pending output, and sends them
// through the sink in order.
type stream struct {
	mu      sync.Mutex
	sendMu  sync.Mutex
	seq     int
	pending []hubclient.Event
	chunks  []chunk
	now     func() time.Time
	sink    Sink
	// all keeps every event for callers that want the full log.
	all []hubclient.Event
}

func newStream(sink Sink, now func() time.Time) *stream {
	return &stream{sink: sink, now: now}
}

// emit adds an event after any output written so far.
func (s *stream) emit(typ string, fields map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.drainChunksLocked()
	s.addLocked(typ, fields)
}

func (s *stream) addLocked(typ string, fields map[string]any) {
	s.seq++
	ev := hubclient.Event{"seq": s.seq, "at": s.now().UTC().Format(time.RFC3339), "type": typ}
	for k, v := range fields {
		ev[k] = v
	}
	s.pending = append(s.pending, ev)
	s.all = append(s.all, ev)
}

func (s *stream) drainChunksLocked() {
	for _, c := range s.chunks {
		data := c.data
		for len(data) > 0 {
			n := min(len(data), maxChunk)
			s.addLocked("output", map[string]any{
				"phase": c.phase, "index": c.index, "stream": c.stream, "data": redact.String(string(data[:n])),
			})
			data = data[n:]
		}
	}
	s.chunks = nil
}

func (s *stream) write(phase string, index int, name string, p []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := len(s.chunks); n > 0 {
		last := &s.chunks[n-1]
		if last.phase == phase && last.index == index && last.stream == name {
			last.data = append(last.data, p...)
			return
		}
	}
	s.chunks = append(s.chunks, chunk{phase, index, name, append([]byte(nil), p...)})
}

// flush sends everything pending. On failure the events stay queued and
// are sent with the next flush.
func (s *stream) flush(ctx context.Context) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	s.mu.Lock()
	s.drainChunksLocked()
	batch := s.pending
	s.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	if err := s.sink(ctx, batch); err != nil {
		return err
	}
	s.mu.Lock()
	s.pending = s.pending[len(batch):]
	s.mu.Unlock()
	return nil
}

// outputWriter is an io.Writer for one step's stdout or stderr, with a cap
// on how much output a step may produce.
type outputWriter struct {
	s       *stream
	phase   string
	index   int
	name    string
	budget  *int
	mu      *sync.Mutex
	clipped *bool
}

func (w *outputWriter) Write(p []byte) (int, error) {
	n := len(p)
	w.mu.Lock()
	if *w.budget <= 0 {
		if !*w.clipped {
			*w.clipped = true
			w.mu.Unlock()
			w.s.write(w.phase, w.index, w.name, []byte("\n[output truncated by bifrost-agent]\n"))
			return n, nil
		}
		w.mu.Unlock()
		return n, nil
	}
	if len(p) > *w.budget {
		p = p[:*w.budget]
	}
	*w.budget -= len(p)
	w.mu.Unlock()
	w.s.write(w.phase, w.index, w.name, p)
	return n, nil
}
