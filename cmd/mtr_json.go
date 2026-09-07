package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/nxtrace/NTrace-core/config"
	"github.com/nxtrace/NTrace-core/trace"
)

const mtrJSONSchemaVersion = 1

type mtrJSONParameters struct {
	MaxPerHop        int    `json:"max_per_hop"`
	HopIntervalMs    int    `json:"hop_interval_ms"`
	TimeoutMs        int64  `json:"timeout_ms"`
	BeginHop         int    `json:"begin_hop"`
	MaxHops          int    `json:"max_hops"`
	ParallelRequests int    `json:"parallel_requests"`
	SourceAddress    string `json:"source_address"`
	SourceDevice     string `json:"source_device,omitempty"`
	SourcePort       *int   `json:"source_port,omitempty"`
	Port             *int   `json:"port,omitempty"`
	PacketSize       int    `json:"packet_size"`
	RandomPacketSize bool   `json:"random_packet_size"`
	TOS              int    `json:"tos"`
	ICMPMode         *int   `json:"icmp_mode,omitempty"`
	DataProvider     string `json:"data_provider"`
	Language         string `json:"language"`
	DotServer        string `json:"dot_server,omitempty"`
	RDNS             bool   `json:"rdns"`
	AlwaysWaitRDNS   bool   `json:"always_wait_rdns"`
	DisableMPLS      bool   `json:"disable_mpls"`
	DN42             bool   `json:"dn42"`
}

type mtrJSONSession struct {
	Version             string             `json:"version"`
	Target              string             `json:"target"`
	ResolvedIP          *string            `json:"resolved_ip"`
	Protocol            string             `json:"protocol"`
	StartedAt           time.Time          `json:"started_at"`
	EffectiveParameters *mtrJSONParameters `json:"effective_parameters"`
}

type mtrJSONError struct {
	Stage   string `json:"stage"`
	Message string `json:"message"`
}

type mtrJSONEnd struct {
	EndedAt    time.Time         `json:"ended_at"`
	DurationMs int64             `json:"duration_ms"`
	EndReason  string            `json:"end_reason"`
	PathEnd    *trace.StopReason `json:"path_end"`
	Error      *mtrJSONError     `json:"error,omitempty"`
	Signal     string            `json:"signal,omitempty"`
}

type mtrJSONReport struct {
	SchemaVersion int `json:"schema_version"`
	mtrJSONSession
	mtrJSONEnd
	Stats []trace.MTRHopStat `json:"stats"`
}

type mtrJSONEvent struct {
	SchemaVersion int    `json:"schema_version"`
	Type          string `json:"type"`
	Seq           uint64 `json:"seq"`
	*mtrJSONSession
	*mtrJSONEnd
	Record *trace.MTRRawRecord `json:"record,omitempty"`
}

// One writer owns event ordering and remembers the first write failure.
type mtrJSONOutput struct {
	mu      sync.Mutex
	writer  io.Writer
	cancel  context.CancelCauseFunc
	stream  bool
	started bool
	seq     uint64
	err     error
	start   time.Time
	report  mtrJSONReport
}

func newMTRJSONOutput(w io.Writer, stream bool, target string, method trace.Method, cancel context.CancelCauseFunc) *mtrJSONOutput {
	start := time.Now()
	return &mtrJSONOutput{
		writer: w, stream: stream, cancel: cancel, start: start,
		report: mtrJSONReport{
			SchemaVersion:  mtrJSONSchemaVersion,
			mtrJSONSession: mtrJSONSession{Version: config.Version, Target: target, Protocol: string(method), StartedAt: start.UTC()},
			Stats:          make([]trace.MTRHopStat, 0),
		},
	}
}

func (o *mtrJSONOutput) writeLocked(value any) {
	if o.err != nil {
		return
	}
	data, err := json.Marshal(value)
	if err == nil {
		data = append(data, '\n')
		var n int
		n, err = o.writer.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
	}
	if err != nil {
		o.err = err
		o.cancel(err)
	}
}

func (o *mtrJSONOutput) eventLocked(event mtrJSONEvent) {
	o.seq++
	event.SchemaVersion, event.Seq = mtrJSONSchemaVersion, o.seq
	o.writeLocked(event)
}

func (o *mtrJSONOutput) startLocked() {
	if !o.stream || o.started {
		return
	}
	o.started = true
	o.eventLocked(mtrJSONEvent{Type: "start", mtrJSONSession: &o.report.mtrJSONSession})
}

func (o *mtrJSONOutput) startStream() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.startLocked()
}

func (o *mtrJSONOutput) probe(rec trace.MTRRawRecord) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.eventLocked(mtrJSONEvent{Type: "probe", Record: &rec})
}

func (o *mtrJSONOutput) pathEnd(reason *trace.StopReason) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.report.PathEnd = copyMTRPathEnd(reason)
	// A separate payload makes an explicit null distinct from an absent field.
	o.seq++
	o.writeLocked(struct {
		SchemaVersion int               `json:"schema_version"`
		Type          string            `json:"type"`
		Seq           uint64            `json:"seq"`
		PathEnd       *trace.StopReason `json:"path_end"`
	}{mtrJSONSchemaVersion, "path_end", o.seq, o.report.PathEnd})
}

func copyMTRPathEnd(reason *trace.StopReason) *trace.StopReason {
	if reason == nil {
		return nil
	}
	result := *reason
	result.Responses = append([]string(nil), reason.Responses...)
	result.Markers = append([]string(nil), reason.Markers...)
	return &result
}

type mtrJSONSignal struct{ signal os.Signal }

func (e *mtrJSONSignal) Error() string { return e.signal.String() }

func (o *mtrJSONOutput) finish(err error, stage string, stderr io.Writer) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	code := 0
	o.report.EndedAt = time.Now().UTC()
	o.report.DurationMs = time.Since(o.start).Milliseconds()
	o.report.EndReason = "completed"
	var interrupted *mtrJSONSignal
	switch {
	case errors.As(err, &interrupted):
		o.report.EndReason, o.report.Signal, code = "interrupted", "SIGINT", 130
		if interrupted.signal == syscall.SIGTERM {
			o.report.Signal, code = "SIGTERM", 143
		}
	case err != nil:
		o.report.EndReason = "error"
		o.report.Error = &mtrJSONError{Stage: stage, Message: err.Error()}
		code = 1
		if stage == "validation" {
			code = 2
		}
		_, _ = fmt.Fprintln(stderr, err)
	}
	if o.stream {
		o.startLocked()
		o.eventLocked(mtrJSONEvent{Type: "end", mtrJSONEnd: &o.report.mtrJSONEnd})
	} else {
		o.writeLocked(o.report)
	}
	if o.err != nil {
		_, _ = fmt.Fprintf(stderr, "write MTR JSON: %v\n", o.err)
		return 1
	}
	return code
}

var runMTRReportFn = trace.RunMTR

// Both human and JSON reports consume the same final snapshot.
func collectMTRReport(ctx context.Context, method trace.Method, conf trace.Config, opts trace.MTROptions) ([]trace.MTRHopStat, *trace.StopReason, error) {
	stats := make([]trace.MTRHopStat, 0)
	var pathEnd *trace.StopReason
	opts.OnPathEnd = func(reason *trace.StopReason) { pathEnd = copyMTRPathEnd(reason) }
	err := runMTRReportFn(ctx, method, conf, opts, func(_ int, snapshot []trace.MTRHopStat) {
		stats = append(stats[:0], snapshot...)
	})
	return stats, pathEnd, err
}
