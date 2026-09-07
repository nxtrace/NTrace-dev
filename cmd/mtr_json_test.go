package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nxtrace/NTrace-core/trace"
	"github.com/nxtrace/NTrace-core/util"
)

func decodeMTRJSON(t *testing.T, data []byte) []map[string]json.RawMessage {
	t.Helper()
	var result []map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var value map[string]json.RawMessage
		err := dec.Decode(&value)
		if err == io.EOF {
			return result
		}
		if err != nil {
			t.Fatalf("invalid JSON: %v\n%s", err, data)
		}
		result = append(result, value)
	}
}

func TestRequestsMTRJSONRoutesSyntaxErrors(t *testing.T) {
	for _, args := range [][]string{
		{"--mtr", "--json=invalid"}, {"-rj"}, {"-twj", "--unknown"},
	} {
		if !requestsMTRJSON(args) {
			t.Fatalf("MTR JSON diagnostics not selected: %v", args)
		}
	}
	if requestsMTRJSON([]string{"--", "--mtr", "--json"}) {
		t.Fatal("positional flags selected MTR JSON")
	}
}

func TestMTRJSONHelpAndVersion(t *testing.T) {
	for _, flag := range []string{"--help", "-h", "--version", "-V"} {
		t.Run(flag, func(t *testing.T) {
			args := []string{"-test.run=^TestMTRJSONCLIProcess$", "--", "--json", flag}
			if enableTraceroute {
				args = append(args, "--mtr")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			process := exec.CommandContext(ctx, os.Args[0], args...)
			process.Env = append(os.Environ(), "NTRACE_TEST_MTR_JSON_PROCESS=1")
			var stdout, stderr bytes.Buffer
			process.Stdout, process.Stderr = &stdout, &stderr
			if err := process.Run(); err != nil || stdout.Len() == 0 || stderr.Len() != 0 {
				t.Fatalf("%s: error=%v stdout=%s stderr=%s", flag, err, stdout.String(), stderr.String())
			}
			if (flag == "--help" || flag == "-h") && !strings.Contains(stdout.String(), "usage:") {
				t.Fatalf("missing help output: %s", stdout.String())
			}
			if (flag == "--version" || flag == "-V") && !strings.Contains(stdout.String(), "NextTrace CopyRight") {
				t.Fatalf("missing version command output: %s", stdout.String())
			}
		})
	}
}

func TestMTRJSONStreamRecordsAndPathChanges(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	var stdout, stderr bytes.Buffer
	out := newMTRJSONOutput(&stdout, true, "example.com", trace.ICMPTrace, cancel)
	out.startStream()
	records := []trace.MTRRawRecord{
		{TTL: 1, Success: true, IP: "192.0.2.1", Host: "中文\n\"host\"", RTTMs: 0, ASN: "64500", City: "测试", MPLS: []string{"label=16"}},
		{TTL: 2, Success: false},
	}
	for _, rec := range records {
		out.probe(rec)
	}
	out.pathEnd(&trace.StopReason{Hop: 2, Reason: trace.StopReasonUnreachable})
	out.pathEnd(nil)
	out.pathEnd(&trace.StopReason{Hop: 3, Reason: trace.StopReasonDestination})
	if code := out.finish(nil, "probe", &stderr); code != 0 || ctx.Err() != nil {
		t.Fatalf("exit=%d, err=%v, stderr=%s", code, ctx.Err(), stderr.String())
	}
	lines := bytes.Split(bytes.TrimSpace(stdout.Bytes()), []byte{'\n'})
	wantTypes := []string{"start", "probe", "probe", "path_end", "path_end", "path_end", "end"}
	if len(lines) != len(wantTypes) {
		t.Fatalf("line count=%d, output=%s", len(lines), stdout.String())
	}
	values := decodeMTRJSON(t, stdout.Bytes())
	for i, value := range values {
		var typ string
		var seq, version int
		_ = json.Unmarshal(value["type"], &typ)
		_ = json.Unmarshal(value["seq"], &seq)
		_ = json.Unmarshal(value["schema_version"], &version)
		if typ != wantTypes[i] || seq != i+1 || version != 1 {
			t.Fatalf("event %d: %s", i, lines[i])
		}
		if i == 1 || i == 2 {
			var rec trace.MTRRawRecord
			if err := json.Unmarshal(value["record"], &rec); err != nil || !reflect.DeepEqual(rec, records[i-1]) {
				t.Fatalf("record %d changed: %#v, %v", i, rec, err)
			}
		}
	}
	if string(values[4]["path_end"]) != "null" || string(values[6]["end_reason"]) != `"completed"` {
		t.Fatalf("path reopening/completion lost: %s", stdout.String())
	}
	if _, present := values[6]["stats"]; present {
		t.Fatal("stream end must not recompute a report")
	}
}

func TestMTRJSONEmptyAndPartialOutcomes(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, tc := range []struct {
			name, stage, reason, signal string
			err                         error
			code                        int
		}{
			{name: "complete", stage: "probe", reason: "completed"},
			{name: "validation", stage: "validation", reason: "error", err: errors.New("bad queries"), code: 2},
			{name: "dns", stage: "resolve", reason: "error", err: errors.New("no address"), code: 1},
			{name: "setup", stage: "initialize", reason: "error", err: errors.New("socket denied"), code: 1},
			{name: "runtime", stage: "probe", reason: "error", err: errors.New("rotation failed"), code: 1},
			{name: "internal cancellation", stage: "probe", reason: "error", err: context.Canceled, code: 1},
			{name: "interrupt", reason: "interrupted", signal: "SIGINT", err: &mtrJSONSignal{os.Interrupt}, code: 130},
			{name: "terminate", reason: "interrupted", signal: "SIGTERM", err: &mtrJSONSignal{syscall.SIGTERM}, code: 143},
		} {
			t.Run(tc.name+map[bool]string{true: "/stream", false: "/report"}[stream], func(t *testing.T) {
				_, cancel := context.WithCancelCause(t.Context())
				defer cancel(nil)
				var stdout, stderr bytes.Buffer
				out := newMTRJSONOutput(&stdout, stream, "target", trace.UDPTrace, cancel)
				if tc.name == "runtime" {
					out.report.Stats = []trace.MTRHopStat{{TTL: 1, Snt: 2, Received: 1, Loss: 50, Avg: 1.5}}
				}
				if code := out.finish(tc.err, tc.stage, &stderr); code != tc.code {
					t.Fatalf("exit=%d want=%d", code, tc.code)
				}
				values := decodeMTRJSON(t, stdout.Bytes())
				count := 1
				if stream {
					count = 2
				}
				if len(values) != count {
					t.Fatalf("got %d documents", len(values))
				}
				last := values[len(values)-1]
				if string(last["end_reason"]) != `"`+tc.reason+`"` {
					t.Fatalf("outcome: %s", stdout.String())
				}
				if tc.signal != "" && string(last["signal"]) != `"`+tc.signal+`"` {
					t.Fatal("missing signal")
				}
				if !stream {
					if tc.name == "runtime" && !bytes.Contains(last["stats"], []byte(`"snt":2`)) {
						t.Fatal("lost partial stats")
					}
					if tc.name != "runtime" && string(last["stats"]) != "[]" {
						t.Fatal("empty stats must be []")
					}
				}
			})
		}
	}
}

type failingMTRWriter struct {
	calls int
	short bool
}

func (w *failingMTRWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.short {
		return len(p) - 1, nil
	}
	return 0, io.ErrClosedPipe
}

func TestMTRJSONWriteFailureCancelsWithoutRetry(t *testing.T) {
	for _, short := range []bool{false, true} {
		ctx, cancel := context.WithCancelCause(t.Context())
		w := &failingMTRWriter{short: short}
		out := newMTRJSONOutput(w, true, "target", trace.ICMPTrace, cancel)
		out.startStream()
		out.probe(trace.MTRRawRecord{TTL: 1})
		if out.finish(nil, "probe", io.Discard) != 1 || ctx.Err() == nil || w.calls != 1 {
			t.Fatalf("write failure retried or not canceled: calls=%d cause=%v", w.calls, context.Cause(ctx))
		}
		cancel(nil)
	}
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	var data bytes.Buffer
	out := newMTRJSONOutput(&data, true, "target", trace.ICMPTrace, cancel)
	out.startStream()
	out.probe(trace.MTRRawRecord{RTTMs: math.NaN()})
	if out.finish(nil, "probe", io.Discard) != 1 || ctx.Err() == nil || len(decodeMTRJSON(t, data.Bytes())) != 1 {
		t.Fatal("encoding failure must leave only previously completed events")
	}
}

func testMTRJSONOptions() mtrJSONOptions {
	return mtrJSONOptions{
		Target: "example.com", Method: trace.ICMPTrace, MaxPerHop: 2, HopIntervalMs: 10,
		DataProvider: "disable-geoip", PowProvider: "api.nxtrace.org",
		Config: trace.Config{SrcAddr: "127.0.0.1", MaxHops: 3, Timeout: time.Second, Lang: "cn"},
	}
}

func TestMTRJSONStreamOrdersProbeBeforePathChange(t *testing.T) {
	oldRaw := runMTRJSONRawFn
	t.Cleanup(func() { runMTRJSONRawFn = oldRaw })
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	var stdout bytes.Buffer
	out := newMTRJSONOutput(&stdout, true, "target", trace.ICMPTrace, cancel)
	out.startStream()
	records := []trace.MTRRawRecord{{TTL: 1, IP: "192.0.2.1"}, {TTL: 2, IP: "192.0.2.2"}}
	runMTRJSONRawFn = func(_ context.Context, _ trace.Method, _ trace.Config, opts trace.MTRRawOptions, cb trace.MTRRawOnRecord) error {
		for i, reason := range []*trace.StopReason{{Hop: 1, Reason: trace.StopReasonUnreachable}, nil} {
			opts.OnPathEnd(reason)
			cb(records[i])
			if got := len(decodeMTRJSON(t, stdout.Bytes())); got != 3+2*i {
				t.Fatalf("probe/path change were not flushed immediately: %s", stdout.String())
			}
		}
		opts.OnPathEnd(&trace.StopReason{Hop: 3, Reason: trace.StopReasonMaxHops})
		return nil
	}
	err := runMTRJSONStream(ctx, testMTRJSONOptions(), out)
	if code := out.finish(err, "probe", io.Discard); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	events := decodeMTRJSON(t, stdout.Bytes())
	wantTypes := []string{"start", "probe", "path_end", "probe", "path_end", "path_end", "end"}
	if len(events) != len(wantTypes) {
		t.Fatalf("unexpected events: %s", stdout.String())
	}
	for i, want := range wantTypes {
		if string(events[i]["type"]) != `"`+want+`"` || string(events[i]["seq"]) != fmt.Sprint(i+1) {
			t.Fatalf("event %d: %s", i, stdout.String())
		}
	}
	for i, event := range []map[string]json.RawMessage{events[1], events[3]} {
		var got trace.MTRRawRecord
		if err := json.Unmarshal(event["record"], &got); err != nil || !reflect.DeepEqual(got, records[i]) {
			t.Fatalf("RAW record changed: %+v, %v", got, err)
		}
	}
	if string(events[4]["path_end"]) != "null" || !bytes.Equal(events[5]["path_end"], events[6]["path_end"]) {
		t.Fatalf("lost reopening or final max-hops conclusion: %s", stdout.String())
	}
}

func TestMTRJSONRunnerUsesFullConfigAndPreservesSnapshot(t *testing.T) {
	oldPort, oldDst := util.SrcPort, util.DstIP
	t.Cleanup(func() { util.SrcPort, util.DstIP = oldPort, oldDst })
	oldLookup, oldReport, oldRaw := domainLookupFn, runMTRReportFn, runMTRJSONRawFn
	t.Cleanup(func() { domainLookupFn, runMTRReportFn, runMTRJSONRawFn = oldLookup, oldReport, oldRaw })
	domainLookupFn = func(context.Context, string, string, string, bool) (net.IP, error) {
		return net.ParseIP("127.0.0.1"), nil
	}
	want := []trace.MTRHopStat{
		{TTL: 1, IP: "192.0.2.1", Snt: 1, Received: 1},
		{TTL: 1, IP: "192.0.2.2", Snt: 1, Received: 1, Avg: 2.5},
		{TTL: 2, Snt: 2, Loss: 100},
	}
	runMTRReportFn = func(_ context.Context, _ trace.Method, cfg trace.Config, opts trace.MTROptions, snapshot trace.MTROnSnapshot) error {
		if cfg.AlwaysWaitRDNS || cfg.TTLInterval != 0 || opts.MaxPerHop != 2 {
			t.Fatalf("unexpected report config: %+v", cfg)
		}
		opts.OnPathEnd(&trace.StopReason{Hop: 3, Reason: trace.StopReasonDestination})
		snapshot(1, want)
		return errors.New("rotation failed")
	}
	var stdout, stderr bytes.Buffer
	opts := testMTRJSONOptions()
	opts.Report, opts.PacketSizeExplicit, opts.PacketSize = true, true, -84
	if code := runMTRJSON(t.Context(), opts, &stdout, &stderr); code != 1 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	var report mtrJSONReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(report.Stats, want) || report.PathEnd.Reason != trace.StopReasonDestination {
		t.Fatalf("lost snapshot: %s", stdout.String())
	}
	if p := report.EffectiveParameters; p.PacketSize != -84 || !p.RandomPacketSize || p.MaxPerHop != 2 || p.Port != nil {
		t.Fatalf("effective parameters: %+v", p)
	}

	runMTRJSONRawFn = func(ctx context.Context, _ trace.Method, _ trace.Config, opts trace.MTRRawOptions, callback trace.MTRRawOnRecord) error {
		callback(trace.MTRRawRecord{TTL: 1, Success: true, IP: "192.0.2.1"})
		opts.OnPathEnd(nil)
		return &mtrJSONSignal{syscall.SIGTERM}
	}
	stdout.Reset()
	stderr.Reset()
	opts.Report = false
	if code := runMTRJSON(t.Context(), opts, &stdout, &stderr); code != 143 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if values := decodeMTRJSON(t, stdout.Bytes()); len(values) != 4 {
		t.Fatalf("events=%d", len(values))
	}
}

func TestMTRJSONPreparationFailures(t *testing.T) {
	oldLookup := domainLookupFn
	t.Cleanup(func() { domainLookupFn = oldLookup })
	for _, tc := range []struct {
		name      string
		source    string
		lookupErr error
		code      int
	}{
		{"DNS failure", "127.0.0.1", errors.New("DNS unavailable"), 1},
		{"interrupted resolution", "127.0.0.1", &mtrJSONSignal{os.Interrupt}, 130},
		{"invalid source", "bad-source", nil, 2},
		{"wrong source family", "::1", nil, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			domainLookupFn = func(context.Context, string, string, string, bool) (net.IP, error) {
				return net.IPv4(127, 0, 0, 1), tc.lookupErr
			}
			opts := testMTRJSONOptions()
			opts.Config.SrcAddr = tc.source
			var stdout, stderr bytes.Buffer
			if code := runMTRJSON(t.Context(), opts, &stdout, &stderr); code != tc.code {
				t.Fatalf("code=%d: %s", code, stderr.String())
			}
			values := decodeMTRJSON(t, stdout.Bytes())
			if len(values) != 2 || string(values[0]["effective_parameters"]) != "null" {
				t.Fatalf("invalid failed lifecycle: %s", stdout.String())
			}
			if tc.lookupErr != nil && string(values[0]["resolved_ip"]) != "null" {
				t.Fatal("failed DNS must not claim a resolved address")
			}
		})
	}
}

func TestMTRJSONUsesEveryRawFixtureRecord(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	var stdout, stderr bytes.Buffer
	out := newMTRJSONOutput(&stdout, true, "fixture", trace.ICMPTrace, cancel)
	out.startStream()
	var records []trace.MTRRawRecord
	err := trace.RunMTRRaw(ctx, trace.ICMPTrace, trace.Config{MaxHops: 2}, trace.MTRRawOptions{
		MaxRounds: 1,
		RunRound: func(_ trace.Method, cfg trace.Config) (*trace.Result, error) {
			res := &trace.Result{Hops: [][]trace.Hop{
				{{TTL: 1, Success: true, Address: &net.IPAddr{IP: net.IPv4(192, 0, 2, 1)}, RTT: 0, MPLS: []string{"label=16"}}, {TTL: 1, Success: true, Address: &net.IPAddr{IP: net.IPv4(192, 0, 2, 2)}}},
				{{TTL: 2, Success: false}},
			}}
			cfg.RealtimePrinter(res, 0)
			cfg.RealtimePrinter(res, 1)
			return res, nil
		}, OnPathEnd: out.pathEnd,
	}, func(rec trace.MTRRawRecord) { records = append(records, rec); out.probe(rec) })
	if code := out.finish(err, "probe", &stderr); code != 0 {
		t.Fatalf("code=%d: %s", code, stderr.String())
	}
	values := decodeMTRJSON(t, stdout.Bytes())
	var got []trace.MTRRawRecord
	for _, value := range values {
		if string(value["type"]) == `"probe"` {
			var rec trace.MTRRawRecord
			if err := json.Unmarshal(value["record"], &rec); err != nil {
				t.Fatal(err)
			}
			got = append(got, rec)
		}
	}
	if len(records) != 3 || !reflect.DeepEqual(got, records) {
		t.Fatalf("RAW/JSON records differ: %+v / %+v", records, got)
	}
}

func TestMTRJSONCLIProcess(t *testing.T) {
	if os.Getenv("NTRACE_TEST_MTR_JSON_PROCESS") == "1" {
		domainLookupFn = func(context.Context, string, string, string, bool) (net.IP, error) {
			return net.ParseIP("127.0.0.1"), nil
		}
		runMTRJSONRawFn = func(ctx context.Context, _ trace.Method, _ trace.Config, _ trace.MTRRawOptions, cb trace.MTRRawOnRecord) error {
			if os.Getenv("NTRACE_TEST_MTR_JSON_BLOCK") != "zero" {
				cb(trace.MTRRawRecord{TTL: 1, Success: true, ASN: "64500", City: "测试", RTTMs: 0})
			}
			if os.Getenv("NTRACE_TEST_MTR_JSON_BLOCK") != "" {
				fmt.Fprintln(os.Stderr, "ready")
				<-ctx.Done()
				return ctx.Err()
			}
			return nil
		}
		runMTRReportFn = func(ctx context.Context, _ trace.Method, cfg trace.Config, _ trace.MTROptions, cb trace.MTROnSnapshot) error {
			if cfg.AlwaysWaitRDNS {
				panic("report must use wide rules")
			}
			if os.Getenv("NTRACE_TEST_MTR_JSON_BLOCK") != "zero" {
				cb(1, []trace.MTRHopStat{{TTL: 1, Snt: 1, Received: 1}})
			}
			if os.Getenv("NTRACE_TEST_MTR_JSON_BLOCK") != "" {
				fmt.Fprintln(os.Stderr, "ready")
				<-ctx.Done()
				return ctx.Err()
			}
			return nil
		}
		for i, arg := range os.Args {
			if arg == "--" {
				os.Args = append([]string{appBinName}, os.Args[i+1:]...)
				break
			}
		}
		Execute()
		os.Exit(0)
	}
	base := []string{"--json", "--data-provider", "disable-geoip", "-s", "127.0.0.1", "127.0.0.1"}
	if enableTraceroute {
		base = append([]string{"--mtr"}, base...)
	}
	for _, tc := range []struct {
		name            string
		extra           []string
		code, documents int
	}{
		{"stream", nil, 0, 3},
		{"finite stream", []string{"-q", "10"}, 0, 3},
		{"unlimited zero", []string{"-q", "0"}, 0, 3},
		{"unlimited negative", []string{"-q", "-1"}, 0, 3},
		{"ignored y", []string{"-y", "99"}, 0, 3},
		{"report", []string{"-r"}, 0, 1},
		{"wide", []string{"-w"}, 0, 1},
		{"report ignored y", []string{"-r", "-y", "99"}, 0, 1},
		{"invalid report count", []string{"-r", "-q", "0"}, 2, 1},
		{"invalid tos", []string{"-Q", "256"}, 2, 2},
		{"duplicate source syntax", []string{"-s", "bad-source"}, 2, 0},
		{"raw conflict", []string{"--raw"}, 2, 0},
		{"unknown argument", []string{"--unknown-mtr-option"}, 2, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"-test.run=^TestMTRJSONCLIProcess$", "--"}, base...)
			args = append(args, tc.extra...)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], args...)
			cmd.Env = append(os.Environ(), "NTRACE_TEST_MTR_JSON_PROCESS=1")
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			code := 0
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatal(err)
				}
				code = exit.ExitCode()
			}
			if code != tc.code {
				t.Fatalf("exit=%d want=%d stdout=%s stderr=%s", code, tc.code, stdout.String(), stderr.String())
			}
			values := decodeMTRJSON(t, stdout.Bytes())
			if len(values) != tc.documents {
				t.Fatalf("documents=%d output=%s stderr=%s", len(values), stdout.String(), stderr.String())
			}
			if strings.Contains(stdout.String(), "\x1b") {
				t.Fatal("ANSI in JSON")
			}
			if code == 0 && tc.documents == 3 && !bytes.Contains(values[1]["record"], []byte(`"asn":"64500"`)) {
				t.Fatal("FULL fields missing")
			}
		})
	}
}
