package trace

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestIsInitializationError(t *testing.T) {
	cause := errors.New("socket unavailable")
	for _, err := range []error{wrapProbeSetupError(cause), fmt.Errorf("mtr: %w", wrapProbeSetupError(cause))} {
		if !IsInitializationError(err) || !errors.Is(err, cause) {
			t.Fatalf("lost initialization classification or cause: %v", err)
		}
	}
	for _, err := range []error{nil, cause, context.Canceled, context.DeadlineExceeded} {
		if IsInitializationError(err) {
			t.Fatalf("misclassified ordinary error: %v", err)
		}
	}
}

func TestProbeListenersWaitForEveryListenerAndPreserveCause(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancelCause(t.Context())
		defer cancel(nil)
		first, second := make(chan struct{}), make(chan struct{})
		close(first)
		done := make(chan error, 1)
		go func() { done <- waitProbeListeners(ctx, first, second) }()
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("returned before second listener was ready: %v", err)
		default:
		}
		cause := wrapProbeSetupError(errors.New("pcap initialization failed"))
		cancel(cause)
		if err := <-done; !errors.Is(err, cause) {
			t.Fatalf("lost setup cause: %v", err)
		}
	})
	synctest.Test(t, func(t *testing.T) {
		err := waitProbeListeners(t.Context(), make(chan struct{}))
		var setup *probeSetupError
		if !errors.As(err, &setup) {
			t.Fatalf("readiness timeout must be terminal: %v", err)
		}
	})
}

func TestSchedulerSetupFailurePreservesStatsAndClosesProber(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	cause := errors.New("ICMP rotation failed")
	prober := &mockTTLProber{}
	prober.probeFn = func(context.Context, int) (mtrProbeResult, error) {
		if prober.getProbeCount() == 1 {
			return mtrProbeResult{TTL: 1, Success: true, Addr: &net.IPAddr{IP: net.IPv4(192, 0, 2, 1)}}, nil
		}
		return mtrProbeResult{}, wrapProbeSetupError(cause)
	}
	var final []MTRHopStat
	probes := 0
	err := runMTRScheduler(ctx, prober, NewMTRAggregator(), mtrSchedulerConfig{
		BeginHop: 1, MaxHops: 1, HopInterval: time.Millisecond, MaxPerHop: 3,
		ParallelRequests: 1, MaxInFlightPerHop: 1, MaxConsecErrors: 1,
	}, func(_ int, stats []MTRHopStat) { final = stats }, func(mtrProbeResult, int, time.Time) { probes++ })
	if !errors.Is(err, cause) || errors.Is(err, context.Canceled) {
		t.Fatalf("lost setup cause: %v", err)
	}
	if probes != 1 || len(final) != 1 || final[0].Snt != 1 || final[0].Last != 0 {
		t.Fatalf("setup failure was counted as timeout or discarded stats: probes=%d stats=%+v", probes, final)
	}
	if prober.getProbeCount() != 2 || atomic.LoadInt32(&prober.closeCnt) != 1 {
		t.Fatalf("unexpected retry/cleanup: probes=%d closes=%d", prober.getProbeCount(), prober.closeCnt)
	}
}

func TestMTRICMPSetupAndRotationReturnErrors(t *testing.T) {
	for _, rotate := range []bool{false, true} {
		workers := newMTRWorkerSession(t.Context())
		engine := newMTRICMPEngineState(Config{DstIP: net.IPv4(127, 0, 0, 1)}, 4, net.IP{1, 2, 3})
		engine.workers = workers
		var err error
		if rotate {
			err = engine.rotateEngine(workers.ctx)
		} else {
			err = engine.startMTRSession(workers)
		}
		workers.shutdown(engine.close)
		var setup *probeSetupError
		if !errors.As(err, &setup) || engine.spec.Load() != nil {
			t.Fatalf("rotate=%v: err=%v spec=%v", rotate, err, engine.spec.Load())
		}
	}
}

func TestMTRICMPRotationFailureClosesPreviousListener(t *testing.T) {
	workers := newMTRWorkerSession(t.Context())
	engine := newMTRICMPEngineState(Config{DstIP: net.IPv4(127, 0, 0, 1), ICMPMode: 1}, 4, net.IPv4(127, 0, 0, 1))
	defer workers.shutdown(engine.close)
	if err := engine.startMTRSession(workers); err != nil {
		t.Skipf("ICMP loopback socket unavailable: %v", err)
	}
	oldDone := engine.listenerDone
	engine.srcIP = net.IP{1, 2, 3}
	err := engine.rotateEngine(workers.ctx)
	var setup *probeSetupError
	if !errors.As(err, &setup) || engine.spec.Load() != nil || workers.ctx.Err() != nil {
		t.Fatalf("rotation error=%v spec=%v session=%v", err, engine.spec.Load(), workers.ctx.Err())
	}
	select {
	case <-oldDone:
	default:
		t.Fatal("old listener was not joined before failed rotation returned")
	}
}

func TestMTRLegacyLoopDoesNotRetrySetupFailure(t *testing.T) {
	cause := errors.New("probe initialization failed")
	calls := 0
	prober := &mockProber{roundFn: func(context.Context) (*Result, error) {
		calls++
		return nil, wrapProbeSetupError(cause)
	}}
	err := mtrLoop(t.Context(), prober, Config{MaxHops: 1}, MTROptions{MaxRounds: 1}, NewMTRAggregator(), nil, false, fastBackoff)
	if !errors.Is(err, cause) || calls != 1 || atomic.LoadInt32(&prober.closed) != 1 {
		t.Fatalf("error=%v calls=%d closed=%d", err, calls, prober.closed)
	}
}
