package trace

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nxtrace/NTrace-core/trace/internal"
)

// probeSetupError cannot be recovered by retrying a TTL or counting a timeout.
type probeSetupError = internal.InitializationError

// IsInitializationError reports failures to initialize or replace probe resources.
func IsInitializationError(err error) bool {
	var setup *probeSetupError
	return errors.As(err, &setup)
}

// A caller-supplied context owns cancellation, including the CLI's signal cause.
func traceSignalContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent != nil {
		return context.WithCancel(parent)
	}
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func wrapProbeSetupError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var setup *probeSetupError
	if errors.As(err, &setup) {
		return err
	}
	return &probeSetupError{Err: err}
}

func waitProbeListeners(ctx context.Context, ready ...chan struct{}) error {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for _, ch := range ready {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-timer.C:
			return wrapProbeSetupError(errors.New("probe listener startup timeout"))
		case <-ch:
		}
	}
	if !waitForTraceDelay(ctx, 100*time.Millisecond) {
		return context.Cause(ctx)
	}
	return nil
}
