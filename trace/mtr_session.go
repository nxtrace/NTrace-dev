package trace

import (
	"context"
	"runtime/pprof"
	"sync"
)

// mtrWorkerSession owns every cancellable worker created for one MTR run.
type mtrWorkerSession struct {
	ctx    context.Context
	cancel context.CancelCauseFunc
	wg     sync.WaitGroup
}

func newMTRWorkerSession(parent context.Context) *mtrWorkerSession {
	ctx, cancel := context.WithCancelCause(parent)
	return &mtrWorkerSession{ctx: ctx, cancel: cancel}
}

func (s *mtrWorkerSession) Go(owner string, fn func()) {
	s.wg.Go(func() {
		pprof.Do(s.ctx, pprof.Labels("owner", owner), func(context.Context) {
			fn()
		})
	})
}

func (s *mtrWorkerSession) shutdown(closeResources func()) {
	s.cancel(nil)
	if closeResources != nil {
		closeResources()
	}
	s.wg.Wait()
}

type mtrSessionStarter interface {
	startMTRSession(*mtrWorkerSession) error
}
