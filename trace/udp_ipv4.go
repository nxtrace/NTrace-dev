package trace

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket/layers"
	"golang.org/x/sync/semaphore"

	"github.com/nxtrace/NTrace-core/trace/internal"
	"github.com/nxtrace/NTrace-core/util"
)

type UDPTracer struct {
	Config
	wg        sync.WaitGroup
	res       Result
	ttlQueues map[int][]attemptPort
	ttlQMu    sync.Mutex
	pending   map[attemptKey]struct{}
	pendingMu sync.Mutex
	sentAt    map[int]sentInfo
	sentMu    sync.RWMutex
	SrcIP     net.IP
	final     atomic.Int32
	sem       *semaphore.Weighted
	matchQ    chan matchTask
	readyOut  chan struct{}
	readyICMP chan struct{}
}

func (t *UDPTracer) waitAllReady(ctx context.Context) error {
	return waitProbeListeners(ctx, t.readyOut, t.readyICMP)
}

func (t *UDPTracer) ttlComp(ttl int) bool {
	return t.res.ttlDisplayComplete(ttl, t.NumMeasurements)
}

func (t *UDPTracer) PrintFunc(ctx context.Context, cancel context.CancelCauseFunc) {
	defer t.wg.Done()

	ttl := t.BeginHop - 1
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		nextTTL, stop := advanceStableTracePrint(
			ctx, &t.res, ttl, t.MaxHops, t.NumMeasurements, &t.final,
			t.AsyncPrinter, t.RealtimePrinter,
		)
		ttl = nextTTL
		if stop {
			cancel(errNaturalDone)
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (t *UDPTracer) launchTTL(ctx context.Context, s *internal.UDPSpec, ttl int) {
	t.wg.Add(1)
	go func(ttl int) {
		defer t.wg.Done()
		defer t.res.markTTLLaunchDoneAndCommit(ctx, ttl, t.NumMeasurements, &t.final)
		for i := 0; i < t.MaxAttempts; i++ {
			// 若此 TTL 已完成或 ctx 已取消，则不再发起新的尝试
			if t.ttlComp(ttl) || ctx.Err() != nil {
				return
			}

			if !t.res.markAttemptLaunched(ttl, i, &t.final) {
				return
			}
			t.wg.Add(1)
			go func(ttl, i int) {
				defer t.wg.Done()
				err := t.send(ctx, s, ttl, i)
				if err != nil && !errors.Is(err, context.Canceled) {
					if util.EnvDevMode {
						panic(err)
					}
					fmt.Fprintf(os.Stderr, "send error (ttl=%d, attempt=%d): %v\n", ttl, i, err)
				}
				if err != nil {
					if ctx.Err() == nil && !errors.Is(err, context.Canceled) {
						t.res.addFailedAttempt(Hop{TTL: ttl, Error: err}, &t.final, i, t.NumMeasurements, t.MaxAttempts)
					} else {
						t.res.settleAttempt(ttl, i)
					}
				}
			}(ttl, i)

			if i+1 == t.MaxAttempts {
				return
			}
			if !waitForTraceDelay(ctx, time.Millisecond*time.Duration(t.PacketInterval)) {
				return
			}
		}
	}(ttl)
}

func (t *UDPTracer) tryMatchTTLPort(ttl, srcPort int) (int, bool) {
	t.ttlQMu.Lock()
	defer t.ttlQMu.Unlock()
	q := t.ttlQueues[ttl]
	if len(q) == 0 {
		return 0, false
	}
	head := q[0]
	if head.srcPort != srcPort {
		return 0, false
	}
	t.ttlQueues[ttl] = q[1:]
	return head.i, true
}

func (t *UDPTracer) enqueueTTLPort(ttl, i, srcPort int) {
	ap := attemptPort{srcPort: srcPort, i: i}
	t.ttlQMu.Lock()
	defer t.ttlQMu.Unlock()
	t.ttlQueues[ttl] = append(t.ttlQueues[ttl], ap)
}

func (t *UDPTracer) markPending(ttl, i int) {
	key := attemptKey{ttl: ttl, i: i}
	t.pendingMu.Lock()
	defer t.pendingMu.Unlock()
	t.pending[key] = struct{}{}
}

func (t *UDPTracer) clearPending(ttl, i int) bool {
	key := attemptKey{ttl: ttl, i: i}
	t.pendingMu.Lock()
	defer t.pendingMu.Unlock()
	_, ok := t.pending[key]
	delete(t.pending, key)
	return ok
}

func (t *UDPTracer) storeSent(seq, ttl, i, srcPort int, start time.Time) {
	t.sentMu.Lock()
	defer t.sentMu.Unlock()
	if t.OSType != 1 {
		t.sentAt[seq] = sentInfo{srcPort: srcPort, start: start}
	} else {
		t.sentAt[seq] = sentInfo{ttl: ttl, i: i, srcPort: srcPort, start: start}
	}
}

func (t *UDPTracer) lookupSent(seq int) (ttl, i, srcPort int, start time.Time, ok bool) {
	t.sentMu.RLock()
	defer t.sentMu.RUnlock()
	si, ok := t.sentAt[seq]
	if !ok {
		return 0, 0, 0, time.Time{}, false
	}
	return si.ttl, si.i, si.srcPort, si.start, true
}

func (t *UDPTracer) dropSent(seq int) {
	t.sentMu.Lock()
	defer t.sentMu.Unlock()
	delete(t.sentAt, seq)
}

func (t *UDPTracer) dropByAttempt(ttl, i int) {
	t.sentMu.Lock()
	defer t.sentMu.Unlock()
	for k, si := range t.sentAt {
		if si.ttl == ttl && si.i == i {
			delete(t.sentAt, k)
			return
		}
	}
}

func (t *UDPTracer) addHopWithIndex(peer net.Addr, ttl, i int, rtt time.Duration, mpls []string, response probeResponse) {
	if f := t.final.Load(); f != -1 && ttl > int(f) {
		t.res.settleAttempt(ttl, i)
		return
	}
	h := Hop{
		Success: true,
		Address: peer,
		TTL:     ttl,
		RTT:     rtt,
		MPLS:    mpls,
	}
	t.res.addMatchedHop(h, response, &t.final, i, t.NumMeasurements, t.MaxAttempts, t.Config)
}

func (t *UDPTracer) matchWorker(ctx context.Context) {
	defer t.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-t.matchQ:
			if !ok {
				return
			}

			var (
				ttl     int
				i       int
				srcPort int
				start   time.Time
			)
			if !retryTraceProbeLookup(ctx, func() bool {
				var found bool
				ttl, i, srcPort, start, found = t.lookupSent(task.seq)
				return found
			}) {
				continue
			}

			if task.srcPort != srcPort {
				continue
			}

			if t.OSType != 1 {
				// 将 task.seq 转为 16 位无符号数
				u := uint16(task.seq)

				// 高 8 位是 TTL
				ttl = int((u >> 8) & 0xFF)

				// 低 8 位是索引 i
				i = int(u & 0xFF)
			}

			if t.clearPending(ttl, i) {
				rtt := task.finish.Sub(start)
				t.addHopWithIndex(task.peer, ttl, i, rtt, task.mpls, task.response)
			}
			t.dropSent(task.seq)
		}
	}
}

func (t *UDPTracer) Execute() (res *Result, err error) {
	// 初始化 ttlQueues、pending、sentAt 和 matchQ
	t.ttlQueues = make(map[int][]attemptPort)
	t.pending = make(map[attemptKey]struct{})
	t.sentAt = make(map[int]sentInfo)
	t.matchQ = make(chan matchTask, 60)

	// 创建就绪通道
	t.readyOut = make(chan struct{})
	t.readyICMP = make(chan struct{})

	if len(t.res.Hops) > 0 {
		return &t.res, errTracerouteExecuted
	}

	// 初始化 res.Hops 和 res.tailDone，并预分配到 MaxHops
	t.res.Hops = make([][]Hop, t.MaxHops)
	t.res.tailDone = make([]bool, t.MaxHops)
	t.res.setGeoWait(t.NumMeasurements)

	// 解析并校验用户指定的 IPv4 源地址
	SrcAddr := net.ParseIP(t.SrcAddr).To4()
	if t.SrcAddr != "" && SrcAddr == nil {
		return nil, errors.New("invalid IPv4 SrcAddr:" + t.SrcAddr)
	}
	t.SrcIP, _ = util.LocalIPPort(t.DstIP, SrcAddr, "udp")
	if t.SrcIP == nil {
		return nil, errors.New("cannot determine local IPv4 address")
	}

	s := internal.NewUDPSpec(
		4,
		t.ICMPMode,
		t.SrcIP,
		t.DstIP,
		t.DstPort,
	)
	s.SourceDevice = t.SourceDevice

	closeSpec := sync.OnceFunc(s.Close)
	defer closeSpec()
	if err := s.InitICMP(); err != nil {
		return nil, wrapProbeSetupError(err)
	}
	if err := s.InitUDP(); err != nil {
		return nil, wrapProbeSetupError(err)
	}

	sigCtx, stop := traceSignalContext(t.Context)
	ctx, cancel := context.WithCancelCause(sigCtx)
	defer stop()
	defer cancel(nil)
	t.final.Store(-1)

	workerN := 16
	for i := 0; i < workerN; i++ {
		t.wg.Add(1)
		go t.matchWorker(ctx)
	}
	if t.OSType == 1 {
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			if err := s.ListenOut(ctx, t.readyOut, func(srcPort, seq, ttl int, start time.Time) {
				// 严格按队列头端口匹配；不匹配就丢弃，避免混入其它进程/杂包
				i, ok := t.tryMatchTTLPort(ttl, srcPort)
				if !ok {
					return
				}
				t.storeSent(seq, ttl, i, srcPort, start)
			}); err != nil {
				cancel(wrapProbeSetupError(err))
			}
		}()
	} else {
		close(t.readyOut)
	}
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		if err := s.ListenICMP(ctx, t.readyICMP, func(msg internal.ReceivedMessage, finish time.Time, data []byte) {
			t.handleICMPMessage(msg, finish, data)
		},
		); err != nil {
			cancel(wrapProbeSetupError(err))
		}
	}()
	if err := t.waitAllReady(ctx); err != nil {
		cancel(err)
		closeSpec()
		t.wg.Wait()
		return &t.res, err
	}
	t.wg.Add(1)
	go t.PrintFunc(ctx, cancel)

	t.sem = semaphore.NewWeighted(int64(t.ParallelRequests))

	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		// 立即启动 BeginHop 对应的 TTL 组
		t.launchTTL(ctx, s, t.BeginHop)

		for ttl := t.BeginHop + 1; ttl <= t.MaxHops; ttl++ {
			// 之后按 TTLInterval 周期启动后续 TTL 组
			if !waitForTraceDelay(ctx, time.Millisecond*time.Duration(t.TTLInterval)) {
				return
			}

			// 如果到达最终跳，则退出
			if f := t.final.Load(); f != -1 && ttl > int(f) {
				t.res.markTTLLaunchDone(ttl)
				return
			}

			// 并发启动这个 TTL 的所有测量
			t.launchTTL(ctx, s, ttl)
		}
	}()

	<-ctx.Done()
	stop()
	t.wg.Wait()

	final := int(t.final.Load())
	if final == -1 {
		final = t.MaxHops
	}
	t.res.reduce(final)

	if cause := context.Cause(ctx); !errors.Is(cause, errNaturalDone) {
		return &t.res, cause
	}
	return &t.res, nil
}

func (t *UDPTracer) handleICMPMessage(msg internal.ReceivedMessage, finish time.Time, data []byte) {
	mpls := extractMPLS(msg, t.DisableMPLS)

	seq, err := util.GetUDPSeq(data)
	if err != nil {
		return
	}

	header, err := util.GetICMPResponsePayload(data)
	if err != nil {
		return
	}

	srcPort, dstPort, err := util.GetUDPPorts(header)
	if err != nil {
		return
	}

	if dstPort != t.DstPort {
		return
	}

	// 非阻塞投递；如果队列已满则直接丢弃该任务
	select {
	case t.matchQ <- matchTask{
		srcPort: srcPort, seq: seq, peer: msg.Peer, finish: finish, mpls: mpls, response: probeResponseFromICMPForMethod(msg.ICMP, UDPTrace),
	}:
	default:
		// 丢弃以避免阻塞抓包循环
	}
}

func randomPayload(size int, offset int) []byte {
	payload := make([]byte, size)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := offset; i < size; i++ {
		payload[i] = byte(r.Intn(256))
	}
	return payload
}

func (t *UDPTracer) acquireSendPermit(ctx context.Context, ttl, i int) (func(), bool, error) {
	if t.ttlComp(ttl) {
		t.res.settleAttemptAndCommit(ctx, ttl, i, t.NumMeasurements, &t.final)
		return nil, true, nil
	}
	if err := acquireTraceSemaphore(ctx, t.sem); err != nil {
		return nil, false, err
	}
	release := func() { t.sem.Release(1) }
	if f := t.final.Load(); f != -1 && ttl > int(f) {
		release()
		t.res.settleAttempt(ttl, i)
		return nil, true, nil
	}
	if t.ttlComp(ttl) {
		release()
		t.res.settleAttemptAndCommit(ctx, ttl, i, t.NumMeasurements, &t.final)
		return nil, true, nil
	}
	return release, false, nil
}

func (t *UDPTracer) resolveSourcePort() int {
	if !util.RandomPortEnabled() && t.SrcPort > 0 {
		return t.SrcPort
	}
	_, srcPort := util.LocalIPPort(t.DstIP, t.SrcIP, "udp")
	return srcPort
}

func (t *UDPTracer) buildUDPPacket(ttl, i, srcPort int) (int, *layers.IPv4, *layers.UDP, []byte) {
	seq := (ttl << 8) | (i & 0xFF)
	payloadSize := resolveProbePayloadSize(UDPTrace, t.DstIP, t.PktSize, t.RandomPacketSize)
	ipHeader := &layers.IPv4{
		Version:  4,
		Id:       uint16(seq),
		SrcIP:    t.SrcIP,
		DstIP:    t.DstIP,
		Protocol: layers.IPProtocolUDP,
		TTL:      uint8(ttl),
		TOS:      uint8(t.TOS),
	}
	udpHeader := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(t.DstPort),
	}
	return seq, ipHeader, udpHeader, randomPayload(payloadSize, 0)
}

func (t *UDPTracer) startSendTimeout(ctx context.Context, ttl, i, seq int) {
	t.markPending(ttl, i)
	t.wg.Add(1)
	go func(seq, ttl, i int) {
		defer t.wg.Done()
		if !waitForTraceDelay(ctx, t.Timeout) {
			_ = t.clearPending(ttl, i)
			t.res.settleAttempt(ttl, i)
			return
		}
		if !t.clearPending(ttl, i) {
			return
		}

		h := Hop{
			Success: false,
			Address: nil,
			TTL:     ttl,
			RTT:     0,
			Error:   errHopLimitTimeout,
		}
		t.res.addTimeout(h, &t.final, i, t.NumMeasurements, t.MaxAttempts)
		if t.OSType != 1 {
			t.dropSent(seq)
			return
		}
		t.dropByAttempt(ttl, i)
	}(seq, ttl, i)
}

func (t *UDPTracer) prepareDarwinSend(ttl, i, srcPort int) {
	if t.OSType == 1 {
		t.enqueueTTLPort(ttl, i, srcPort)
	}
}

func (t *UDPTracer) finalizeSent(seq, srcPort int, start time.Time) {
	if t.OSType != 1 {
		t.storeSent(seq, 0, 0, srcPort, start)
	}
}

func (t *UDPTracer) send(ctx context.Context, s *internal.UDPSpec, ttl, i int) error {
	release, skip, err := t.acquireSendPermit(ctx, ttl, i)
	if err != nil {
		return err
	}
	if skip {
		return nil
	}
	defer release()

	srcPort := t.resolveSourcePort()
	seq, ipHeader, udpHeader, payload := t.buildUDPPacket(ttl, i, srcPort)
	t.prepareDarwinSend(ttl, i, srcPort)
	t.startSendTimeout(ctx, ttl, i, seq)
	start, err := s.SendUDP(ctx, ipHeader, udpHeader, payload)
	if err != nil {
		_ = t.clearPending(ttl, i)
		return err
	}
	t.finalizeSent(seq, srcPort, start)
	return nil
}
