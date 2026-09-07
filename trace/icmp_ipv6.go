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

type ICMPTracerv6 struct {
	Config
	wg        sync.WaitGroup
	res       Result
	echoID    int
	pending   map[int]struct{}
	pendingMu sync.Mutex
	sentAt    map[int]time.Time
	sentMu    sync.RWMutex
	SrcIP     net.IP
	final     atomic.Int32
	sem       *semaphore.Weighted
	matchQ    chan matchTask
	readyICMP chan struct{}
}

func (t *ICMPTracerv6) waitAllReady(ctx context.Context) error {
	return waitProbeListeners(ctx, t.readyICMP)
}

func (t *ICMPTracerv6) ttlComp(ttl int) bool {
	return t.res.ttlDisplayComplete(ttl, t.NumMeasurements)
}

func (t *ICMPTracerv6) PrintFunc(ctx context.Context, cancel context.CancelCauseFunc) {
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

func (t *ICMPTracerv6) launchTTL(ctx context.Context, s *internal.ICMPSpec, ttl int) {
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

func (t *ICMPTracerv6) initEchoID() {
	// 设置随机种子
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	// 生成一个 8 位的随机 tag
	echoIDTag := r.Intn(256)

	// 获取当前进程的 pid
	pid := os.Getpid()

	// 将随机 tag 编码到高 8 位；将 pid 的低 8 位编码到低 8 位
	t.echoID = (echoIDTag << 8) | (pid & 0xFF)
}

func (t *ICMPTracerv6) markPending(seq int) {
	t.pendingMu.Lock()
	defer t.pendingMu.Unlock()
	t.pending[seq] = struct{}{}
}

func (t *ICMPTracerv6) clearPending(seq int) bool {
	t.pendingMu.Lock()
	defer t.pendingMu.Unlock()
	_, ok := t.pending[seq]
	delete(t.pending, seq)
	return ok
}

func (t *ICMPTracerv6) storeSent(seq int, start time.Time) {
	t.sentMu.Lock()
	defer t.sentMu.Unlock()
	t.sentAt[seq] = start
}

func (t *ICMPTracerv6) lookupSent(seq int) (start time.Time, ok bool) {
	t.sentMu.RLock()
	defer t.sentMu.RUnlock()
	start, ok = t.sentAt[seq]
	if !ok {
		return time.Time{}, false
	}
	return start, true
}

func (t *ICMPTracerv6) dropSent(seq int) {
	t.sentMu.Lock()
	defer t.sentMu.Unlock()
	delete(t.sentAt, seq)
}

func (t *ICMPTracerv6) addHopWithIndex(peer net.Addr, ttl, i int, rtt time.Duration, mpls []string, response probeResponse) {
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

func (t *ICMPTracerv6) matchWorker(ctx context.Context) {
	defer t.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-t.matchQ:
			if !ok {
				return
			}

			var start time.Time
			if !retryTraceProbeLookup(ctx, func() bool {
				var found bool
				start, found = t.lookupSent(task.seq)
				return found
			}) {
				continue
			}

			// 将 task.seq 转为 16 位无符号数
			u := uint16(task.seq)

			// 高 8 位是 TTL
			ttl := int((u >> 8) & 0xFF)

			// 低 8 位是索引 i
			i := int(u & 0xFF)

			if t.clearPending(task.seq) {
				rtt := task.finish.Sub(start)
				t.addHopWithIndex(task.peer, ttl, i, rtt, task.mpls, task.response)
			}
			t.dropSent(task.seq)
		}
	}
}

func (t *ICMPTracerv6) Execute() (res *Result, err error) {
	// 初始化 Echo.ID
	t.initEchoID()

	// 初始化 pending、sentAt 和 matchQ
	t.pending = make(map[int]struct{})
	t.sentAt = make(map[int]time.Time)
	t.matchQ = make(chan matchTask, 60)

	// 创建就绪通道
	t.readyICMP = make(chan struct{})

	if len(t.res.Hops) > 0 {
		return &t.res, errTracerouteExecuted
	}

	// 初始化 res.Hops 和 res.tailDone，并预分配到 MaxHops
	t.res.Hops = make([][]Hop, t.MaxHops)
	t.res.tailDone = make([]bool, t.MaxHops)
	t.res.setGeoWait(t.NumMeasurements)

	// 解析并校验用户指定的 IPv6 源地址
	SrcAddr := net.ParseIP(t.SrcAddr)
	if t.SrcAddr != "" && !util.IsIPv6(SrcAddr) {
		return nil, errors.New("invalid IPv6 SrcAddr: " + t.SrcAddr)
	}
	t.SrcIP, _ = util.LocalIPPortv6(t.DstIP, SrcAddr, "icmp6")
	if t.SrcIP == nil {
		return nil, errors.New("cannot determine local IPv6 address")
	}

	s := internal.NewICMPSpec(
		6,
		t.ICMPMode,
		t.echoID,
		t.SrcIP,
		t.DstIP,
	)
	applyICMPSourceDevice(s, t.OSType, t.SourceDevice)

	closeSpec := sync.OnceFunc(s.Close)
	defer closeSpec()
	if err := s.InitICMP(); err != nil {
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
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		if err := s.ListenICMP(ctx, t.readyICMP, func(msg internal.ReceivedMessage, finish time.Time, seq int) {
			t.handleICMPMessage(msg, finish, seq)
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

func (t *ICMPTracerv6) handleICMPMessage(msg internal.ReceivedMessage, finish time.Time, seq int) {
	mpls := extractMPLS(msg, t.DisableMPLS)

	// 非阻塞投递；如果队列已满则直接丢弃该任务
	select {
	case t.matchQ <- matchTask{
		seq: seq, peer: msg.Peer, finish: finish, mpls: mpls, response: probeResponseFromICMP(msg.ICMP),
	}:
	default:
		// 丢弃以避免阻塞抓包循环
	}
}

func (t *ICMPTracerv6) send(ctx context.Context, s *internal.ICMPSpec, ttl, i int) error {
	if t.ttlComp(ttl) {
		// 快路径短路：若该 TTL 已完成，直接返回避免竞争信号量与无谓发包
		t.res.settleAttemptAndCommit(ctx, ttl, i, t.NumMeasurements, &t.final)
		return nil
	}

	if err := acquireTraceSemaphore(ctx, t.sem); err != nil {
		return err
	}
	defer t.sem.Release(1)

	if f := t.final.Load(); f != -1 && ttl > int(f) {
		t.res.settleAttempt(ttl, i)
		return nil
	}

	if t.ttlComp(ttl) {
		// 竞态兜底：获取信号量期间可能已完成，再次检查以避免冗余发包
		t.res.settleAttemptAndCommit(ctx, ttl, i, t.NumMeasurements, &t.final)
		return nil
	}

	// 将 TTL 编码到高 8 位；将索引 i 编码到低 8 位
	seq := (ttl << 8) | (i & 0xFF)

	ipHeader := &layers.IPv6{
		Version:      6,
		SrcIP:        t.SrcIP,
		DstIP:        t.DstIP,
		NextHeader:   layers.IPProtocolICMPv6,
		HopLimit:     uint8(ttl),
		TrafficClass: uint8(t.TOS),
	}

	icmpHeader := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
	}

	icmpEcho := &layers.ICMPv6Echo{
		Identifier: uint16(t.echoID),
		SeqNumber:  uint16(seq),
	}

	desiredPayloadSize := resolveProbePayloadSize(ICMPTrace, t.DstIP, t.PktSize, t.RandomPacketSize)
	payload := make([]byte, desiredPayloadSize)

	if desiredPayloadSize >= 3 {
		copy(payload[desiredPayloadSize-3:], []byte{'n', 't', 'r'}) // "ntr" 作为标识
	}

	// 登记 pending，并启动超时守护
	t.markPending(seq)
	t.wg.Add(1)
	go func(seq, ttl, i int) {
		defer t.wg.Done()
		if !waitForTraceDelay(ctx, t.Timeout) {
			_ = t.clearPending(seq)
			t.res.settleAttempt(ttl, i)
			return
		}
		if !t.clearPending(seq) {
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
		t.dropSent(seq)
	}(seq, ttl, i)

	start, err := s.SendICMP(ctx, ipHeader, icmpHeader, icmpEcho, payload)
	if err != nil {
		_ = t.clearPending(seq)
		return err
	}
	t.storeSent(seq, start)
	return nil
}
