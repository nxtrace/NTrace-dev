package internal

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type failingListenerConn struct {
	net.PacketConn
	err    error
	closed atomic.Int32
}

func (c *failingListenerConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, c.err }
func (c *failingListenerConn) Close() error                           { c.closed.Add(1); return nil }

func TestSocketListenerReturnsReadErrorAndJoins(t *testing.T) {
	cause := errors.New("socket read failed")
	for _, proto := range []string{"icmp", "tcp", "udp"} {
		t.Run(proto, func(t *testing.T) {
			conn := &failingListenerConn{err: cause}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			ready := make(chan struct{})
			var err error
			switch proto {
			case "icmp":
				spec := &ICMPSpec{icmp: conn}
				err = spec.listenICMPSock(ctx, ready, nil)
				spec.Close()
			case "tcp":
				spec := &TCPSpec{icmp: conn}
				err = spec.listenICMPSock(ctx, ready, nil)
				spec.Close() // Sending socket/handle was never initialized.
			case "udp":
				spec := &UDPSpec{icmp: conn}
				err = spec.listenICMPSock(ctx, ready, nil)
				spec.Close()
			}
			if !errors.Is(err, cause) || ctx.Err() != nil || conn.closed.Load() == 0 {
				t.Fatalf("error=%v ctx=%v closes=%d", err, ctx.Err(), conn.closed.Load())
			}
		})
	}
}

func TestUninitializedSpecsCloseSafely(t *testing.T) {
	(&ICMPSpec{}).Close()
	(&TCPSpec{}).Close()
	(&UDPSpec{}).Close()
}
