package internal

import (
	"context"
	"errors"
	"net"
	"time"
)

type ReceivedMessage struct {
	Peer net.Addr
	Msg  []byte
	Err  error
	ICMP ICMPResponse
}

// PacketListener 负责监听网络数据包并通过通道传递接收到的消息
// 对外暴露只读的 Messages，避免外部代码误写
type PacketListener struct {
	Conn     net.PacketConn
	Messages <-chan ReceivedMessage
	ch       chan ReceivedMessage
}

// NewPacketListener 创建一个新的数据包监听器
// conn: 用于接收数据包的连接
// 返回初始化好的 PacketListener 实例
func NewPacketListener(conn net.PacketConn) *PacketListener {
	ch := make(chan ReceivedMessage, 64)

	return &PacketListener{Conn: conn, Messages: ch, ch: ch}
}

func startPacketListener(parent context.Context, conn net.PacketConn) (*PacketListener, func()) {
	ctx, cancel := context.WithCancel(parent)
	l := NewPacketListener(conn)
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.Start(ctx)
	}()
	return l, func() { cancel(); <-done }
}

func listenerStoppedError(ctx context.Context) error {
	if ctx.Err() != nil {
		return nil
	}
	return errors.New("probe listener stopped unexpectedly")
}

func (l *PacketListener) Start(ctx context.Context) {
	defer close(l.ch)

	stopCloser, closerDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(closerDone)
		select {
		case <-ctx.Done():
			_ = l.Conn.Close()
		case <-stopCloser:
		}
	}()
	defer func() { close(stopCloser); <-closerDone }()

	buf := make([]byte, 4096)

	for {
		n, peer, err := l.Conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				continue
			}

			// 限时等待投递错误；超时或取消就丢弃/退出
			select {
			case l.ch <- ReceivedMessage{Err: err}:
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			return
		}
		if n == 0 {
			continue
		}

		// 拷贝出精确长度，避免 buf 复用带来的数据竞争
		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		// 限时等待投递数据；超时或取消就丢弃/退出
		select {
		case l.ch <- ReceivedMessage{Peer: peer, Msg: pkt}:
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}
