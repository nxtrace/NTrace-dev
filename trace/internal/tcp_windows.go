//go:build windows && amd64

package internal

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	wd "github.com/xjasonlyu/windivert-go"
)

type TCPSpec struct {
	IPVersion    int
	ICMPMode     int
	SrcIP        net.IP
	DstIP        net.IP
	DstPort      int
	icmp         net.PacketConn
	PktSize      int
	SourceDevice string
	addr         wd.Address
	handle       wd.Handle
}

func (s *TCPSpec) sourceDeviceUnsupportedErr() error {
	if s.SourceDevice == "" {
		return nil
	}
	return fmt.Errorf("source_device %q is not supported on Windows TCP traces", s.SourceDevice)
}

func (s *TCPSpec) InitTCP() error {
	if err := s.sourceDeviceUnsupportedErr(); err != nil {
		return err
	}

	handle, err := OpenWinDivertHandle("false", 0)
	if err != nil {
		return fmt.Errorf("%s: %w", formatWinDivertRequiredError("Windows TCP 探测", err), err)
	}
	s.handle = handle

	// 设置出站 Address
	s.addr.SetLayer(wd.LayerNetwork)
	s.addr.SetEvent(wd.EventNetworkPacket)
	s.addr.SetOutbound()
	return nil
}

func (s *TCPSpec) Close() {
	if s.icmp != nil {
		_ = s.icmp.Close()
	}
	if s.handle != 0 {
		_ = s.handle.Close()
	}
}

// resolveICMPMode 进行最终模式判定
func (s *TCPSpec) resolveICMPMode() int {
	icmpMode := s.ICMPMode
	if icmpMode != 1 && icmpMode != 2 {
		icmpMode = 0 // 统一成 Auto
	}

	// 指定 1=Socket：直接返回
	if icmpMode == 1 {
		return 1
	}

	// Auto(0) 或强制 Sniff(2) → 尝试 WinDivert
	ok, err := detectWinDivertAvailability()
	if !ok {
		if icmpMode == 2 {
			log.Printf("%s", formatWinDivertFallbackMessage("WinDivert 嗅探模式", err))
		}
		return 1
	}
	return 2
}

func (s *TCPSpec) ListenICMP(ctx context.Context, ready chan struct{}, onICMP func(msg ReceivedMessage, finish time.Time, data []byte)) error {
	switch s.resolveICMPMode() {
	case 1:
		return s.listenICMPSock(ctx, ready, onICMP)
	case 2:
		return s.listenICMPWinDivert(ctx, ready, onICMP)
	}
	return nil
}

func (s *TCPSpec) listenICMPWinDivert(ctx context.Context, ready chan struct{}, onICMP func(msg ReceivedMessage, finish time.Time, data []byte)) error {
	if err := s.sourceDeviceUnsupportedErr(); err != nil {
		return err
	}

	sniffHandle, closeHandleICMP, err := openWinDivertSniffHandle(ctx, winDivertICMPFilter(s.IPVersion, s.SrcIP), "ListenICMP")
	if err != nil {
		return err
	}
	defer closeHandleICMP()
	close(ready)

	buf := make([]byte, 65535)
	var addr wd.Address

	for {
		raw, finish, err := receiveWinDivertPacket(ctx, sniffHandle, buf, &addr)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}

		packet, ok := decodeWinDivertICMPPacket(s.IPVersion, raw)
		if !ok {
			continue
		}
		data, ok := packet.errorPayloadFor(s.DstIP)
		if !ok {
			continue
		}
		onICMP(packet.message(), finish, data)
	}
}

func (s *TCPSpec) ListenTCP(ctx context.Context, ready chan struct{}, onTCP func(srcPort, seq, ack int, peer net.Addr, finish time.Time)) error {
	if err := s.sourceDeviceUnsupportedErr(); err != nil {
		return err
	}

	sniffHandle, closeHandleTCP, err := openWinDivertSniffHandle(
		ctx,
		winDivertTCPFilter(s.IPVersion, s.SrcIP, s.DstPort),
		"ListenTCP",
	)
	if err != nil {
		return err
	}
	defer closeHandleTCP()

	close(ready)

	buf := make([]byte, 65535)
	var addr wd.Address

	for {
		raw, finish, err := receiveWinDivertPacket(ctx, sniffHandle, buf, &addr)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}

		srcPort, seq, ack, peer, ok := decodeWinDivertTCPPacket(s.IPVersion, raw, s.DstPort)
		if !ok {
			continue
		}
		onTCP(srcPort, seq, ack, peer, finish)
	}
}

func (s *TCPSpec) SendTCP(ctx context.Context, ipHdr ipLayer, tcpHdr *layers.TCP, payload []byte) (time.Time, error) {
	if err := s.sourceDeviceUnsupportedErr(); err != nil {
		return time.Time{}, err
	}

	select {
	case <-ctx.Done():
		return time.Time{}, context.Canceled
	default:
	}

	if err := tcpHdr.SetNetworkLayerForChecksum(ipHdr); err != nil {
		return time.Time{}, fmt.Errorf("SetNetworkLayerForChecksum: %w", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// 序列化 IP 与 TCP 头以及 payload 到缓冲区
	if err := gopacket.SerializeLayers(buf, opts, ipHdr, tcpHdr, gopacket.Payload(payload)); err != nil {
		return time.Time{}, err
	}

	start := time.Now()

	// 复用预置的出站 Address
	if _, err := s.handle.Send(buf.Bytes(), &s.addr); err != nil {
		return time.Time{}, err
	}
	return start, nil
}
