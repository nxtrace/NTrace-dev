//go:build windows && amd64

package internal

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/nxtrace/NTrace-core/util"
	wd "github.com/xjasonlyu/windivert-go"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var hasWindowsAdminPrivileges = util.HasAdminPrivileges
var detectWinDivertAvailability = winDivertAvailable

type ICMPSpec struct {
	IPVersion    int
	ICMPMode     int
	EchoID       int
	SrcIP        net.IP
	DstIP        net.IP
	SourceDevice string
	icmp         net.PacketConn
	icmp4        *ipv4.PacketConn
	icmp6        *ipv6.PacketConn
	sendHandle   wd.Handle
	closed       bool // protected by hopLimitLock, including lazy send-handle initialization
	sendAddr     wd.Address
	hopLimitLock sync.Mutex
}

func ListenPacket(network string, laddr string) (net.PacketConn, error) {
	return net.ListenPacket(network, laddr)
}

func (s *ICMPSpec) Close() {
	s.hopLimitLock.Lock()
	defer s.hopLimitLock.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	if s.icmp != nil {
		_ = s.icmp.Close()
	}
	if s.sendHandle != 0 {
		_ = s.sendHandle.Close()
	}
}

// winDivertAvailable 通过尝试打开一个 WinDivert 嗅探 handle 来判断 WinDivert 是否可用
func winDivertAvailable() (bool, error) {
	h, err := OpenWinDivertHandle("false", wd.FlagSniff|wd.FlagRecvOnly)
	if err != nil {
		return false, err
	}
	_ = h.Close()
	return true, nil
}

// resolveICMPMode 进行最终模式判定
// 1=Socket, 2=WinDivert (嗅探模式，原 PCAP 模式的替代)
func (s *ICMPSpec) resolveICMPMode() int {
	icmpMode := s.ICMPMode
	if icmpMode != 1 && icmpMode != 2 {
		icmpMode = 0 // 统一成 Auto
	}

	// 指定 1=Socket：直接返回
	if icmpMode == 1 {
		return 1
	}

	// Auto(0) 或强制 Sniff(2) → 尝试 WinDivert
	if !hasWindowsAdminPrivileges() {
		if icmpMode == 2 {
			log.Printf("请求使用 WinDivert 嗅探模式，但当前缺少管理员权限；已回退到 Socket 模式。")
		}
		return 1
	}

	ok, err := detectWinDivertAvailability()
	if !ok {
		if icmpMode == 2 {
			log.Printf("%s", formatWinDivertFallbackMessage("WinDivert 嗅探模式", err))
		}
		return 1
	}
	return 2
}

func (s *ICMPSpec) ListenICMP(ctx context.Context, ready chan struct{}, onICMP func(msg ReceivedMessage, finish time.Time, seq int)) error {
	switch s.resolveICMPMode() {
	case 1:
		return s.listenICMPSock(ctx, ready, onICMP)
	case 2:
		return s.listenICMPWinDivert(ctx, ready, onICMP)
	}
	return nil
}

func (s *ICMPSpec) listenICMPWinDivert(ctx context.Context, ready chan struct{}, onICMP func(msg ReceivedMessage, finish time.Time, seq int)) error {
	handle, closeHandle, err := openWinDivertSniffHandle(ctx, winDivertICMPFilter(s.IPVersion, s.SrcIP), "ListenICMP")
	if err != nil {
		return err
	}
	defer closeHandle()
	close(ready)

	buf := make([]byte, 65535)
	var addr wd.Address

	for {
		raw, finish, err := receiveWinDivertPacket(ctx, handle, buf, &addr)
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

		msg := packet.message()
		if seq, ok := packet.echoReplyFor(s.EchoID, s.DstIP); ok {
			onICMP(msg, finish, seq)
			continue
		}

		data, ok := packet.errorPayloadFor(s.DstIP)
		if !ok {
			continue
		}
		if seq, ok := extractEmbeddedICMPSeq(data, s.EchoID); ok {
			onICMP(msg, finish, seq)
		}
	}
}

func (s *ICMPSpec) SendICMP(ctx context.Context, ipHdr gopacket.NetworkLayer, icmpHdr, icmpEcho gopacket.SerializableLayer, payload []byte) (time.Time, error) {
	select {
	case <-ctx.Done():
		return time.Time{}, context.Canceled
	default:
	}

	if s.IPVersion == 4 {
		ip4, ok := ipHdr.(*layers.IPv4)
		if !ok || ip4 == nil {
			return time.Time{}, errors.New("SendICMP: expect *layers.IPv4 when s.IPVersion==4")
		}
		ttl := int(ip4.TTL)

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		}

		// 序列化 ICMP 头与 payload 到缓冲区
		if err := gopacket.SerializeLayers(buf, opts, icmpHdr, gopacket.Payload(payload)); err != nil {
			return time.Time{}, err
		}

		// 串行设置 TTL + 发送，放在同一把锁里保证并发安全
		s.hopLimitLock.Lock()
		defer s.hopLimitLock.Unlock()

		if err := s.icmp4.SetTOS(int(ip4.TOS)); err != nil {
			return time.Time{}, err
		}
		if err := s.icmp4.SetTTL(ttl); err != nil {
			return time.Time{}, err
		}

		start := time.Now()

		if _, err := s.icmp.WriteTo(buf.Bytes(), &net.IPAddr{IP: s.DstIP}); err != nil {
			return time.Time{}, err
		}
		return start, nil
	}

	ip6, ok := ipHdr.(*layers.IPv6)
	if !ok || ip6 == nil {
		return time.Time{}, errors.New("SendICMP: expect *layers.IPv6 when s.IPVersion==6")
	}
	ttl := int(ip6.HopLimit)

	ic6, ok := icmpHdr.(*layers.ICMPv6)
	if !ok || ic6 == nil {
		return time.Time{}, errors.New("SendICMP: expect *layers.ICMPv6 when s.IPVersion==6")
	}

	if err := ic6.SetNetworkLayerForChecksum(ipHdr); err != nil {
		return time.Time{}, fmt.Errorf("SetNetworkLayerForChecksum: %w", err)
	}

	if shouldUseICMPv6RawSend(ip6) {
		return s.sendICMPv6WithWinDivert(ip6, icmpHdr, icmpEcho, payload)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// Socket path only needs the ICMPv6 payload; the kernel prepends the IPv6 header.
	if err := gopacket.SerializeLayers(buf, opts, icmpHdr, icmpEcho, gopacket.Payload(payload)); err != nil {
		return time.Time{}, err
	}

	// 串行设置 HopLimit + 发送，放在同一把锁里保证并发安全
	s.hopLimitLock.Lock()
	defer s.hopLimitLock.Unlock()

	if err := s.icmp6.SetHopLimit(ttl); err != nil {
		return time.Time{}, err
	}

	start := time.Now()

	if _, err := s.icmp.WriteTo(buf.Bytes(), &net.IPAddr{IP: s.DstIP}); err != nil {
		return time.Time{}, err
	}
	return start, nil
}

func shouldUseICMPv4RawSend(ip4 *layers.IPv4) bool {
	return false
}

func shouldUseICMPv6RawSend(ip6 *layers.IPv6) bool {
	return ip6 != nil && ip6.TrafficClass != 0
}

func (s *ICMPSpec) sendICMPv6WithWinDivert(ip6 *layers.IPv6, icmpHdr, icmpEcho gopacket.SerializableLayer, payload []byte) (time.Time, error) {
	s.hopLimitLock.Lock()
	defer s.hopLimitLock.Unlock()
	if s.closed {
		return time.Time{}, net.ErrClosed
	}

	if err := s.ensureICMPSendHandle(true); err != nil {
		return time.Time{}, &InitializationError{Err: err}
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, ip6, icmpHdr, icmpEcho, gopacket.Payload(payload)); err != nil {
		return time.Time{}, err
	}

	start := time.Now()
	if _, err := s.sendHandle.Send(buf.Bytes(), &s.sendAddr); err != nil {
		return time.Time{}, err
	}
	return start, nil
}

func (s *ICMPSpec) ensureICMPSendHandle(ipv6 bool) error {
	if s.sendHandle != 0 {
		return nil
	}

	handle, err := OpenWinDivertHandle("false", 0)
	if err != nil {
		if ipv6 {
			return fmt.Errorf("%s: %w", formatWinDivertRequiredError("Windows ICMPv6 --tos", err), err)
		}
		return fmt.Errorf("%s: %w", formatWinDivertRequiredError("Windows ICMPv4 --tos", err), err)
	}

	s.sendHandle = handle
	s.sendAddr.SetLayer(wd.LayerNetwork)
	s.sendAddr.SetEvent(wd.EventNetworkPacket)
	s.sendAddr.SetOutbound()
	if ipv6 {
		s.sendAddr.SetIPv6()
	}
	return nil
}
