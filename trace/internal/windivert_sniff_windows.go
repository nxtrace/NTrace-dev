//go:build windows && amd64

package internal

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	wd "github.com/xjasonlyu/windivert-go"
)

type winDivertICMPPacket struct {
	ipVersion int
	peerIP    net.IP
	outer     []byte
	errorData []byte
	response  ICMPResponse
	echoID    int
	echoSeq   int
	echoReply bool
}

var openWinDivertSniffCall = OpenWinDivertHandle

func winDivertICMPFilter(ipVersion int, srcIP net.IP) string {
	if ipVersion == 4 {
		return fmt.Sprintf("inbound and icmp and ip.DstAddr == %s", srcIP.String())
	}
	return fmt.Sprintf("inbound and icmpv6 and ipv6.DstAddr == %s", srcIP.String())
}

func winDivertTCPFilter(ipVersion int, srcIP net.IP, dstPort int) string {
	if ipVersion == 4 {
		return fmt.Sprintf(
			"inbound and tcp and ip.DstAddr == %s and tcp.SrcPort == %d",
			srcIP.String(), dstPort,
		)
	}
	return fmt.Sprintf(
		"inbound and tcp and ipv6.DstAddr == %s and tcp.SrcPort == %d",
		srcIP.String(), dstPort,
	)
}

func openWinDivertSniffHandle(ctx context.Context, filter, action string) (wd.Handle, func(), error) {
	handle, err := openWinDivertSniffCall(filter, wd.FlagSniff|wd.FlagRecvOnly)
	if err != nil {
		msg := formatWinDivertRequiredError(fmt.Sprintf("Windows WinDivert 嗅探 (%s, filter=%q)", action, filter), err)
		return 0, nil, fmt.Errorf("%s: %w", msg, err)
	}

	var closeOnce sync.Once
	closeHandle := func() { closeOnce.Do(func() { _ = handle.Close() }) }
	go func() {
		<-ctx.Done()
		closeHandle()
	}()

	_ = handle.SetParam(wd.QueueLength, 8192)
	_ = handle.SetParam(wd.QueueTime, 4000)
	return handle, closeHandle, nil
}

func packetDecoderForIPVersion(ipVersion int) gopacket.Decoder {
	if ipVersion == 4 {
		return layers.LayerTypeIPv4
	}
	return layers.LayerTypeIPv6
}

func receiveWinDivertPacket(ctx context.Context, handle wd.Handle, buf []byte, addr *wd.Address) ([]byte, time.Time, error) {
	if ctx.Err() != nil {
		return nil, time.Time{}, context.Cause(ctx)
	}
	n, err := handle.Recv(buf, addr)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("WinDivert receive failed: %w", err)
	}
	finish := time.Now()
	raw := make([]byte, n)
	copy(raw, buf[:n])
	return raw, finish, nil
}

func decodeWinDivertICMPPacket(ipVersion int, raw []byte) (*winDivertICMPPacket, bool) {
	pkt := gopacket.NewPacket(raw, packetDecoderForIPVersion(ipVersion), gopacket.NoCopy)
	if ipVersion == 4 {
		return decodeWinDivertICMPv4Packet(pkt, raw)
	}
	return decodeWinDivertICMPv6Packet(pkt, raw)
}

func decodeWinDivertTCPPacket(ipVersion int, raw []byte, dstPort int) (srcPort, seq, ack int, peer net.Addr, ok bool) {
	pkt := gopacket.NewPacket(raw, packetDecoderForIPVersion(ipVersion), gopacket.NoCopy)
	return decodeTCPProbePacket(ipVersion, dstPort, pkt)
}

func decodeWinDivertICMPv4Packet(pkt gopacket.Packet, raw []byte) (*winDivertICMPPacket, bool) {
	ip4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok || ip4 == nil {
		return nil, false
	}
	ic4, ok := pkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if !ok || ic4 == nil {
		return nil, false
	}

	packet := &winDivertICMPPacket{
		ipVersion: 4,
		peerIP:    ip4.SrcIP,
		outer:     raw,
		response:  classifyICMPResponse(4, int(ic4.TypeCode.Type()), int(ic4.TypeCode.Code()), int(ic4.Seq)),
	}

	switch ic4.TypeCode.Type() {
	case layers.ICMPv4TypeEchoReply:
		packet.echoReply = true
		packet.echoID = int(ic4.Id)
		packet.echoSeq = int(ic4.Seq)
		return packet, true
	case layers.ICMPv4TypeTimeExceeded, layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4TypeParameterProblem:
		packet.errorData = ic4.Payload
		return packet, true
	default:
		return nil, false
	}
}

func decodeWinDivertICMPv6Packet(pkt gopacket.Packet, raw []byte) (*winDivertICMPPacket, bool) {
	ip6, ok := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if !ok || ip6 == nil {
		return nil, false
	}
	ic6, ok := pkt.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	if !ok || ic6 == nil || len(ic6.Payload) < 4 {
		return nil, false
	}

	packet := &winDivertICMPPacket{
		ipVersion: 6,
		peerIP:    ip6.SrcIP,
		outer:     raw,
		response:  classifyICMPResponse(6, int(ic6.TypeCode.Type()), int(ic6.TypeCode.Code()), 0),
	}

	switch ic6.TypeCode.Type() {
	case layers.ICMPv6TypeEchoReply:
		echo, ok := pkt.Layer(layers.LayerTypeICMPv6Echo).(*layers.ICMPv6Echo)
		if !ok || echo == nil {
			return nil, false
		}
		packet.echoReply = true
		packet.echoID = int(echo.Identifier)
		packet.echoSeq = int(echo.SeqNumber)
		return packet, true
	case layers.ICMPv6TypeTimeExceeded, layers.ICMPv6TypePacketTooBig, layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv6TypeParameterProblem:
		if ic6.TypeCode.Type() == layers.ICMPv6TypePacketTooBig {
			packet.response = classifyICMPResponse(6, int(ic6.TypeCode.Type()), int(ic6.TypeCode.Code()), int(binary.BigEndian.Uint32(ic6.Payload[:4])))
		}
		packet.errorData = ic6.Payload[4:]
		return packet, true
	default:
		return nil, false
	}
}

func (p *winDivertICMPPacket) message() ReceivedMessage {
	return ReceivedMessage{
		Peer: &net.IPAddr{IP: p.peerIP},
		Msg:  p.outer,
		ICMP: p.response,
	}
}

func (p *winDivertICMPPacket) echoReplyFor(echoID int, dstIP net.IP) (int, bool) {
	if !p.echoReply || p.echoID != echoID || !p.peerIP.Equal(dstIP) {
		return 0, false
	}
	return p.echoSeq, true
}

func (p *winDivertICMPPacket) errorPayloadFor(dstIP net.IP) ([]byte, bool) {
	if p.echoReply || !matchesEmbeddedDstIP(p.ipVersion, p.errorData, dstIP) {
		return nil, false
	}
	return p.errorData, true
}
