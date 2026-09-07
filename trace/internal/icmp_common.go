package internal

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type ipLayer interface {
	gopacket.NetworkLayer
	gopacket.SerializableLayer
}

func NewICMPSpec(IPVersion, ICMPMode, echoID int, srcIP, dstIP net.IP) *ICMPSpec {
	return &ICMPSpec{IPVersion: IPVersion, ICMPMode: ICMPMode, EchoID: echoID, SrcIP: srcIP, DstIP: dstIP}
}

func (s *ICMPSpec) InitICMP() error {
	network := "ip4:icmp"
	if s.IPVersion == 6 {
		network = "ip6:ipv6-icmp"
	}

	icmpConn, err := ListenPacket(network, s.SrcIP.String())
	if err != nil {
		return fmt.Errorf("(InitICMP) ListenPacket(%s, %s) failed: %w", network, s.SrcIP, err)
	}
	if s.SourceDevice != "" {
		if err := bindPacketConnToSourceDevice(icmpConn, s.IPVersion, s.SourceDevice); err != nil {
			_ = icmpConn.Close()
			return fmt.Errorf("(InitICMP) bind source device %q failed: %w", s.SourceDevice, err)
		}
	}
	s.icmp = icmpConn

	if s.IPVersion == 4 {
		s.icmp4 = ipv4.NewPacketConn(s.icmp)
	} else {
		s.icmp6 = ipv6.NewPacketConn(s.icmp)
	}
	return nil
}

func (s *ICMPSpec) listenICMPSock(ctx context.Context, ready chan struct{}, onICMP func(msg ReceivedMessage, finish time.Time, seq int)) error {
	lc, stop := startPacketListener(ctx, s.icmp)
	defer stop()
	close(ready)

	for {
		select {
		case <-ctx.Done():
			return nil
		case msg, ok := <-lc.Messages:
			if !ok {
				return listenerStoppedError(ctx)
			}
			if msg.Err != nil {
				return msg.Err
			}
			finish, seq, response, ok := s.decodeICMPSocketMessage(msg)
			if ok {
				msg.ICMP = response
				onICMP(msg, finish, seq)
			}
		}
	}
}

func (s *ICMPSpec) decodeICMPSocketMessage(msg ReceivedMessage) (time.Time, int, ICMPResponse, bool) {
	if msg.Err != nil {
		return time.Time{}, 0, ICMPResponse{}, false
	}

	finish := time.Now()
	rm, ok := parseSocketICMPMessage(s.IPVersion, msg.Msg)
	if !ok {
		return finish, 0, ICMPResponse{}, false
	}
	response := classifySocketICMPResponse(s.IPVersion, rm, msg.Msg)

	if seq, ok := matchSocketICMPEchoReply(s.IPVersion, rm, s.EchoID, msg.Peer, s.DstIP); ok {
		return finish, seq, response, true
	}

	data, ok := extractSocketICMPPayload(s.IPVersion, rm, s.DstIP)
	if !ok {
		return finish, 0, ICMPResponse{}, false
	}

	seq, ok := extractEmbeddedICMPSeq(data, s.EchoID)
	return finish, seq, response, ok
}
