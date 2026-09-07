//go:build windows && amd64

package internal

import (
	"errors"
	"net"
	"strings"
	"testing"

	wd "github.com/xjasonlyu/windivert-go"
	"golang.org/x/sys/windows"
)

func TestWinDivertTCPFilterAllowsAlternateRemoteSource(t *testing.T) {
	tests := []struct {
		name      string
		ipVersion int
		srcIP     net.IP
		port      int
		want      string
	}{
		{
			name:      "IPv4",
			ipVersion: 4,
			srcIP:     net.ParseIP("192.0.2.10"),
			port:      443,
			want:      "inbound and tcp and ip.DstAddr == 192.0.2.10 and tcp.SrcPort == 443",
		},
		{
			name:      "IPv6",
			ipVersion: 6,
			srcIP:     net.ParseIP("2001:db8::10"),
			port:      8443,
			want:      "inbound and tcp and ipv6.DstAddr == 2001:db8::10 and tcp.SrcPort == 8443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := winDivertTCPFilter(tt.ipVersion, tt.srcIP, tt.port); got != tt.want {
				t.Fatalf("winDivertTCPFilter() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWinDivertEchoReplyRequiresDestinationSource(t *testing.T) {
	dstIP := net.ParseIP("2001:db8::1")
	packet := &winDivertICMPPacket{
		peerIP:    dstIP,
		echoReply: true,
		echoID:    7,
		echoSeq:   11,
	}
	if seq, ok := packet.echoReplyFor(7, dstIP); !ok || seq != 11 {
		t.Fatalf("echoReplyFor() = (%d, %v), want (11, true)", seq, ok)
	}

	packet.peerIP = net.ParseIP("2001:db8::2")
	if _, ok := packet.echoReplyFor(7, dstIP); ok {
		t.Fatal("echoReplyFor() ok = true, want false for non-destination source")
	}
}

func TestWinDivertICMPErrorAllowsAlternateOuterSource(t *testing.T) {
	dstIP := net.ParseIP("192.0.2.1")
	packet := &winDivertICMPPacket{
		ipVersion: 4,
		peerIP:    net.ParseIP("198.51.100.1"),
		errorData: buildIPv4InnerPacket(dstIP, 7, 11),
	}
	data, ok := packet.errorPayloadFor(dstIP)
	if !ok {
		t.Fatal("errorPayloadFor() ok = false, want true for alternate outer source")
	}
	if seq, ok := extractEmbeddedICMPSeq(data, 7); !ok || seq != 11 {
		t.Fatalf("extractEmbeddedICMPSeq() = (%d, %v), want (11, true)", seq, ok)
	}
}

func TestOpenWinDivertSniffHandleReturnsSetupError(t *testing.T) {
	oldOpen := openWinDivertSniffCall
	t.Cleanup(func() { openWinDivertSniffCall = oldOpen })
	for _, failure := range []error{wd.Error(windows.ERROR_FILE_NOT_FOUND), errors.New("boom")} {
		openWinDivertSniffCall = func(string, uint64) (wd.Handle, error) { return 0, failure }
		handle, cleanup, err := openWinDivertSniffHandle(t.Context(), "false", "test")
		if handle != 0 || cleanup != nil || !errors.Is(err, failure) {
			t.Fatalf("open = (%v, cleanup %v, %v)", handle, cleanup != nil, err)
		}
		if !strings.Contains(err.Error(), "WinDivert") || !strings.Contains(err.Error(), `filter="false"`) {
			t.Fatalf("missing setup context: %v", err)
		}
	}
}
