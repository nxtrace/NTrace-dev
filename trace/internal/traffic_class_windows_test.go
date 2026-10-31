//go:build windows && !amd64

package internal

import (
	"net"
	"testing"

	"golang.org/x/net/ipv6"
)

func TestSetIPv6TrafficClassSkipsOnlyZeroOnWindows(t *testing.T) {
	conn, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback is unavailable: %v", err)
	}
	defer conn.Close()
	packetConn := ipv6.NewPacketConn(conn)

	if err := setIPv6TrafficClass(packetConn, 0); err != nil {
		t.Fatalf("zero Traffic Class should not require the unsupported socket option: %v", err)
	}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := setIPv6TrafficClass(packetConn, 46); err == nil {
		t.Fatal("nonzero Traffic Class unexpectedly bypassed socket setup")
	}
}
