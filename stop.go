package tun

import (
	"bytes"
	"errors"
	"net"
)

var (
	stopMarker = []byte{2, 2, 2, 2, 2, 2, 2, 2}

	errStopMarkerReceived = errors.New("received stop marker")
	errAlreadyClosed      = errors.New("already closed")
)

// Close of Windows and Linux tun/tap device do not interrupt blocking Read.
// sendStopMarker is used to issue a specific packet to notify threads blocking
// on Read.
func sendStopMarker(src, dst string) {
	l, _ := net.ResolveUDPAddr("udp", src+":2222")
	r, _ := net.ResolveUDPAddr("udp", dst+":2222")
	conn, err := net.DialUDP("udp", l, r)
	if err != nil {
		log.Errorf("failed to send stopmarker: %v", err)
		return
	}
	defer conn.Close()
	conn.Write(stopMarker)
}

func isStopMarker(pkt []byte, src, dst net.IP) bool {
	n := len(pkt)
	// at least should be 20(ip) + 8(udp) + 8(stopmarker)
	if n < 20+8+8 {
		return false
	}
	return pkt[0]&0xf0 == 0x40 && pkt[9] == 0x11 && src.Equal(pkt[12:16]) &&
		dst.Equal(pkt[16:20]) && bytes.Compare(pkt[n-8:n], stopMarker) == 0
}
