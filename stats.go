package tun

import (
	"time"
)

func (br *bridge) trackStats() {
	for {
		time.Sleep(15 * time.Second)
		br.tcpConnTrackMx.Lock()
		tcpConns := len(br.tcpConnTrack)
		br.tcpConnTrackMx.Unlock()
		br.udpConnTrackMx.Lock()
		udpConns := len(br.udpConnTrack)
		br.udpConnTrackMx.Unlock()
		log.Debugf("TCP Conns: %v    UDP Conns: %v", tcpConns, udpConns)
	}
}
