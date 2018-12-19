package tun

import (
	"time"
)

func (br *bridge) trackStats() {
	ticker := time.NewTicker(15 * time.Second)
	for {
		select {
		case <-br.stopCh:
			return
		case <-ticker.C:
			br.tcpConnTrackMx.Lock()
			tcpConns := len(br.tcpConnTrack)
			br.tcpConnTrackMx.Unlock()
			br.udpConnTrackMx.Lock()
			udpConns := len(br.udpConnTrack)
			br.udpConnTrackMx.Unlock()
			log.Debugf("TCP Conns: %v    UDP Conns: %v", tcpConns, udpConns)
		}
	}
}
