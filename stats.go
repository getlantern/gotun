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
			log.Debugf("TCP Conns: %v    UDP Conns: %v", br.NumTCPConns(), br.NumUDPConns())
		}
	}
}

func (br *bridge) NumTCPConns() int {
	br.tcpConnTrackMx.Lock()
	tcpConns := len(br.tcpConnTrack)
	br.tcpConnTrackMx.Unlock()
	return tcpConns
}

func (br *bridge) NumUDPConns() int {
	br.udpConnTrackMx.Lock()
	udpConns := len(br.udpConnTrack)
	br.udpConnTrackMx.Unlock()
	return udpConns
}
