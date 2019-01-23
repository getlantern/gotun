package tun

import (
	"sync/atomic"
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
			log.Debugf("Accepted Packets: %d    Rejected Packets: %d", br.AcceptedPackets(), br.RejectedPackets())
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

func (br *bridge) acceptedPacket() {
	atomic.AddInt64(&br.acceptedPackets, 1)
}

func (br *bridge) AcceptedPackets() int {
	return int(atomic.LoadInt64(&br.acceptedPackets))
}

func (br *bridge) rejectedPacket() {
	atomic.AddInt64(&br.rejectedPackets, 1)
}

func (br *bridge) RejectedPackets() int {
	return int(atomic.LoadInt64(&br.rejectedPackets))
}
