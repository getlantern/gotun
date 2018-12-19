package tun

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/getlantern/errors"
	"github.com/getlantern/gotun/packet"
	"github.com/getlantern/netx"
)

type udpPacket struct {
	ip     *packet.IPv4
	udp    *packet.UDP
	mtuBuf []byte
	wire   []byte
}

type udpConnTrack struct {
	net.Conn
	lastActivity   time.Time
	lastActivityMx sync.RWMutex
}

func (ct *udpConnTrack) Write(b []byte) (int, error) {
	n, err := ct.Conn.Write(b)
	if err == nil {
		ct.markActive()
	}
	return n, err
}

func (ct *udpConnTrack) Read(b []byte) (int, error) {
	n, err := ct.Conn.Read(b)
	if err == nil {
		ct.markActive()
	}
	return n, err
}

func (ct *udpConnTrack) markActive() {
	now := time.Now()
	ct.lastActivityMx.Lock()
	ct.lastActivity = now
	ct.lastActivityMx.Unlock()
}

func (ct *udpConnTrack) timeSinceLastActive() time.Duration {
	ct.lastActivityMx.RLock()
	lastActivity := ct.lastActivity
	ct.lastActivityMx.RUnlock()
	return time.Since(lastActivity)
}

func (br *bridge) onUDPPacket(ip *packet.IPv4, udp *packet.UDP) {
	connID := fourtuple{
		localIP:    ip.SrcIP.String(),
		localPort:  udp.SrcPort,
		remoteIP:   ip.DstIP.String(),
		remotePort: udp.DstPort,
	}

	br.udpConnTrackMx.Lock()
	ct := br.udpConnTrack[connID]
	var err error
	if ct != nil {
		br.udpConnTrackMx.Unlock()
	} else {
		ct, err = br.newUDPConn(connID)
		if err != nil {
			log.Error(err)
			return
		}
	}
	_, err = ct.Write(udp.Payload)
	if err != nil {
		log.Errorf("Error writing to upstream UDP connection for %v: %v", connID, err)
	}
}

func (br *bridge) newUDPConn(connID fourtuple) (*udpConnTrack, error) {
	remoteAddr := &net.UDPAddr{IP: parseIPv4(connID.remoteIP), Port: int(connID.remotePort)}
	conn, err := br.dialUDP(context.Background(), "udp", remoteAddr.String())
	if err != nil {
		br.udpConnTrackMx.Unlock()
		return nil, errors.New("Unable to dial upstream UDP connection for %v: %v", connID, err)
	}
	ct := &udpConnTrack{Conn: conn}
	br.udpConnTrack[connID] = ct
	br.udpConnTrackMx.Unlock()
	go func() {
		rb := br.newBuffer()
		defer br.releaseBuffer(rb)
		for {
			ct.SetDeadline(time.Now().Add(br.idleTimeout))
			n, err := ct.Read(rb)
			isIdleTimeout := err != nil && netx.IsTimeout(err)
			shouldContinue := err == nil || (isIdleTimeout && ct.timeSinceLastActive() < br.idleTimeout)
			if !shouldContinue {
				if isIdleTimeout {
					log.Debugf("UDP connection to %v idled", remoteAddr)
				} else {
					log.Errorf("Error reading from remote end of UDP connection for %v: %v", connID, err)
				}
				br.udpConnTrackMx.Lock()
				delete(br.udpConnTrack, connID)
				br.udpConnTrackMx.Unlock()
				return
			}
			if n > 0 {
				pkt, fragments := br.responsePacket(parseIPv4(connID.localIP), parseIPv4(connID.remoteIP), connID.localPort, connID.remotePort, rb[:n])
				br.writes <- pkt
				for _, fragment := range fragments {
					br.writes <- fragment
				}
			}
		}
	}()
	return ct, nil
}

func (br *bridge) responsePacket(local net.IP, remote net.IP, lPort uint16, rPort uint16, respPayload []byte) (*udpPacket, []*ipPacket) {
	ipid := packet.IPID()

	ip := packet.NewIPv4()
	udp := packet.NewUDP()

	ip.Version = 4
	ip.Id = ipid
	ip.SrcIP = make(net.IP, len(remote))
	copy(ip.SrcIP, remote)
	ip.DstIP = make(net.IP, len(local))
	copy(ip.DstIP, local)
	ip.TTL = 64
	ip.Protocol = packet.IPProtocolUDP

	udp.SrcPort = rPort
	udp.DstPort = lPort
	udp.Payload = respPayload

	pkt := br.newUDPPacket()
	pkt.ip = ip
	pkt.udp = udp

	pkt.mtuBuf = br.newBuffer()
	payloadL := len(udp.Payload)
	payloadStart := br.mtu - payloadL
	// if payload too long, need fragment, only part of payload put to mtubuf[28:]
	if payloadL > br.mtu-28 {
		ip.Flags = 1
		payloadStart = 28
	}
	udpHL := 8
	udpStart := payloadStart - udpHL
	pseduoStart := udpStart - packet.IPv4_PSEUDO_LENGTH
	ip.PseudoHeader(pkt.mtuBuf[pseduoStart:udpStart], packet.IPProtocolUDP, udpHL+payloadL)
	// udp length and checksum count on full payload
	udp.Serialize(pkt.mtuBuf[udpStart:payloadStart], pkt.mtuBuf[pseduoStart:payloadStart], udp.Payload)
	if payloadL != 0 {
		copy(pkt.mtuBuf[payloadStart:], udp.Payload)
	}
	ipHL := ip.HeaderLength()
	ipStart := udpStart - ipHL
	// ip length and checksum count on actual transmitting payload
	ip.Serialize(pkt.mtuBuf[ipStart:udpStart], udpHL+(br.mtu-payloadStart))
	pkt.wire = pkt.mtuBuf[ipStart:]

	if ip.Flags == 0 {
		return pkt, nil
	}
	// generate fragments
	frags := br.genFragments(ip, uint16(br.mtu-20)/8, respPayload[br.mtu-28:])
	return pkt, frags
}

func (br *bridge) newUDPPacket() *udpPacket {
	return br.udpPacketPool.Get().(*udpPacket)
}

func (br *bridge) releaseUDPPacket(pkt *udpPacket) {
	packet.ReleaseIPv4(pkt.ip)
	packet.ReleaseUDP(pkt.udp)
	if pkt.mtuBuf != nil {
		br.releaseBuffer(pkt.mtuBuf)
	}
	pkt.mtuBuf = nil
	pkt.wire = nil
	br.udpPacketPool.Put(pkt)
}
