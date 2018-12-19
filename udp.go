package tun

import (
	"context"
	"net"

	"github.com/getlantern/errors"
	"github.com/getlantern/gotun/packet"
)

type udpPacket struct {
	ip     *packet.IPv4
	udp    *packet.UDP
	mtuBuf []byte
	wire   []byte
}

func (br *bridge) onUDPPacket(ip *packet.IPv4, udp *packet.UDP) {
	connID := fourtuple{
		localIP:    ip.SrcIP.String(),
		localPort:  udp.SrcPort,
		remoteIP:   ip.DstIP.String(),
		remotePort: udp.DstPort,
	}

	br.udpConnsMx.Lock()
	conn := br.udpConns[connID]
	var err error
	if conn != nil {
		br.udpConnsMx.Unlock()
	} else {
		conn, err = br.newUDPConn(connID)
		if err != nil {
			log.Error(err)
			return
		}
	}
	_, err = conn.Write(udp.Payload)
	if err != nil {
		log.Errorf("Error writing to upstream UDP connection for %v: %v", connID, err)
	}
}

func (br *bridge) newUDPConn(connID fourtuple) (net.Conn, error) {
	remoteAddr := &net.UDPAddr{IP: parseIPv4(connID.remoteIP), Port: int(connID.remotePort)}
	conn, err := br.dialUDP(context.Background(), "udp", remoteAddr.String())
	if err != nil {
		br.udpConnsMx.Unlock()
		return nil, errors.New("Unable to dial upstream UDP connection for %v: %v", connID, err)
	}
	br.udpConns[connID] = conn
	br.udpConnsMx.Unlock()
	go func() {
		rb := make([]byte, br.mtu) // TODO: pool these
		for {
			n, _, err := conn.ReadFromUDP(rb)
			if err != nil {
				log.Errorf("Error reading from remote end of UDP connection for %v: %v", connID, err)
				br.udpConnsMx.Lock()
				delete(br.udpConns, connID)
				br.udpConnsMx.Unlock()
				return
			}
			pkt, fragments := br.responsePacket(parseIPv4(connID.localIP), parseIPv4(connID.remoteIP), connID.localPort, connID.remotePort, rb[:n])
			br.writes <- pkt
			for _, fragment := range fragments {
				br.writes <- fragment
			}
		}
	}()
	return conn, nil
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
