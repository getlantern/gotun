package tun

import (
	"net"

	"github.com/getlantern/gotun/packet"
)

type ipPacket struct {
	ip     *packet.IPv4
	mtuBuf []byte
	wire   []byte
}

func (br *bridge) procFragment(ip *packet.IPv4, raw []byte) (bool, *packet.IPv4, []byte) {
	exist, ok := br.ipFragments[ip.Id]
	if !ok {
		if ip.Flags&0x1 == 0 {
			return false, nil, nil
		}
		// first
		dup := make([]byte, len(raw))
		copy(dup, raw)
		clone := &packet.IPv4{}
		packet.ParseIPv4(dup, clone)
		br.ipFragments[ip.Id] = &ipPacket{
			ip:   clone,
			wire: dup,
		}
		return false, clone, dup
	} else {
		exist.wire = append(exist.wire, ip.Payload...)
		packet.ParseIPv4(exist.wire, exist.ip)

		last := false
		if ip.Flags&0x1 == 0 {
			last = true
			delete(br.ipFragments, ip.Id)
		} else {
			// continue fragment
		}

		return last, exist.ip, exist.wire
	}
}

func (br *bridge) genFragments(first *packet.IPv4, offset uint16, data []byte) []*ipPacket {
	var ret []*ipPacket
	for {
		frag := packet.NewIPv4()

		frag.Version = 4
		frag.Id = first.Id
		frag.SrcIP = make(net.IP, len(first.SrcIP))
		copy(frag.SrcIP, first.SrcIP)
		frag.DstIP = make(net.IP, len(first.DstIP))
		copy(frag.DstIP, first.DstIP)
		frag.TTL = first.TTL
		frag.Protocol = first.Protocol
		frag.FragOffset = offset
		if len(data) <= br.mtu-20 {
			frag.Payload = data
		} else {
			frag.Flags = 1
			offset += uint16(br.mtu-20) / 8
			frag.Payload = data[:br.mtu-20]
			data = data[br.mtu-20:]
		}

		pkt := &ipPacket{ip: frag}
		pkt.mtuBuf = br.newBuffer()

		payloadL := len(frag.Payload)
		payloadStart := br.mtu - payloadL
		if payloadL != 0 {
			copy(pkt.mtuBuf[payloadStart:], frag.Payload)
		}
		ipHL := frag.HeaderLength()
		ipStart := payloadStart - ipHL
		frag.Serialize(pkt.mtuBuf[ipStart:payloadStart], payloadL)
		pkt.wire = pkt.mtuBuf[ipStart:]
		ret = append(ret, pkt)

		if frag.Flags == 0 {
			return ret
		}
	}
}

func (br *bridge) releaseIPPacket(pkt *ipPacket) {
	packet.ReleaseIPv4(pkt.ip)
	if pkt.mtuBuf != nil {
		br.releaseBuffer(pkt.mtuBuf)
	}
	pkt.mtuBuf = nil
	pkt.wire = nil
}
