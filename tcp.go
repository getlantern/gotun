package tun

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getlantern/gotun/packet"
)

type tcpPacket struct {
	ip     *packet.IPv4
	tcp    *packet.TCP
	mtuBuf []byte
	wire   []byte
}

type tcpState byte

const (
	// simplified server-side tcp states
	CLOSED      tcpState = 0x0
	SYN_RCVD    tcpState = 0x1
	ESTABLISHED tcpState = 0x2
	FIN_WAIT_1  tcpState = 0x3
	FIN_WAIT_2  tcpState = 0x4
	CLOSING     tcpState = 0x5
	LAST_ACK    tcpState = 0x6
	TIME_WAIT   tcpState = 0x7

	MAX_RECV_WINDOW int = 65535
	MAX_SEND_WINDOW int = 65535
)

type tcpConnTrack struct {
	br *bridge
	id string

	input         chan *tcpPacket
	fromRemoteCh  chan []byte
	toRemoteCh    chan *tcpPacket
	remoteCloseCh chan bool
	quitBySelf    chan bool
	quitByOther   chan bool

	remoteConn net.Conn

	// tcp context
	state tcpState
	// sequence I should use to send next segment
	// also as ack I expect in next received segment
	nxtSeq uint32
	// sequence I want in next received segment
	rcvNxtSeq uint32
	// what I have acked
	lastAck uint32

	// flow control
	recvWindow  int32
	sendWindow  int32
	sendWndCond *sync.Cond
	// recvWndCond *sync.Cond

	localIP    net.IP
	remoteIP   net.IP
	localPort  uint16
	remotePort uint16
}

var (
	tcpPacketPool *sync.Pool = &sync.Pool{
		New: func() interface{} {
			return &tcpPacket{}
		},
	}
)

func tcpflagsString(tcp *packet.TCP) string {
	s := []string{}
	if tcp.SYN {
		s = append(s, "SYN")
	}
	if tcp.RST {
		s = append(s, "RST")
	}
	if tcp.FIN {
		s = append(s, "FIN")
	}
	if tcp.ACK {
		s = append(s, "ACK")
	}
	if tcp.PSH {
		s = append(s, "PSH")
	}
	if tcp.URG {
		s = append(s, "URG")
	}
	if tcp.ECE {
		s = append(s, "ECE")
	}
	if tcp.CWR {
		s = append(s, "CWR")
	}
	return strings.Join(s, ",")
}

func tcpstateString(state tcpState) string {
	switch state {
	case CLOSED:
		return "CLOSED"
	case SYN_RCVD:
		return "SYN_RCVD"
	case ESTABLISHED:
		return "ESTABLISHED"
	case FIN_WAIT_1:
		return "FIN_WAIT_1"
	case FIN_WAIT_2:
		return "FIN_WAIT_2"
	case CLOSING:
		return "CLOSING"
	case LAST_ACK:
		return "LAST_ACK"
	case TIME_WAIT:
		return "TIME_WAIT"
	}
	return ""
}

func newTCPPacket() *tcpPacket {
	return tcpPacketPool.Get().(*tcpPacket)
}

func (br *bridge) releaseTCPPacket(pkt *tcpPacket) {
	packet.ReleaseIPv4(pkt.ip)
	packet.ReleaseTCP(pkt.tcp)
	if pkt.mtuBuf != nil {
		br.releaseBuffer(pkt.mtuBuf)
	}
	pkt.mtuBuf = nil
	pkt.wire = nil
	tcpPacketPool.Put(pkt)
}

func (br *bridge) copyTCPPacket(raw []byte, ip *packet.IPv4, tcp *packet.TCP) *tcpPacket {
	iphdr := packet.NewIPv4()
	tcphdr := packet.NewTCP()
	pkt := newTCPPacket()

	// make a deep copy
	var buf []byte
	if len(raw) <= br.mtu {
		buf = br.newBuffer()
		pkt.mtuBuf = buf
	} else {
		buf = make([]byte, len(raw))
	}
	n := copy(buf, raw)
	pkt.wire = buf[:n]
	packet.ParseIPv4(pkt.wire, iphdr)
	packet.ParseTCP(iphdr.Payload, tcphdr)
	pkt.ip = iphdr
	pkt.tcp = tcphdr

	return pkt
}

func tcpConnID(ip *packet.IPv4, tcp *packet.TCP) string {
	return strings.Join([]string{
		ip.SrcIP.String(),
		fmt.Sprintf("%d", tcp.SrcPort),
		ip.DstIP.String(),
		fmt.Sprintf("%d", tcp.DstPort),
	}, "|")
}

func (br *bridge) packTCP(ip *packet.IPv4, tcp *packet.TCP) *tcpPacket {
	pkt := newTCPPacket()
	pkt.ip = ip
	pkt.tcp = tcp

	buf := br.newBuffer()
	pkt.mtuBuf = buf

	payloadL := len(tcp.Payload)
	payloadStart := br.mtu - payloadL
	if payloadL != 0 {
		copy(pkt.mtuBuf[payloadStart:], tcp.Payload)
	}
	tcpHL := tcp.HeaderLength()
	tcpStart := payloadStart - tcpHL
	pseduoStart := tcpStart - packet.IPv4_PSEUDO_LENGTH
	ip.PseudoHeader(pkt.mtuBuf[pseduoStart:tcpStart], packet.IPProtocolTCP, tcpHL+payloadL)
	tcp.Serialize(pkt.mtuBuf[tcpStart:payloadStart], pkt.mtuBuf[pseduoStart:])
	ipHL := ip.HeaderLength()
	ipStart := tcpStart - ipHL
	ip.Serialize(pkt.mtuBuf[ipStart:tcpStart], tcpHL+payloadL)
	pkt.wire = pkt.mtuBuf[ipStart:]
	return pkt
}

func (br *bridge) rst(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16, seq uint32, ack uint32, payloadLen uint32) *tcpPacket {
	iphdr := packet.NewIPv4()
	tcphdr := packet.NewTCP()

	iphdr.Version = 4
	iphdr.Id = packet.IPID()
	iphdr.DstIP = srcIP
	iphdr.SrcIP = dstIP
	iphdr.TTL = 64
	iphdr.Protocol = packet.IPProtocolTCP

	tcphdr.DstPort = srcPort
	tcphdr.SrcPort = dstPort
	tcphdr.Window = uint16(MAX_RECV_WINDOW)
	tcphdr.RST = true
	tcphdr.ACK = true
	tcphdr.Seq = 0

	// RFC 793:
	// "If the incoming segment has an ACK field, the reset takes its sequence
	// number from the ACK field of the segment, otherwise the reset has
	// sequence number zero and the ACK field is set to the sum of the sequence
	// number and segment length of the incoming segment. The connection remains
	// in the CLOSED state."
	tcphdr.Ack = seq + payloadLen
	if tcphdr.Ack == seq {
		tcphdr.Ack += 1
	}
	if ack != 0 {
		tcphdr.Seq = ack
	}
	return br.packTCP(iphdr, tcphdr)
}

func (br *bridge) rstByPacket(pkt *tcpPacket) *tcpPacket {
	return br.rst(pkt.ip.SrcIP, pkt.ip.DstIP, pkt.tcp.SrcPort, pkt.tcp.DstPort, pkt.tcp.Seq, pkt.tcp.Ack, uint32(len(pkt.tcp.Payload)))
}

func (tt *tcpConnTrack) changeState(nxt tcpState) {
	// log.Debugf("### [%v -> %v]", tcpstateString(tt.state), tcpstateString(nxt))
	tt.state = nxt
}

func (tt *tcpConnTrack) validAck(pkt *tcpPacket) bool {
	ret := (pkt.tcp.Ack == tt.nxtSeq)
	if !ret {
		// log.Debugf("WARNING: invalid ack: recvd: %d, expecting: %d", pkt.tcp.Ack, tt.nxtSeq)
	}
	return ret
}

func (tt *tcpConnTrack) validSeq(pkt *tcpPacket) bool {
	ret := (pkt.tcp.Seq == tt.rcvNxtSeq)
	if !ret {
		// log.Debugf("WARNING: invalid seq: recvd: %d, expecting: %d", pkt.tcp.Seq, tt.rcvNxtSeq)
		// if (tt.rcvNxtSeq - pkt.tcp.Seq) == 1 && tt.state == ESTABLISHED {
		// 	log.Debugf("(probably a keep-alive message)")
		// }
	}
	return ret
}

func (tt *tcpConnTrack) relayPayload(pkt *tcpPacket) bool {
	payloadLen := uint32(len(pkt.tcp.Payload))
	select {
	case tt.toRemoteCh <- pkt:
		tt.rcvNxtSeq += payloadLen

		// reduce window when recved
		wnd := atomic.LoadInt32(&tt.recvWindow)
		wnd -= int32(payloadLen)
		if wnd < 0 {
			wnd = 0
		}
		atomic.StoreInt32(&tt.recvWindow, wnd)

		return true
	case <-tt.remoteCloseCh:
		return false
	}
}

func (tt *tcpConnTrack) send(pkt *tcpPacket) {
	// log.Debugf("<-- [TCP][%v][%v][seq:%d][ack:%d][payload:%d]", tt.id, tcpflagsString(pkt.tcp), pkt.tcp.Seq, pkt.tcp.Ack, len(pkt.tcp.Payload))
	if pkt.tcp.ACK {
		tt.lastAck = pkt.tcp.Ack
	}
	tt.br.writes <- pkt
}

func (tt *tcpConnTrack) synAck(syn *tcpPacket) {
	iphdr := packet.NewIPv4()
	tcphdr := packet.NewTCP()

	iphdr.Version = 4
	iphdr.Id = packet.IPID()
	iphdr.SrcIP = tt.remoteIP
	iphdr.DstIP = tt.localIP
	iphdr.TTL = 64
	iphdr.Protocol = packet.IPProtocolTCP

	tcphdr.SrcPort = tt.remotePort
	tcphdr.DstPort = tt.localPort
	tcphdr.Window = uint16(atomic.LoadInt32(&tt.recvWindow))
	tcphdr.SYN = true
	tcphdr.ACK = true
	tcphdr.Seq = tt.nxtSeq
	tcphdr.Ack = tt.rcvNxtSeq

	tcphdr.Options = []packet.TCPOption{{2, 4, []byte{0x5, 0xb4}}}

	synAck := tt.br.packTCP(iphdr, tcphdr)
	tt.send(synAck)
	// SYN counts 1 seq
	tt.nxtSeq += 1
}

func (tt *tcpConnTrack) finAck() {
	iphdr := packet.NewIPv4()
	tcphdr := packet.NewTCP()

	iphdr.Version = 4
	iphdr.Id = packet.IPID()
	iphdr.SrcIP = tt.remoteIP
	iphdr.DstIP = tt.localIP
	iphdr.TTL = 64
	iphdr.Protocol = packet.IPProtocolTCP

	tcphdr.SrcPort = tt.remotePort
	tcphdr.DstPort = tt.localPort
	tcphdr.Window = uint16(atomic.LoadInt32(&tt.recvWindow))
	tcphdr.FIN = true
	tcphdr.ACK = true
	tcphdr.Seq = tt.nxtSeq
	tcphdr.Ack = tt.rcvNxtSeq

	finAck := tt.br.packTCP(iphdr, tcphdr)
	tt.send(finAck)
	// FIN counts 1 seq
	tt.nxtSeq += 1
}

func (tt *tcpConnTrack) ack() {
	iphdr := packet.NewIPv4()
	tcphdr := packet.NewTCP()

	iphdr.Version = 4
	iphdr.Id = packet.IPID()
	iphdr.SrcIP = tt.remoteIP
	iphdr.DstIP = tt.localIP
	iphdr.TTL = 64
	iphdr.Protocol = packet.IPProtocolTCP

	tcphdr.SrcPort = tt.remotePort
	tcphdr.DstPort = tt.localPort
	tcphdr.Window = uint16(atomic.LoadInt32(&tt.recvWindow))
	tcphdr.ACK = true
	tcphdr.Seq = tt.nxtSeq
	tcphdr.Ack = tt.rcvNxtSeq

	ack := tt.br.packTCP(iphdr, tcphdr)
	tt.send(ack)
}

func (tt *tcpConnTrack) payload(data []byte) {
	iphdr := packet.NewIPv4()
	tcphdr := packet.NewTCP()

	iphdr.Version = 4
	iphdr.Id = packet.IPID()
	iphdr.SrcIP = tt.remoteIP
	iphdr.DstIP = tt.localIP
	iphdr.TTL = 64
	iphdr.Protocol = packet.IPProtocolTCP

	tcphdr.SrcPort = tt.remotePort
	tcphdr.DstPort = tt.localPort
	tcphdr.Window = uint16(atomic.LoadInt32(&tt.recvWindow))
	tcphdr.ACK = true
	tcphdr.PSH = true
	tcphdr.Seq = tt.nxtSeq
	tcphdr.Ack = tt.rcvNxtSeq
	tcphdr.Payload = data

	pkt := tt.br.packTCP(iphdr, tcphdr)
	tt.send(pkt)
	// adjust seq
	tt.nxtSeq = tt.nxtSeq + uint32(len(data))
}

// stateClosed receives a SYN packet, tries to connect the the remote, gives a
// SYN/ACK if success, otherwise RST
func (tt *tcpConnTrack) stateClosed(syn *tcpPacket) (continu bool, release bool) {
	var e error
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		tt.remoteConn, e = tt.br.dialTCP(ctx, "tcp", fmt.Sprintf("%v:%v", syn.ip.DstIP.String(), syn.tcp.DstPort))
		if e != nil {
			log.Debugf("fail to connect to remote: %v", e)
			tt.remoteConn = nil
		} else {
			// no timeout
			tt.remoteConn.SetDeadline(time.Time{})
			break
		}
	}
	if tt.remoteConn == nil {
		resp := tt.br.rstByPacket(syn)
		tt.br.writes <- resp
		// log.Debugf("<-- [TCP][%v][RST]", tt.id)
		return false, true
	}
	// context variables
	tt.rcvNxtSeq = syn.tcp.Seq + 1
	tt.nxtSeq = 1

	tt.synAck(syn)
	tt.changeState(SYN_RCVD)
	return true, true
}

func (tt *tcpConnTrack) copyToRemote(dstIP net.IP, dstPort uint16, conn net.Conn, readCh chan<- []byte, writes <-chan *tcpPacket, closeCh chan bool) {
	// writer
	go func() {
	loop:
		for {
			select {
			case <-closeCh:
				break loop
			case pkt := <-writes:
				conn.Write(pkt.tcp.Payload)

				// increase window when processed
				wnd := atomic.LoadInt32(&tt.recvWindow)
				wnd += int32(len(pkt.tcp.Payload))
				if wnd > int32(MAX_RECV_WINDOW) {
					wnd = int32(MAX_RECV_WINDOW)
				}
				atomic.StoreInt32(&tt.recvWindow, wnd)

				tt.br.releaseTCPPacket(pkt)
			}
		}
	}()

	// reader
	for {
		buf := make([]byte, tt.br.mtu-40)

		// tt.sendWndCond.L.Lock()
		var wnd int32
		var cur int32
		wnd = atomic.LoadInt32(&tt.sendWindow)

		if wnd <= 0 {
			for wnd <= 0 {
				tt.sendWndCond.L.Lock()
				tt.sendWndCond.Wait()
				wnd = atomic.LoadInt32(&tt.sendWindow)
			}
			tt.sendWndCond.L.Unlock()
		}

		cur = wnd
		if cur > int32(tt.br.mtu-40) {
			cur = int32(tt.br.mtu - 40)
		}
		// tt.sendWndCond.L.Unlock()

		n, e := conn.Read(buf[:cur])
		if e != nil {
			log.Errorf("error reading from remote: %v", e)
			conn.Close()
			break
		} else {
			b := make([]byte, n)
			copy(b, buf[:n])
			readCh <- b

			// tt.sendWndCond.L.Lock()
			nxt := wnd - int32(n)
			if nxt < 0 {
				nxt = 0
			}
			// if sendWindow does not equal to wnd, it is already updated by a
			// received pkt from TUN
			atomic.CompareAndSwapInt32(&tt.sendWindow, wnd, nxt)
			// tt.sendWndCond.L.Unlock()
		}
	}
	close(closeCh)
}

// stateSynRcvd expects a ACK with matching ack number,
func (tt *tcpConnTrack) stateSynRcvd(pkt *tcpPacket) (continu bool, release bool) {
	// rst to packet with invalid sequence/ack, state unchanged
	if !(tt.validSeq(pkt) && tt.validAck(pkt)) {
		if !pkt.tcp.RST {
			resp := tt.br.rstByPacket(pkt)
			tt.br.writes <- resp
			// log.Debugf("<-- [TCP][%v][RST] continue", tt.id)
		}
		return true, true
	}
	// connection ends by valid RST
	if pkt.tcp.RST {
		return false, true
	}
	// ignore non-ACK packets
	if !pkt.tcp.ACK {
		return true, true
	}

	continu = true
	release = true
	tt.changeState(ESTABLISHED)
	go tt.copyToRemote(tt.remoteIP, uint16(tt.remotePort), tt.remoteConn, tt.fromRemoteCh, tt.toRemoteCh, tt.remoteCloseCh)
	if len(pkt.tcp.Payload) != 0 {
		if tt.relayPayload(pkt) {
			// pkt hands to remote writer
			release = false
		}
	}
	return
}

func (tt *tcpConnTrack) stateEstablished(pkt *tcpPacket) (continu bool, release bool) {
	// ack if sequence is not expected
	if !tt.validSeq(pkt) {
		tt.ack()
		return true, true
	}
	// connection ends by valid RST
	if pkt.tcp.RST {
		return false, true
	}
	// ignore non-ACK packets
	if !pkt.tcp.ACK {
		return true, true
	}

	continu = true
	release = true
	if len(pkt.tcp.Payload) != 0 {
		if tt.relayPayload(pkt) {
			// pkt hands to remote writer
			release = false
		}
	}
	if pkt.tcp.FIN {
		tt.rcvNxtSeq += 1
		tt.finAck()
		tt.changeState(LAST_ACK)
		tt.remoteConn.Close()
	}
	return
}

func (tt *tcpConnTrack) stateFinWait1(pkt *tcpPacket) (continu bool, release bool) {
	// ignore packet with invalid sequence, state unchanged
	if !tt.validSeq(pkt) {
		return true, true
	}
	// connection ends by valid RST
	if pkt.tcp.RST {
		return false, true
	}
	// ignore non-ACK packets
	if !pkt.tcp.ACK {
		return true, true
	}

	if pkt.tcp.FIN {
		tt.rcvNxtSeq += 1
		tt.ack()
		if pkt.tcp.ACK && tt.validAck(pkt) {
			tt.changeState(TIME_WAIT)
			return false, true
		} else {
			tt.changeState(CLOSING)
			return true, true
		}
	} else {
		tt.changeState(FIN_WAIT_2)
		return true, true
	}
}

func (tt *tcpConnTrack) stateFinWait2(pkt *tcpPacket) (continu bool, release bool) {
	// ignore packet with invalid sequence/ack, state unchanged
	if !(tt.validSeq(pkt) && tt.validAck(pkt)) {
		return true, true
	}
	// connection ends by valid RST
	if pkt.tcp.RST {
		return false, true
	}
	// ignore non-FIN non-ACK packets
	if !pkt.tcp.ACK || !pkt.tcp.FIN {
		return true, true
	}
	tt.rcvNxtSeq += 1
	tt.ack()
	tt.changeState(TIME_WAIT)
	return false, true
}

func (tt *tcpConnTrack) stateClosing(pkt *tcpPacket) (continu bool, release bool) {
	// ignore packet with invalid sequence/ack, state unchanged
	if !(tt.validSeq(pkt) && tt.validAck(pkt)) {
		return true, true
	}
	// connection ends by valid RST
	if pkt.tcp.RST {
		return false, true
	}
	// ignore non-ACK packets
	if !pkt.tcp.ACK {
		return true, true
	}
	tt.changeState(TIME_WAIT)
	return false, true
}

func (tt *tcpConnTrack) stateLastAck(pkt *tcpPacket) (continu bool, release bool) {
	// ignore packet with invalid sequence/ack, state unchanged
	if !(tt.validSeq(pkt) && tt.validAck(pkt)) {
		return true, true
	}
	// ignore non-ACK packets
	if !pkt.tcp.ACK {
		return true, true
	}
	// connection ends
	tt.changeState(CLOSED)
	return false, true
}

func (tt *tcpConnTrack) newPacket(pkt *tcpPacket) {
	select {
	case <-tt.quitByOther:
	case <-tt.quitBySelf:
	case tt.input <- pkt:
	}
}

func (tt *tcpConnTrack) updateSendWindow(pkt *tcpPacket) {
	// tt.sendWndCond.L.Lock()
	atomic.StoreInt32(&tt.sendWindow, int32(pkt.tcp.Window))
	tt.sendWndCond.Signal()
	// tt.sendWndCond.L.Unlock()
}

func (tt *tcpConnTrack) run() {
	for {
		var ackTimer *time.Timer
		var timeout *time.Timer = time.NewTimer(5 * time.Minute)

		var ackTimeout <-chan time.Time
		var remoteCloseCh chan bool
		var fromRemoteCh chan []byte
		// enable some channels only when the state is ESTABLISHED
		if tt.state == ESTABLISHED {
			remoteCloseCh = tt.remoteCloseCh
			fromRemoteCh = tt.fromRemoteCh
			ackTimer = time.NewTimer(10 * time.Millisecond)
			ackTimeout = ackTimer.C
		}

		select {
		case pkt := <-tt.input:
			// log.Debugf("--> [TCP][%v][%v][%v][seq:%d][ack:%d][payload:%d]", tt.id, tcpstateString(tt.state), tcpflagsString(pkt.tcp), pkt.tcp.Seq, pkt.tcp.Ack, len(pkt.tcp.Payload))
			var continu, release bool

			tt.updateSendWindow(pkt)
			switch tt.state {
			case CLOSED:
				continu, release = tt.stateClosed(pkt)
			case SYN_RCVD:
				continu, release = tt.stateSynRcvd(pkt)
			case ESTABLISHED:
				continu, release = tt.stateEstablished(pkt)
			case FIN_WAIT_1:
				continu, release = tt.stateFinWait1(pkt)
			case FIN_WAIT_2:
				continu, release = tt.stateFinWait2(pkt)
			case CLOSING:
				continu, release = tt.stateClosing(pkt)
			case LAST_ACK:
				continu, release = tt.stateLastAck(pkt)
			}
			if release {
				tt.br.releaseTCPPacket(pkt)
			}
			if !continu {
				if tt.remoteConn != nil {
					tt.remoteConn.Close()
				}
				close(tt.quitBySelf)
				tt.br.clearTCPConnTrack(tt.id)
				return
			}

		case <-ackTimeout:
			if tt.lastAck < tt.rcvNxtSeq {
				// have something to ack
				tt.ack()
			}

		case data := <-fromRemoteCh:
			tt.payload(data)

		case <-remoteCloseCh:
			tt.finAck()
			tt.changeState(FIN_WAIT_1)

		case <-timeout.C:
			if tt.remoteConn != nil {
				tt.remoteConn.Close()
			}
			close(tt.quitBySelf)
			tt.br.clearTCPConnTrack(tt.id)
			return

		case <-tt.quitByOther:
			// who closes this channel should be responsible to clear track map
			if tt.remoteConn != nil {
				tt.remoteConn.Close()
			}
			return
		}
		timeout.Stop()
		if ackTimer != nil {
			ackTimer.Stop()
		}
	}
}

func (br *bridge) createTCPConnTrack(id string, ip *packet.IPv4, tcp *packet.TCP) *tcpConnTrack {
	br.tcpConnTrackMx.Lock()
	defer br.tcpConnTrackMx.Unlock()

	track := &tcpConnTrack{
		br:            br,
		id:            id,
		input:         make(chan *tcpPacket, 10000),
		fromRemoteCh:  make(chan []byte, 100),
		toRemoteCh:    make(chan *tcpPacket, 100),
		remoteCloseCh: make(chan bool),
		quitBySelf:    make(chan bool),
		quitByOther:   make(chan bool),

		sendWindow:  int32(MAX_SEND_WINDOW),
		recvWindow:  int32(MAX_RECV_WINDOW),
		sendWndCond: &sync.Cond{L: &sync.Mutex{}},

		localPort:  tcp.SrcPort,
		remotePort: tcp.DstPort,
		state:      CLOSED,
	}
	track.localIP = make(net.IP, len(ip.SrcIP))
	copy(track.localIP, ip.SrcIP)
	track.remoteIP = make(net.IP, len(ip.DstIP))
	copy(track.remoteIP, ip.DstIP)

	br.tcpConnTrack[id] = track
	go track.run()
	return track
}

func (br *bridge) getTCPConnTrack(id string) *tcpConnTrack {
	br.tcpConnTrackMx.Lock()
	defer br.tcpConnTrackMx.Unlock()

	return br.tcpConnTrack[id]
}

func (br *bridge) clearTCPConnTrack(id string) {
	br.tcpConnTrackMx.Lock()
	defer br.tcpConnTrackMx.Unlock()

	delete(br.tcpConnTrack, id)
}

func (br *bridge) onTCPPacket(raw []byte, ip *packet.IPv4, tcp *packet.TCP) {
	connID := tcpConnID(ip, tcp)
	track := br.getTCPConnTrack(connID)
	if track != nil {
		pkt := br.copyTCPPacket(raw, ip, tcp)
		track.newPacket(pkt)
	} else {
		// ignore RST, if there is no track of this connection
		if tcp.RST {
			// log.Debugf("--> [TCP][%v][%v]", connID, tcpflagsString(tcp))
			return
		}
		// return a RST to non-SYN packet
		if !tcp.SYN {
			// log.Debugf("--> [TCP][%v][%v]", connID, tcpflagsString(tcp))
			resp := br.rst(ip.SrcIP, ip.DstIP, tcp.SrcPort, tcp.DstPort, tcp.Seq, tcp.Ack, uint32(len(tcp.Payload)))
			br.writes <- resp
			// log.Debugf("<-- [TCP][%v][RST]", connID)
			return
		}
		pkt := br.copyTCPPacket(raw, ip, tcp)
		track := br.createTCPConnTrack(connID, ip, tcp)
		track.newPacket(pkt)
	}
}
