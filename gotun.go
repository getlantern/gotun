package tun

import (
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/getlantern/golog"
	"github.com/getlantern/gotun/packet"
	"github.com/oxtoacart/bpool"
)

const (
	defaultMTU              = 1500
	defaultWriteBufferDepth = 10000
	defaultBufferPoolDepth  = 1000
)

var (
	log = golog.LoggerFor("gotun")
)

type bridge struct {
	dev              io.ReadWriteCloser
	mtu              int
	ipFragments      map[uint16]*ipPacket
	writes           chan interface{}
	buffers          *bpool.BytePool
	udpPacketPool    *sync.Pool
	tcpConnTrackMap  map[string]*tcpConnTrack
	tcpConnTrackLock sync.Mutex
	udpConns         map[fourtuple]*net.UDPConn
}

type fourtuple struct {
	localIP, remoteIP     string
	localPort, remotePort uint16
}

func (ft fourtuple) String() string {
	return fmt.Sprintf("%v:%v -> %v:%v", ft.localIP, ft.localPort, ft.remoteIP, ft.remotePort)
}

type ServerOpts struct {
	MTU              int
	WriteBufferDepth int
	BufferPoolDepth  int
}

func Serve(dev io.ReadWriteCloser, opts *ServerOpts) error {
	if opts.MTU <= 0 {
		opts.MTU = defaultMTU
		log.Debugf("Defaulting mtu to %v", opts.MTU)
	}
	if opts.WriteBufferDepth <= 0 {
		opts.WriteBufferDepth = defaultWriteBufferDepth
		log.Debugf("Defaulting write buffer depth to %v", opts.WriteBufferDepth)
	}
	if opts.BufferPoolDepth <= 0 {
		opts.BufferPoolDepth = defaultBufferPoolDepth
		log.Debugf("Defaulted buffer pool depth to %v", opts.BufferPoolDepth)
	}
	br := &bridge{
		dev:             dev,
		mtu:             opts.MTU,
		ipFragments:     make(map[uint16]*ipPacket),
		writes:          make(chan interface{}, opts.WriteBufferDepth),
		tcpConnTrackMap: make(map[string]*tcpConnTrack),
		udpConns:        make(map[fourtuple]*net.UDPConn),
		buffers:         bpool.NewBytePool(opts.BufferPoolDepth, opts.MTU),
		udpPacketPool: &sync.Pool{
			New: func() interface{} {
				return &udpPacket{}
			},
		},
	}

	go br.write()
	return br.read()
}

func (br *bridge) read() error {
	var ip packet.IPv4
	var tcp packet.TCP
	var udp packet.UDP

	for {
		// TODO: use pool for buffers
		buf := make([]byte, br.mtu)
		n, err := br.dev.Read(buf)
		if err != nil {
			// TODO: stop at critical error
			return log.Errorf("error reading packet: %v", err)
		}
		data := buf[:n]
		err = packet.ParseIPv4(data, &ip)
		if err != nil {
			log.Errorf("unable to parse IPv4: %v", err)
			continue
		}

		if ip.Flags&0x1 != 0 || ip.FragOffset != 0 {
			last, pkt, raw := br.procFragment(&ip, data)
			if last {
				ip = *pkt
				data = raw
			} else {
				continue
			}
		}

		switch ip.Protocol {
		case packet.IPProtocolTCP:
			err = packet.ParseTCP(ip.Payload, &tcp)
			if err != nil {
				log.Errorf("unable to parse TCP: %v", err)
				continue
			}
			br.onTCPPacket(data, &ip, &tcp)

		case packet.IPProtocolUDP:
			err = packet.ParseUDP(ip.Payload, &udp)
			if err != nil {
				log.Errorf("unable to parse UDP: %v", err)
				continue
			}
			br.onUDPPacket(&ip, &udp)

		default:
			// Unsupported packets
			log.Errorf("Unsupported packet: protocol %d", ip.Protocol)
		}
	}
}

func (br *bridge) write() {
	for pkt := range br.writes {
		switch p := pkt.(type) {
		case *tcpPacket:
			_, err := br.dev.Write(p.wire)
			br.releaseTCPPacket(p)
			if err != nil {
				log.Errorf("Error on writing TCP to tun device: %v", err)
				return
			}
		case *udpPacket:
			_, err := br.dev.Write(p.wire)
			br.releaseUDPPacket(p)
			if err != nil {
				log.Errorf("Error on writing UDP to tun device: %v", err)
				return
			}
		case *ipPacket:
			_, err := br.dev.Write(p.wire)
			br.releaseIPPacket(p)
			if err != nil {
				log.Errorf("Error on writing IP to tun device: %v", err)
				return
			}
		}
	}
}

func (br *bridge) newBuffer() []byte {
	return br.buffers.Get()
}

func (br *bridge) releaseBuffer(b []byte) {
	br.buffers.Put(b)
}

func parseIPv4(ip string) net.IP {
	return net.ParseIP(ip).To4()
}
