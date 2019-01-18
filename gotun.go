package tun

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/getlantern/golog"
	"github.com/getlantern/gotun/packet"
	"github.com/getlantern/netx"
	"github.com/oxtoacart/bpool"
)

const (
	defaultMTU              = 1500
	defaultWriteBufferDepth = 10000
	defaultBufferPoolDepth  = 1000
	defaultIdleTimeout      = 5 * time.Minute
)

var (
	log = golog.LoggerFor("gotun")
)

type bridge struct {
	dev            io.ReadWriteCloser
	dialTCP        func(ctx context.Context, network, addr string) (net.Conn, error)
	dialUDP        func(ctx context.Context, network, addr string) (*net.UDPConn, error)
	mtu            int
	idleTimeout    time.Duration
	ipFragments    map[uint16]*ipPacket
	writes         chan interface{}
	buffers        *bpool.BytePool
	udpPacketPool  *sync.Pool
	tcpConnTrack   map[string]*tcpConnTrack
	tcpConnTrackMx sync.Mutex
	udpConnTrack   map[fourtuple]*udpConnTrack
	udpConnTrackMx sync.Mutex
	stopCh         chan bool
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
	IdleTimeout      time.Duration
	DialTCP          func(ctx context.Context, network, addr string) (net.Conn, error)
	DialUDP          func(ctx context.Context, network, addr string) (*net.UDPConn, error)
}

type Bridge interface {
	// Serve() services clients (blocking)
	Serve() error

	// NumTCPConns returns the current number of TCP connections being tracked
	NumTCPConns() int

	// NumUDPConns returns the current number of UDP connections being tracked
	NumUDPConns() int
}

func NewBridge(dev io.ReadWriteCloser, opts *ServerOpts) Bridge {
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
		log.Debugf("Defaulting buffer pool depth to %v", opts.BufferPoolDepth)
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = defaultIdleTimeout
	}
	if opts.DialTCP == nil {
		opts.DialTCP = netx.DialContext
		log.Debug("Defaulted tcp dial function")
	}
	if opts.DialUDP == nil {
		opts.DialUDP = func(ctx context.Context, network, addr string) (*net.UDPConn, error) {
			udpAddr, err := netx.ResolveUDPAddr(network, addr)
			if err != nil {
				return nil, err
			}
			return netx.DialUDP(network, nil, udpAddr)
		}
		log.Debug("Defaulting udp dial function")
	}

	return &bridge{
		dev:          dev,
		dialTCP:      opts.DialTCP,
		dialUDP:      opts.DialUDP,
		mtu:          opts.MTU,
		idleTimeout:  opts.IdleTimeout,
		ipFragments:  make(map[uint16]*ipPacket),
		writes:       make(chan interface{}, opts.WriteBufferDepth),
		tcpConnTrack: make(map[string]*tcpConnTrack),
		udpConnTrack: make(map[fourtuple]*udpConnTrack),
		buffers:      bpool.NewBytePool(opts.BufferPoolDepth, opts.MTU),
		udpPacketPool: &sync.Pool{
			New: func() interface{} {
				return &udpPacket{}
			},
		},
		stopCh: make(chan bool),
	}
}

func (br *bridge) Serve() error {
	go br.write()
	go br.trackStats()
	return br.read()
}

func (br *bridge) read() error {
	defer func() {
		close(br.stopCh)
	}()

	var ip packet.IPv4
	var tcp packet.TCP
	var udp packet.UDP

	for {
		buf := make([]byte, br.mtu)
		n, err := br.dev.Read(buf)
		if err != nil {
			if err == errStopMarkerReceived {
				log.Debug("bridge received close signal")
				return nil
			}
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
	for {
		select {
		case <-br.stopCh:
			return
		case pkt := <-br.writes:
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
