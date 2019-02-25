package tun

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/getlantern/gotun/packet"
	"github.com/getlantern/netx"
	"github.com/oxtoacart/bpool"
)

// BridgeOpts configures a Bridge
type BridgeOpts struct {
	MTU              int
	WriteBufferDepth int
	BufferPoolDepth  int
	IdleTimeout      time.Duration
	DialTCP          func(ctx context.Context, network, addr string) (net.Conn, error)
	DialUDP          func(ctx context.Context, network, addr string) (*net.UDPConn, error)
}

// Bridge is a bridge between a TUN device and a proxy that can connect upstream.
type Bridge interface {
	// Serve() services clients (blocking)
	Serve() error

	// NumTCPConns returns the current number of TCP connections being tracked
	NumTCPConns() int

	// NumUDPConns returns the current number of UDP connections being tracked
	NumUDPConns() int
}

type bridge struct {
	acceptedPackets int64
	rejectedPackets int64
	dev             io.ReadWriteCloser
	dialTCP         func(ctx context.Context, network, addr string) (net.Conn, error)
	dialUDP         func(ctx context.Context, network, addr string) (*net.UDPConn, error)
	mtu             int
	idleTimeout     time.Duration
	ipFragments     map[uint16]*ipPacket
	writes          chan interface{}
	buffers         *bpool.BytePool
	udpPacketPool   *sync.Pool
	tcpConnTrack    map[string]*tcpConnTrack
	tcpConnTrackMx  sync.Mutex
	udpConnTrack    map[fourtuple]*udpConnTrack
	udpConnTrackMx  sync.Mutex
	stopCh          chan bool
}

// NewBridge creates a new bridge on the given TUN device. Once a bridge is
// using a TUN device, you can shut down by calling Stop() on the device. The
// bridge will finish up processing and then close the device.
func NewBridge(dev io.ReadWriteCloser, opts *BridgeOpts) Bridge {
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
	doneWriting := make(chan interface{})
	go br.write(doneWriting)
	go br.trackStats()
	return br.read(doneWriting)
}

func (br *bridge) read(doneWriting <-chan interface{}) error {
	defer func() {
		close(br.stopCh)
		// Wait for writing to finish, but no longer than 30 seconds
		select {
		case <-doneWriting:
		case <-time.After(30 * time.Second):
		}
		br.dev.Close()
	}()

	var ip packet.IPv4
	var tcp packet.TCP
	var udp packet.UDP

	for {
		buf := make([]byte, br.mtu)
		n, err := br.dev.Read(buf)
		if err != nil {
			if err == errStopMarkerReceived {
				log.Debug("bridge received stop signal")
				return nil
			}
			if err == io.EOF {
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
			br.acceptedPacket()

		case packet.IPProtocolUDP:
			err = packet.ParseUDP(ip.Payload, &udp)
			if err != nil {
				log.Errorf("unable to parse UDP: %v", err)
				continue
			}
			br.onUDPPacket(&ip, &udp)
			br.acceptedPacket()

		default:
			// Unsupported packets
			// log.Errorf("Unsupported packet: protocol %d", ip.Protocol)
			br.rejectedPacket()
		}
	}
}

func (br *bridge) write(doneWriting chan<- interface{}) {
	defer func() {
		doneWriting <- nil
	}()

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
