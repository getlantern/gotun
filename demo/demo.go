package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/getlantern/golog"
	"github.com/getlantern/gotun"
	"github.com/getlantern/netx"
)

var (
	log = golog.LoggerFor("gotun-demo")
)

var (
	tunDevice = flag.String("tun-device", "tun0", "tun device name")
	tunAddr   = flag.String("tun-address", "10.0.0.2", "tun device address")
	tunMask   = flag.String("tun-mask", "255.255.255.0", "tun device netmask")
	tunGW     = flag.String("tun-gw", "10.0.0.1", "tun device gateway")
	ifOut     = flag.String("ifout", "en0", "name of interface to use for outbound connections")
)

type fivetuple struct {
	proto            string
	srcIP, dstIP     string
	srcPort, dstPort int
}

func (ft fivetuple) String() string {
	return fmt.Sprintf("[%v] %v:%v -> %v:%v", ft.proto, ft.srcIP, ft.srcPort, ft.dstIP, ft.dstPort)
}

func main() {
	dev, err := tun.OpenTunDevice(*tunDevice, *tunAddr, *tunGW, *tunMask)
	if err != nil {
		log.Fatal(err)
	}
	defer dev.Close()

	outIF, err := net.InterfaceByName(*ifOut)
	if err != nil {
		log.Fatal(err)
	}
	outIFAddrs, err := outIF.Addrs()
	if err != nil {
		log.Fatal(err)
	}
	var laddrTCP *net.TCPAddr
	var laddrUDP *net.UDPAddr
	for _, outIFAddr := range outIFAddrs {
		switch t := outIFAddr.(type) {
		case *net.IPNet:
			ipv4 := t.IP.To4()
			if ipv4 != nil {
				laddrTCP = &net.TCPAddr{IP: ipv4, Port: 0}
				laddrUDP = &net.UDPAddr{IP: ipv4, Port: 0}
				break
			}
		}
	}
	if laddrTCP == nil {
		log.Fatalf("Unable to get IPv4 address for interface %v", *ifOut)
	}
	log.Debugf("Outbound TCP will use %v", laddrTCP)
	log.Debugf("Outbound UDP will use %v", laddrUDP)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		<-ch
		log.Debug("Closing TUN device")
		dev.Close()
		log.Debug("Closed TUN device")
		time.Sleep(1 * time.Minute)
	}()

	tun.NewBridge(dev, &tun.ServerOpts{
		IdleTimeout: 5 * time.Second,
		DialTCP: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raddr, err := netx.Resolve(network, addr)
			if err != nil {
				return nil, err
			}
			return net.DialTCP(network, laddrTCP, raddr)
		},
		DialUDP: func(ctx context.Context, network, addr string) (*net.UDPConn, error) {
			raddr, err := netx.ResolveUDPAddr(network, addr)
			if err != nil {
				return nil, err
			}
			return netx.DialUDP(network, laddrUDP, raddr)
		},
	}).Serve()
}
