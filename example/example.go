package main

import (
	"encoding/binary"
	"flag"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/link/channel"
	"github.com/google/netstack/tcpip/network/arp"
	"github.com/google/netstack/tcpip/network/ipv4"
	"github.com/google/netstack/tcpip/network/ipv6"
	"github.com/google/netstack/tcpip/stack"
	"github.com/google/netstack/tcpip/transport/tcp"
	"github.com/google/netstack/waiter"

	"github.com/getlantern/gotun"
	"github.com/getlantern/gotun/packet"
)

var (
	tunDevice = flag.String("tun-device", "tun0", "tun device name")
	tunAddr   = flag.String("tun-address", "10.0.0.2", "tun device address")
	tunMask   = flag.String("tun-mask", "255.255.255.0", "tun device netmask")
	tunGW     = flag.String("tun-gw", "10.0.0.1", "tun device gateway")
	mac       = flag.String("mac", "aa:00:01:01:01:01", "mac address to use in tap device")
)

func echo(wq *waiter.Queue, ep tcpip.Endpoint) {
	defer ep.Close()

	// Create wait queue entry that notifies a channel.
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)

	wq.EventRegister(&waitEntry, waiter.EventIn)
	defer wq.EventUnregister(&waitEntry)

	for {
		v, _, err := ep.Read(nil)
		if err != nil {
			if err == tcpip.ErrWouldBlock {
				<-notifyCh
				continue
			}

			return
		}

		ep.Write(tcpip.SlicePayload(v), tcpip.WriteOptions{})
	}
}

func main() {
	flag.Parse()
	rand.Seed(time.Now().UnixNano())

	// Parse the mac address.
	maddr, err := net.ParseMAC(*mac)
	if err != nil {
		log.Fatalf("Bad MAC address: %v", *mac)
	}

	// Create the stack with ip and tcp protocols, then add a tun-based
	// NIC and address.
	s := stack.New([]string{ipv4.ProtocolName, ipv6.ProtocolName, arp.ProtocolName}, []string{tcp.ProtocolName}, stack.Options{})

	// mtu, err := rawfile.GetMTU(tunName)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// TODO: get MTU dynamically?
	mtu := 1500

	dev, err := tun.OpenTunDevice(*tunDevice, *tunAddr, *tunGW, *tunMask)
	if err != nil {
		log.Fatal(err)
	}

	linkID, endpoint := channel.New(100, uint32(mtu), tcpip.LinkAddress(maddr))
	if err := s.CreateNIC(1, linkID); err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			b := make([]byte, mtu)
			n, err := dev.Read(b)
			if err != nil {
				log.Fatal(err)
			}
			pkt := b[:n]
			ipv4Pkt := packet.NewIPv4()
			packet.ParseIPv4(pkt, ipv4Pkt)
			log.Printf("--> %v,%v\n", binary.BigEndian.Uint16(ipv4Pkt.Payload[0:2]), binary.BigEndian.Uint16(ipv4Pkt.Payload[2:4]))
			endpoint.Inject(ipv4.ProtocolNumber, buffer.View(pkt).ToVectorisedView())
		}
	}()

	go func() {
		for pktInfo := range endpoint.C {
			pkt := make([]byte, 0, len(pktInfo.Header)+len(pktInfo.Payload))
			pkt = append(pkt, pktInfo.Header...)
			pkt = append(pkt, pktInfo.Payload...)
			ipv4Pkt := packet.NewIPv4()
			packet.ParseIPv4(pkt, ipv4Pkt)
			log.Printf("<-- %v,%v\n", binary.BigEndian.Uint16(ipv4Pkt.Payload[0:2]), binary.BigEndian.Uint16(ipv4Pkt.Payload[2:4]))
			_, err := dev.Write(pkt)
			if err != nil {
				log.Fatal(err)
			}
		}
		log.Println("done")
	}()

	localPort := 9000
	proto := ipv4.ProtocolNumber
	addr := tcpip.Address(net.ParseIP(*tunGW).To4())
	log.Println(addr)
	if err := s.AddAddress(1, proto, addr); err != nil {
		log.Fatal(err)
	}

	if err := s.AddAddress(1, arp.ProtocolNumber, arp.ProtocolAddress); err != nil {
		log.Fatal(err)
	}

	// Add default route.
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: tcpip.Address(strings.Repeat("\x00", len(addr))),
			Mask:        tcpip.AddressMask(strings.Repeat("\x00", len(addr))),
			Gateway:     "",
			NIC:         1,
		},
	})

	// Create TCP endpoint, bind it, then start listening.
	var wq waiter.Queue
	ep, e := s.NewEndpoint(tcp.ProtocolNumber, proto, &wq)
	if err != nil {
		log.Fatal(e)
	}

	defer ep.Close()

	if err := ep.Bind(tcpip.FullAddress{0, "", uint16(localPort)}, nil); err != nil {
		log.Fatal("Bind failed: ", err)
	}

	if err := ep.Listen(10); err != nil {
		log.Fatal("Listen failed: ", err)
	}

	// Wait for connections to appear.
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	wq.EventRegister(&waitEntry, waiter.EventIn)
	defer wq.EventUnregister(&waitEntry)

	for {
		n, wq, err := ep.Accept()
		if err != nil {
			if err == tcpip.ErrWouldBlock {
				<-notifyCh
				continue
			}

			log.Fatal("Accept() failed:", err)
		}

		go echo(wq, n)
	}
}
