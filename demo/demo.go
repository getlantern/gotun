package main

import (
	"flag"
	"fmt"

	"github.com/getlantern/golog"
	"github.com/getlantern/gotun"
)

var (
	log = golog.LoggerFor("gotun-demo")
)

var (
	tunDevice = flag.String("tun-device", "tun0", "tun device name")
	tunAddr   = flag.String("tun-address", "10.0.0.2", "tun device address")
	tunMask   = flag.String("tun-mask", "255.255.255.0", "tun device netmask")
	tunGW     = flag.String("tun-gw", "10.0.0.1", "tun device gateway")
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
	dev, e := tun.OpenTunDevice(*tunDevice, *tunAddr, *tunGW, *tunMask)
	if e != nil {
		log.Fatal(e)
	}
	defer dev.Close()

	tun.Serve(dev, &tun.ServerOpts{})
}
