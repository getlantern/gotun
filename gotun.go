package tun

import (
	"fmt"
	"io"
	"time"

	"github.com/getlantern/golog"
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

type fourtuple struct {
	localIP, remoteIP     string
	localPort, remotePort uint16
}

func (ft fourtuple) String() string {
	return fmt.Sprintf("%v:%v -> %v:%v", ft.localIP, ft.localPort, ft.remoteIP, ft.remotePort)
}

type TUNDevice interface {
	io.ReadWriteCloser

	// Stop sends the stop signal to this TUN device
	Stop() error
}
