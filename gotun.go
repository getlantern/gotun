package tun

import (
	"errors"
	"net"
	"os"
	"sync/atomic"

	"github.com/getlantern/golog"
)

var (
	log = golog.LoggerFor("gotun")

	errAlreadyClosed = errors.New("already closed")
)

type baseDevice struct {
	closed int64

	f *os.File
}

func (dev *baseDevice) isClosed() bool {
	return atomic.LoadInt64(&dev.closed) == 1
}

func parseIPv4(ip string) net.IP {
	return net.ParseIP(ip).To4()
}
