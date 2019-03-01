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

func (dev *baseDevice) closeIfNecessary(closer func() error) error {
	err := errAlreadyClosed
	if atomic.CompareAndSwapInt64(&dev.closed, 0, 1) {
		err = closer()
	}
	return err
}

func parseIPv4(ip string) net.IP {
	return net.ParseIP(ip).To4()
}
