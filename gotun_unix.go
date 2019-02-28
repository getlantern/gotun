// +build !darwin,!windows

package tun

import (
	"io"
	"net"
	"os"
	"sync/atomic"
	"syscall"
)

func WrapTunDevice(fd int, addr, gw string) (io.ReadWriteCloser, error) {
	return newTunDev(os.NewFile(uintptr(fd), "wrapped"), addr, gw), nil
}

func newTunDev(file *os.File, addr string, gw string) io.ReadWriteCloser {
	syscall.SetNonblock(int(file.Fd()), false)
	dev := &tunDev{
		baseDevice: baseDevice{
			f: file,
		},
	}
	if addr != "" {
		dev.addr = addr
		dev.addrIP = parseIPv4(addr)
	}
	if gw != "" {
		dev.gw = gw
		dev.gwIP = parseIPv4(gw)
	}
	return dev
}

type tunDev struct {
	closed int64
	name   string
	addr   string
	addrIP net.IP
	gw     string
	gwIP   net.IP

	baseDevice
}

func (dev *tunDev) Read(data []byte) (int, error) {
	n, err := dev.f.Read(data)
	if err != nil && dev.isClosed() {
		err = io.EOF
	}
	return n, err
}

func (dev *tunDev) Write(data []byte) (int, error) {
	return dev.f.Write(data)
}

func (dev *tunDev) Close() error {
	if atomic.CompareAndSwapInt64(&dev.closed, 0, 1) {
		return syscall.Close(int(dev.f.Fd()))
	}
	return errAlreadyClosed
}
