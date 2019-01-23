// +build !darwin

package tun

import (
	"net"
	"os"
	"sync/atomic"
	"syscall"
)

func WrapTunDevice(fd int, addr, gw string) (TUNDevice, error) {
	return NewTunDev(os.NewFile(uintptr(fd), "wrapped"), addr, gw), nil
}

func NewTunDev(file *os.File, addr string, gw string) TUNDevice {
	syscall.SetNonblock(int(file.Fd()), false)
	dev := &tunDev{
		f: file,
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
	stopped int64
	name    string
	addr    string
	addrIP  net.IP
	gw      string
	gwIP    net.IP
	f       *os.File
}

func (dev *tunDev) Read(data []byte) (int, error) {
	n, e := dev.f.Read(data)
	if e == nil && isStopMarker(data[:n], dev.addrIP, dev.gwIP) {
		return 0, errStopMarkerReceived
	}
	return n, e
}

func (dev *tunDev) Write(data []byte) (int, error) {
	return dev.f.Write(data)
}

func (dev *tunDev) Stop() error {
	if atomic.CompareAndSwapInt64(&dev.stopped, 0, 1) {
		sendStopMarker(dev.addr, dev.gw)
		return nil
	}
	return errAlreadyStopped
}

func (dev *tunDev) Close() error {
	return dev.f.Close()
}
