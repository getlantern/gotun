// +build !darwin

package tun

import (
	"errors"
	"io"
	"net"
	"os"
	"syscall"
)

func WrapTunDevice(fd int) (io.ReadWriteCloser, error) {
	return NewTunDev(os.NewFile(uintptr(fd), "wrapped"), "", ""), nil
}

func NewTunDev(file *os.File, addr string, gw string) io.ReadWriteCloser {
	syscall.SetNonblock(int(file.Fd()), false)
	dev := &tunDev{
		f: file,
	}
	if addr != "" {
		dev.addr = addr
		dev.addrIP = net.ParseIP(addr).To4()
	}
	if gw != "" {
		dev.gw = gw
		dev.gwIP = net.ParseIP(gw).To4()
	}
	return dev
}

type tunDev struct {
	name   string
	addr   string
	addrIP net.IP
	gw     string
	gwIP   net.IP
	f      *os.File
}

func (dev *tunDev) Read(data []byte) (int, error) {
	n, e := dev.f.Read(data)
	if e == nil && isStopMarker(data[:n], dev.addrIP, dev.gwIP) {
		return 0, errors.New("received stop marker")
	}
	return n, e
}

func (dev *tunDev) Write(data []byte) (int, error) {
	return dev.f.Write(data)
}

func (dev *tunDev) Close() error {
	sendStopMarker(dev.addr, dev.gw)
	return dev.f.Close()
}
