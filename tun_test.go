package tun

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Note - this test has to be run with root permissions to allow setting up the
// TUN device.
func TestTCPandUDP(t *testing.T) {
	ip := "127.0.0.1"

	dev, err := OpenTunDevice("tun0", "10.0.0.2", "10.0.0.1", "255.255.255.0")
	if err != nil {
		log.Fatal(err)
	}
	defer dev.Close()

	d := &net.Dialer{}
	go Serve(dev, &ServerOpts{
		IdleTimeout: 5 * time.Second,
		DialTCP: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Send everything to local echo server
			log.Debug("dialing")
			_, port, _ := net.SplitHostPort(addr)
			return d.DialContext(ctx, network, ip+":"+port)
		},
		DialUDP: func(ctx context.Context, network, addr string) (*net.UDPConn, error) {
			// Send everything to local echo server
			_, port, _ := net.SplitHostPort(addr)
			conn, err := net.Dial(network, ip+":"+port)
			if err != nil {
				return nil, err
			}
			return conn.(*net.UDPConn), nil
		},
	})

	closeCh := make(chan interface{})
	echoAddr := tcpEcho(t, closeCh, ip)
	udpEcho(t, closeCh, echoAddr)

	// point at TUN device rather than echo server directly
	_, port, _ := net.SplitHostPort(echoAddr)
	echoAddr = "10.0.0.1:" + port

	b := make([]byte, 8)

	log.Debugf("Dialing echo server at: %v", echoAddr)
	uconn, err := net.Dial("udp", echoAddr)
	defer uconn.Close()

	_, err = uconn.Write([]byte("helloudp"))
	if !assert.NoError(t, err) {
		return
	}

	uconn.SetDeadline(time.Now().Add(250 * time.Millisecond))
	_, err = io.ReadFull(uconn, b)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, "helloudp", string(b))

	conn, err := net.DialTimeout("tcp", echoAddr, 5*time.Second)
	if !assert.NoError(t, err) {
		return
	}
	defer conn.Close()

	_, err = conn.Write([]byte("hellotcp"))
	if !assert.NoError(t, err) {
		return
	}

	_, err = io.ReadFull(conn, b)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, "hellotcp", string(b))
}

func tcpEcho(t *testing.T, closeCh <-chan interface{}, ip string) string {
	l, err := net.Listen("tcp", ip+":0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		<-closeCh
		l.Close()
	}()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				t.Error(err)
				return
			}
			go io.Copy(conn, conn)
		}
	}()

	return l.Addr().String()
}

func udpEcho(t *testing.T, closeCh <-chan interface{}, echoAddr string) {
	conn, err := net.ListenPacket("udp", echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		<-closeCh
		conn.Close()
	}()

	go func() {
		b := make([]byte, 20480)
		for {
			n, addr, err := conn.ReadFrom(b)
			if err != nil {
				t.Error(err)
				return
			}
			conn.WriteTo(b[:n], addr)
		}
	}()
}
