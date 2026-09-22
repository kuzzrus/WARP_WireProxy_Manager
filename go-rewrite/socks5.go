package main

import (
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	socksHandshakeTimeout = 30 * time.Second
	socksDialTimeout      = 30 * time.Second
	socksIdleTimeout      = 10 * time.Minute
)

// Минимальный SOCKS5: без аутентификации, только CONNECT (RFC 1928). Этого
// достаточно для Xray-outbound, который сейчас смотрит на wireproxy так же.
func serveSOCKS5(ctx context.Context, ln net.Listener, active *atomic.Pointer[tunnel]) {
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("socks5: accept: %v", err)
			return
		}
		go handleSOCKS5ConnContext(ctx, c, active)
	}
}

func handleSOCKS5Conn(c net.Conn, active *atomic.Pointer[tunnel]) {
	handleSOCKS5ConnContext(context.Background(), c, active)
}

func handleSOCKS5ConnContext(ctx context.Context, c net.Conn, active *atomic.Pointer[tunnel]) {
	defer c.Close()
	stopHandshakeCancellation := closeConnectionsOnContext(ctx, c)
	defer stopHandshakeCancellation()
	buf := make([]byte, 262)
	if err := c.SetDeadline(time.Now().Add(socksHandshakeTimeout)); err != nil {
		return
	}

	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	nmethods := int(buf[1])
	if nmethods > 0 {
		if _, err := io.ReadFull(c, buf[:nmethods]); err != nil {
			return
		}
	}
	supportsNoAuth := false
	for _, method := range buf[:nmethods] {
		if method == 0x00 {
			supportsNoAuth = true
			break
		}
	}
	if !supportsNoAuth {
		_, _ = c.Write([]byte{0x05, 0xff})
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil { // без аутентификации
		return
	}

	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return
	}
	ver, cmd, atyp := buf[0], buf[1], buf[3]
	if ver != 0x05 || cmd != 0x01 { // поддерживаем только CONNECT
		writeSOCKS5Reply(c, 0x07)
		return
	}

	var host string
	switch atyp {
	case 0x01: // IPv4
		if _, err := io.ReadFull(c, buf[:4]); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 0x04: // IPv6
		if _, err := io.ReadFull(c, buf[:16]); err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	case 0x03: // domain name
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return
		}
		l := int(buf[0])
		if _, err := io.ReadFull(c, buf[:l]); err != nil {
			return
		}
		host = string(buf[:l])
	default:
		writeSOCKS5Reply(c, 0x08)
		return
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(c, portBuf[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf[:])

	t := active.Load()
	if t == nil || !t.Borrow() {
		writeSOCKS5Reply(c, 0x01)
		return
	}
	defer t.Release()
	dialCtx, cancelDial := context.WithTimeout(ctx, socksDialTimeout)
	remote, err := t.tnet.DialContext(dialCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	cancelDial()
	if err != nil {
		writeSOCKS5Reply(c, 0x05)
		return
	}
	defer remote.Close()
	stopHandshakeCancellation()
	stopRelayCancellation := closeConnectionsOnContext(ctx, c, remote)
	defer stopRelayCancellation()
	if err := writeSOCKS5Reply(c, 0x00); err != nil {
		return
	}
	clientRelay, remoteRelay, err := newIdleTimeoutPair(c, remote, socksIdleTimeout)
	if err != nil {
		return
	}

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(remoteRelay, clientRelay)
		closeWrite(remoteRelay)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientRelay, remoteRelay)
		closeWrite(clientRelay)
		done <- struct{}{}
	}()
	// A single io.Copy finishing only means one side half-closed its stream.
	// Wait for the opposite direction too, otherwise a server response sent
	// after client EOF is lost.
	<-done
	<-done
}

func closeConnectionsOnContext(ctx context.Context, conns ...net.Conn) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			for _, conn := range conns {
				_ = conn.Close()
			}
		case <-stop:
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(stop)
			<-done
		})
	}
}

type idleDeadlineGroup struct {
	timeout time.Duration
	conns   []net.Conn
}

func (g *idleDeadlineGroup) refresh() error {
	deadline := time.Now().Add(g.timeout)
	for _, conn := range g.conns {
		if err := conn.SetDeadline(deadline); err != nil {
			return err
		}
	}
	return nil
}

type idleTimeoutConn struct {
	net.Conn
	deadlines *idleDeadlineGroup
}

func newIdleTimeoutPair(left, right net.Conn, timeout time.Duration) (*idleTimeoutConn, *idleTimeoutConn, error) {
	deadlines := &idleDeadlineGroup{timeout: timeout, conns: []net.Conn{left, right}}
	if err := deadlines.refresh(); err != nil {
		return nil, nil, err
	}
	return &idleTimeoutConn{Conn: left, deadlines: deadlines}, &idleTimeoutConn{Conn: right, deadlines: deadlines}, nil
}

func (c *idleTimeoutConn) Read(p []byte) (int, error) {
	if err := c.deadlines.refresh(); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

func (c *idleTimeoutConn) Write(p []byte) (int, error) {
	if err := c.deadlines.refresh(); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

func (c *idleTimeoutConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func writeSOCKS5Reply(c net.Conn, rep byte) error {
	_, err := c.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}
