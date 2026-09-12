package main

import (
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"
	"sync/atomic"
)

// Минимальный SOCKS5: без аутентификации, только CONNECT (RFC 1928). Этого
// достаточно для Xray-outbound, который сейчас смотрит на wireproxy так же.
func serveSOCKS5(ln net.Listener, active *atomic.Pointer[tunnel]) {
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("socks5: accept: %v", err)
			return
		}
		go handleSOCKS5Conn(c, active)
	}
}

func handleSOCKS5Conn(c net.Conn, active *atomic.Pointer[tunnel]) {
	defer c.Close()
	buf := make([]byte, 262)

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
	if t == nil {
		writeSOCKS5Reply(c, 0x01)
		return
	}
	remote, err := t.tnet.DialContext(context.Background(), "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		writeSOCKS5Reply(c, 0x05)
		return
	}
	defer remote.Close()
	writeSOCKS5Reply(c, 0x00)

	done := make(chan struct{}, 2)
	go func() { io.Copy(remote, c); done <- struct{}{} }()
	go func() { io.Copy(c, remote); done <- struct{}{} }()
	<-done
}

func writeSOCKS5Reply(c net.Conn, rep byte) {
	c.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}
