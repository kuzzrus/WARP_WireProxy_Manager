package main

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDialer подставляется вместо netstack.Net — тест никогда не трогает
// реальную сеть или WireGuard.
type fakeDialer struct {
	conn net.Conn
	err  error
}

func (f *fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.conn, nil
}

func TestSOCKS5ConnectAndRelay(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	remoteClientSide, remoteServerSide := net.Pipe()
	defer remoteClientSide.Close()

	var active atomic.Pointer[tunnel]
	active.Store(&tunnel{endpoint: "fake:1", tnet: &fakeDialer{conn: remoteServerSide}})

	go handleSOCKS5Conn(serverSide, &active)

	if _, err := clientSide.Write([]byte{0x05, 0x01, 0x00}); err != nil { // VER, NMETHODS, NO-AUTH
		t.Fatal(err)
	}
	methodResp := make([]byte, 2)
	if _, err := io.ReadFull(clientSide, methodResp); err != nil {
		t.Fatal(err)
	}
	if methodResp[0] != 0x05 || methodResp[1] != 0x00 {
		t.Fatalf("method negotiation: got % x, want [05 00]", methodResp)
	}

	// CONNECT 93.184.216.34:80 (IPv4)
	req := []byte{0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x00, 0x50}
	if _, err := clientSide.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(clientSide, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("CONNECT reply REP = 0x%02x, want 0x00 (succeeded)", reply[1])
	}

	if _, err := clientSide.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	remoteClientSide.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(remoteClientSide, got); err != nil {
		t.Fatalf("payload не дошёл до \"удалённой\" стороны: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("got %q, want %q", got, "ping")
	}
}

func TestSOCKS5RejectsNonConnect(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	var active atomic.Pointer[tunnel]
	go handleSOCKS5Conn(serverSide, &active)

	clientSide.Write([]byte{0x05, 0x01, 0x00})
	io.ReadFull(clientSide, make([]byte, 2))

	// При неподдерживаемой команде сервер читает только 4-байтный заголовок
	// и сразу отвечает, не дожидаясь остатка запроса — net.Pipe синхронный
	// и без буфера, поэтому лишние байты в этом же Write привели бы к
	// вечной блокировке. Пишем ровно то, что сервер реально прочитает.
	clientSide.Write([]byte{0x05, 0x02, 0x00, 0x01}) // CMD=BIND, не поддерживается
	reply := make([]byte, 10)
	if _, err := io.ReadFull(clientSide, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0x07 {
		t.Fatalf("REP = 0x%02x, want 0x07 (command not supported)", reply[1])
	}
}

func TestSOCKS5NoActiveTunnel(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	var active atomic.Pointer[tunnel] // ничего не Store — активного туннеля нет

	go handleSOCKS5Conn(serverSide, &active)

	clientSide.Write([]byte{0x05, 0x01, 0x00})
	io.ReadFull(clientSide, make([]byte, 2))
	clientSide.Write([]byte{0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(clientSide, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0x01 {
		t.Fatalf("REP = 0x%02x, want 0x01 (general failure, нет активного туннеля)", reply[1])
	}
}

func TestSOCKS5DialFailure(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	var active atomic.Pointer[tunnel]
	active.Store(&tunnel{endpoint: "fake:1", tnet: &fakeDialer{err: errTestDial}})

	go handleSOCKS5Conn(serverSide, &active)

	clientSide.Write([]byte{0x05, 0x01, 0x00})
	io.ReadFull(clientSide, make([]byte, 2))
	clientSide.Write([]byte{0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(clientSide, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0x05 {
		t.Fatalf("REP = 0x%02x, want 0x05 (connection refused)", reply[1])
	}
}

var errTestDial = &net.OpError{Op: "dial", Err: net.ErrClosed}
