package main

import (
	"errors"
	"testing"
	"time"
)

func TestPickFastestPicksLowestElapsed(t *testing.T) {
	results := []raceResult{
		{endpoint: "a", elapsed: 500 * time.Millisecond},
		{endpoint: "b", elapsed: 100 * time.Millisecond},
		{endpoint: "c", elapsed: 900 * time.Millisecond},
	}
	if got := pickFastest(results); got != 1 {
		t.Fatalf("got index %d, want 1 (%q)", got, results[1].endpoint)
	}
}

func TestPickFastestSkipsFailed(t *testing.T) {
	results := []raceResult{
		{endpoint: "a", elapsed: 50 * time.Millisecond, err: errors.New("timeout")},
		{endpoint: "b", elapsed: 900 * time.Millisecond},
	}
	if got := pickFastest(results); got != 1 {
		t.Fatalf("got index %d, want 1 (единственный успешный, хоть и медленнее)", got)
	}
}

func TestPickFastestAllFailed(t *testing.T) {
	results := []raceResult{
		{endpoint: "a", err: errors.New("x")},
		{endpoint: "b", err: errors.New("y")},
	}
	if got := pickFastest(results); got != -1 {
		t.Fatalf("got %d, want -1 (ничего не прошло)", got)
	}
}

func TestPickFastestEmpty(t *testing.T) {
	if got := pickFastest(nil); got != -1 {
		t.Fatalf("got %d, want -1 для пустого входа", got)
	}
}

func TestRetiredTunnelWaitsForBorrowedConnection(t *testing.T) {
	tn := &tunnel{endpoint: "old:1"}
	if !tn.Borrow() {
		t.Fatal("fresh tunnel must accept a connection")
	}
	tn.Retire()
	if tn.closed {
		t.Fatal("retired tunnel with an active SOCKS connection must stay open")
	}
	if tn.Borrow() {
		t.Fatal("retired tunnel must not accept new SOCKS connections")
	}
	tn.Release()
	if !tn.closed {
		t.Fatal("retired tunnel must close after its last SOCKS connection")
	}
}
