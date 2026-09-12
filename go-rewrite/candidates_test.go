package main

import (
	"strings"
	"testing"
)

func TestKnownGoodEndpointsNonEmpty(t *testing.T) {
	eps := knownGoodEndpoints()
	if len(eps) == 0 {
		t.Fatal("knownGoodEndpoints пуст")
	}
	for _, ep := range eps {
		if !strings.Contains(ep, ":") {
			t.Fatalf("endpoint %q не похож на host:port", ep)
		}
	}
}

func TestRandomEndpointsCountAndShape(t *testing.T) {
	eps := randomEndpoints(10)
	if len(eps) != 10 {
		t.Fatalf("got %d endpoints, want 10", len(eps))
	}
	for _, ep := range eps {
		host, port, ok := strings.Cut(ep, ":")
		if !ok || host == "" || port == "" {
			t.Fatalf("malformed endpoint %q", ep)
		}
		if len(strings.Split(host, ".")) != 4 {
			t.Fatalf("host %q не похож на IPv4", host)
		}
	}
}

func TestRandomEndpointsZero(t *testing.T) {
	if eps := randomEndpoints(0); len(eps) != 0 {
		t.Fatalf("got %d endpoints, want 0", len(eps))
	}
}
