package main

import (
	"strings"
	"testing"
)

func TestPortSetTokens(t *testing.T) {
	toks := portSetTokens([]int{500, 854, 2408})
	want := []string{"{", "500,", "854,", "2408", "}"}
	if len(toks) != len(want) {
		t.Fatalf("got %d tokens, want %d: %q", len(toks), len(want), toks)
	}
	for i := range want {
		if toks[i] != want[i] {
			t.Fatalf("token %d: got %q, want %q (full: %q)", i, toks[i], want[i], toks)
		}
	}
}

func TestPortSetTokensSingle(t *testing.T) {
	toks := portSetTokens([]int{2408})
	want := []string{"{", "2408", "}"}
	if len(toks) != len(want) || toks[1] != "2408" {
		t.Fatalf("got %q, want %q", toks, want)
	}
}

func TestPrepareNfqwsArgsPinsCompatibleFwmark(t *testing.T) {
	got, err := prepareNfqwsArgs("--filter-l7=wireguard", defaultNfqwsDesyncMark)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "--dpi-desync-fwmark=0x40000000") {
		t.Fatalf("prepared args missing explicit fwmark: %q", got)
	}

	if _, err := prepareNfqwsArgs("--dpi-desync-fwmark=0x1", defaultNfqwsDesyncMark); err == nil {
		t.Fatal("mismatched user fwmark must be rejected")
	}
	if _, err := prepareNfqwsArgs("--dpi-desync-fwmark=0x40000000 --dpi-desync-fwmark=0x40000000", defaultNfqwsDesyncMark); err == nil {
		t.Fatal("duplicate user fwmark must be rejected")
	}
}

func TestNfqwsRulesScopeQueueAndExcludeGeneratedPackets(t *testing.T) {
	cfg := nfqwsConfig{
		queueNum: 20000, ports: []int{2408},
		desyncMark: defaultNfqwsDesyncMark, socketMark: defaultWarpSocketMark,
	}
	exclusion := strings.Join(nfqwsMarkExclusionRuleArgs(cfg), " ")
	if !strings.Contains(exclusion, "meta mark & 0x40000000 != 0 return") {
		t.Fatalf("fake-packet exclusion is missing: %s", exclusion)
	}

	queue := strings.Join(nfqwsQueueRuleArgs(cfg), " ")
	for _, required := range []string{
		"meta mark & 0x20000000 != 0",
		"ip daddr {",
		"162.159.192.0/24",
		"udp dport { 2408 }",
		"queue num 20000 bypass",
	} {
		if !strings.Contains(queue, required) {
			t.Fatalf("queue rule missing %q: %s", required, queue)
		}
	}
}
