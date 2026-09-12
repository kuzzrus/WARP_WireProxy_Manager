package main

import "testing"

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
