package main

import (
	"strings"
	"testing"
	"time"
)

func TestValidateDaemonNumericOptions(t *testing.T) {
	tests := []struct {
		name          string
		random        int
		probe         time.Duration
		check         time.Duration
		duration      time.Duration
		queue         int
		wantErrSubstr string
	}{
		{name: "valid", random: 6, probe: 8 * time.Second, check: 2 * time.Minute, queue: 20000},
		{name: "negative random", random: -1, probe: time.Second, check: time.Minute, queue: 1, wantErrSubstr: "-random"},
		{name: "excessive random", random: 257, probe: time.Second, check: time.Minute, queue: 1, wantErrSubstr: "-random"},
		{name: "zero probe", random: 1, check: time.Minute, queue: 1, wantErrSubstr: "-probe-timeout"},
		{name: "fast check loop", random: 1, probe: time.Second, check: time.Millisecond, queue: 1, wantErrSubstr: "-check-interval"},
		{name: "negative duration", random: 1, probe: time.Second, check: time.Minute, duration: -time.Second, queue: 1, wantErrSubstr: "-duration"},
		{name: "bad queue", random: 1, probe: time.Second, check: time.Minute, queue: 65536, wantErrSubstr: "-nfqws-queue"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDaemonNumericOptions(tc.random, tc.probe, tc.check, tc.duration, tc.queue)
			if tc.wantErrSubstr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErrSubstr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErrSubstr)) {
				t.Fatalf("error = %v, want substring %q", err, tc.wantErrSubstr)
			}
		})
	}
}

func TestRunDaemonRejectsInvalidNumericFlagsBeforeStartup(t *testing.T) {
	for _, args := range [][]string{
		{"-random=-1"},
		{"-random=1000000"},
		{"-probe-timeout=0"},
		{"-check-interval=0"},
		{"-duration=-1s"},
		{"-nfqws-queue=65536"},
	} {
		if err := runDaemon(args); err == nil {
			t.Fatalf("runDaemon(%q) unexpectedly accepted invalid values", args)
		}
	}
}
