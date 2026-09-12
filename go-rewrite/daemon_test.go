package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func newTestDaemon(initial *tunnel) (*daemon, *atomic.Pointer[tunnel]) {
	var active atomic.Pointer[tunnel]
	active.Store(initial)
	d := &daemon{
		acct:         &account{},
		active:       &active,
		probeTimeout: time.Second,
		randomCount:  0,
		retryDelay:   0, // тесты не должны реально спать
		closeGrace:   0,
	}
	return d, &active
}

func TestCheckAndHealHealthyDoesNothing(t *testing.T) {
	current := &tunnel{endpoint: "current:1"}
	d, active := newTestDaemon(current)
	probeCalls := 0
	d.probeFn = func(ctx context.Context, tn *tunnel, timeout time.Duration) (time.Duration, string, error) {
		probeCalls++
		return time.Millisecond, "warp=on", nil
	}
	d.raceFn = func(ctx context.Context, acct *account, endpoints []string, probeTimeout time.Duration) (*tunnel, []raceResult) {
		t.Fatal("raceFn не должен вызываться, если проверка прошла")
		return nil, nil
	}

	d.checkAndHeal(context.Background(), false)

	if probeCalls != 1 {
		t.Fatalf("probeFn вызван %d раз, ожидался 1 (успех с первой попытки)", probeCalls)
	}
	if active.Load() != current {
		t.Fatal("активный туннель не должен был поменяться")
	}
	_, healthy, _, _, switches := d.state.snapshot()
	if !healthy || switches != 0 {
		t.Fatalf("state: healthy=%v switches=%d, want healthy=true switches=0", healthy, switches)
	}
}

func TestCheckAndHealRetriesBeforeGivingUp(t *testing.T) {
	current := &tunnel{endpoint: "current:1"}
	d, _ := newTestDaemon(current)
	probeCalls := 0
	d.probeFn = func(ctx context.Context, tn *tunnel, timeout time.Duration) (time.Duration, string, error) {
		probeCalls++
		if probeCalls == 1 {
			return 0, "", errors.New("transient")
		}
		return time.Millisecond, "warp=on", nil
	}
	d.raceFn = func(ctx context.Context, acct *account, endpoints []string, probeTimeout time.Duration) (*tunnel, []raceResult) {
		t.Fatal("raceFn не должен вызываться — вторая попытка должна была пройти")
		return nil, nil
	}

	d.checkAndHeal(context.Background(), false)

	if probeCalls != 2 {
		t.Fatalf("probeFn вызван %d раз, ожидалось 2 (одна неудача не должна сразу вести к rescan)", probeCalls)
	}
}

func TestCheckAndHealSwapsOnGenuineFailure(t *testing.T) {
	current := &tunnel{endpoint: "current:1"}
	winner := &tunnel{endpoint: "winner:2"}
	d, active := newTestDaemon(current)
	d.probeFn = func(ctx context.Context, tn *tunnel, timeout time.Duration) (time.Duration, string, error) {
		return 0, "", errors.New("dead")
	}
	raceCalled := false
	d.raceFn = func(ctx context.Context, acct *account, endpoints []string, probeTimeout time.Duration) (*tunnel, []raceResult) {
		raceCalled = true
		return winner, []raceResult{{endpoint: winner.endpoint, elapsed: time.Millisecond}}
	}

	d.checkAndHeal(context.Background(), false)

	if !raceCalled {
		t.Fatal("raceFn должен был вызваться после двух неудачных проб")
	}
	if active.Load() != winner {
		t.Fatal("активный туннель должен был переключиться на победителя гонки")
	}
	_, _, _, _, switches := d.state.snapshot()
	if switches != 1 {
		t.Fatalf("switchCount = %d, want 1", switches)
	}
}

func TestCheckAndHealKeepsCurrentWhenRaceFindsNothing(t *testing.T) {
	current := &tunnel{endpoint: "current:1"}
	d, active := newTestDaemon(current)
	d.probeFn = func(ctx context.Context, tn *tunnel, timeout time.Duration) (time.Duration, string, error) {
		return 0, "", errors.New("dead")
	}
	d.raceFn = func(ctx context.Context, acct *account, endpoints []string, probeTimeout time.Duration) (*tunnel, []raceResult) {
		return nil, []raceResult{{endpoint: "a", err: errors.New("also dead")}}
	}

	d.checkAndHeal(context.Background(), false)

	if active.Load() != current {
		t.Fatal("без победителя гонки активный туннель не должен меняться")
	}
	_, _, _, _, switches := d.state.snapshot()
	if switches != 0 {
		t.Fatalf("switchCount = %d, want 0 (менять было не на что)", switches)
	}
}

func TestCheckAndHealForceSkipsProbe(t *testing.T) {
	current := &tunnel{endpoint: "current:1"}
	winner := &tunnel{endpoint: "winner:2"}
	d, active := newTestDaemon(current)
	d.probeFn = func(ctx context.Context, tn *tunnel, timeout time.Duration) (time.Duration, string, error) {
		t.Fatal("forceUnhealthy=true должен пропускать пробу текущего туннеля")
		return 0, "", nil
	}
	d.raceFn = func(ctx context.Context, acct *account, endpoints []string, probeTimeout time.Duration) (*tunnel, []raceResult) {
		return winner, nil
	}

	d.checkAndHeal(context.Background(), true)

	if active.Load() != winner {
		t.Fatal("форсированный rescan должен был переключить на победителя")
	}
}
