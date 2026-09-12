package main

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// daemonState — то, что показываем наружу через /status. Отдельно от
// active, потому что active меняется атомарно и часто, а это — просто
// последний известный результат проверки для наблюдателя.
type daemonState struct {
	mu           sync.Mutex
	lastCheck    time.Time
	lastHealthy  bool
	lastError    string
	lastRaceTook time.Duration
	switchCount  int
}

func (s *daemonState) snapshot() (lastCheck time.Time, healthy bool, lastErr string, raceTook time.Duration, switches int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastCheck, s.lastHealthy, s.lastError, s.lastRaceTook, s.switchCount
}

// daemon — держатель текущего активного туннеля и цикла его проверки.
// Аналог связки quick_warp_check + select_best_endpoint_native + cron из
// bash-версии, но: без внешнего планировщика (свой тикер), без рестартов
// (atomic-подмена указателя) и без последовательного перебора (raceCandidates
// уже параллелит сама).
type daemon struct {
	acct         *account
	active       *atomic.Pointer[tunnel]
	probeTimeout time.Duration
	randomCount  int
	state        daemonState

	// Подменяемые в тестах хуки на реальные сетевые операции — по умолчанию
	// настоящие probeTunnel/raceCandidates, тесты подставляют фейки и не
	// трогают ни сеть, ни WireGuard.
	probeFn    func(ctx context.Context, t *tunnel, timeout time.Duration) (time.Duration, string, error)
	raceFn     func(ctx context.Context, acct *account, endpoints []string, probeTimeout time.Duration) (*tunnel, []raceResult)
	retryDelay time.Duration
	closeGrace time.Duration
}

func newDaemon(acct *account, active *atomic.Pointer[tunnel], probeTimeout time.Duration, randomCount int) *daemon {
	return &daemon{
		acct: acct, active: active, probeTimeout: probeTimeout, randomCount: randomCount,
		probeFn:    probeTunnel,
		raceFn:     raceCandidates,
		retryDelay: 2 * time.Second,
		closeGrace: 10 * time.Second,
	}
}

func (d *daemon) healthLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.checkAndHeal(ctx, false)
		}
	}
}

// checkAndHeal — сердце демона. forceUnhealthy=true пропускает пробу
// текущего endpoint'а и сразу пересканирует; используется ручным /rescan.
func (d *daemon) checkAndHeal(ctx context.Context, forceUnhealthy bool) {
	current := d.active.Load()
	healthy := false
	var lastErr error

	if !forceUnhealthy {
		// Как quick_warp_check с QUICK_CHECK_RETRIES=2: одна случайная
		// заминка не должна разгонять полное пересканирование.
		for attempt := 1; attempt <= 2; attempt++ {
			_, _, err := d.probeFn(ctx, current, d.probeTimeout)
			if err == nil {
				healthy = true
				break
			}
			lastErr = err
			log.Printf("health-check: попытка %d/2 не прошла (%s): %v", attempt, current.endpoint, err)
			if attempt < 2 {
				time.Sleep(d.retryDelay)
			}
		}
	}

	d.state.mu.Lock()
	d.state.lastCheck = time.Now()
	d.state.lastHealthy = healthy
	if lastErr != nil {
		d.state.lastError = lastErr.Error()
	} else {
		d.state.lastError = ""
	}
	d.state.mu.Unlock()

	if healthy {
		log.Printf("health-check: %s всё ещё жив, ничего не трогаю", current.endpoint)
		return
	}

	log.Printf("health-check: %s не отвечает, пересканирую...", current.endpoint)
	candidates := append(knownGoodEndpoints(), randomEndpoints(d.randomCount)...)
	start := time.Now()
	winner, results := d.raceFn(ctx, d.acct, candidates, d.probeTimeout)
	took := time.Since(start)
	logRaceResults(results)

	d.state.mu.Lock()
	d.state.lastRaceTook = took
	d.state.mu.Unlock()

	if winner == nil {
		log.Printf("health-check: рабочий endpoint не найден, оставляю %s как есть", current.endpoint)
		return
	}
	if winner.endpoint == current.endpoint {
		// Тот же адрес переизбрался — но это уже новый, свежепрогретый
		// tunnel/device, так что старый всё равно можно закрыть.
		log.Printf("health-check: %s остаётся лучшим", winner.endpoint)
	}

	old := d.active.Swap(winner)
	d.state.mu.Lock()
	d.state.switchCount++
	d.state.mu.Unlock()
	log.Printf("health-check: переключился на %s (был %s); старый туннель закрою через %s, дав дожить активным соединениям", winner.endpoint, old.endpoint, d.closeGrace)
	go func(old *tunnel) {
		time.Sleep(d.closeGrace)
		old.Close()
	}(old)
}
