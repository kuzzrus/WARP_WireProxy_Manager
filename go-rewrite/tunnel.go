package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// netDialer — то немногое, что нужно от netstack.Net остальному коду.
// Интерфейс, а не конкретный *netstack.Net, специально: тесты SOCKS5 и
// демона подставляют фейковый dialer вместо реального WireGuard-стека.
type netDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// tunnel — один живой WARP-туннель в userspace: своя виртуальная сетевая
// карта (netstack) поверх одного WireGuard-peer'а на конкретном endpoint'е.
// Дёшев в создании и уничтожении — ни TUN-интерфейса, ни прав root, ни
// системных портов, поэтому их можно поднимать пачками для гонки кандидатов.
type tunnel struct {
	endpoint string
	tnet     netDialer
	dev      *device.Device
}

func (t *tunnel) Close() {
	if t != nil && t.dev != nil {
		t.dev.Close()
	}
}

func dialTunnel(acct *account, endpoint string) (*tunnel, error) {
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{acct.addr4, acct.addr6},
		[]netip.Addr{netip.MustParseAddr("1.1.1.1")},
		1280,
	)
	if err != nil {
		return nil, fmt.Errorf("CreateNetTUN: %w", err)
	}
	logger := device.NewLogger(device.LogLevelSilent, "")
	dev := device.NewDevice(tun, conn.NewDefaultBind(), logger)

	uapi := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=25\n",
		acct.privHex, acct.peerPubHex, endpoint,
	)
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("IpcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("dev.Up: %w", err)
	}
	return &tunnel{endpoint: endpoint, tnet: tnet, dev: dev}, nil
}

// probeTunnel — эквивалент quick_warp_check/test_endpoint из bash-версии:
// настоящий HTTP-запрос через сам туннель, а не просто "хендшейк прошёл".
func probeTunnel(ctx context.Context, t *tunnel, timeout time.Duration) (time.Duration, string, error) {
	client := &http.Client{
		Transport: &http.Transport{DialContext: t.tnet.DialContext},
		Timeout:   timeout,
	}
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.cloudflare.com/cdn-cgi/trace", nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return time.Since(start), "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	elapsed := time.Since(start)
	if !bytes.Contains(data, []byte("warp=on")) {
		return elapsed, string(data), fmt.Errorf("warp=on не найден в trace")
	}
	return elapsed, string(data), nil
}

type raceResult struct {
	endpoint string
	elapsed  time.Duration
	trace    string
	err      error
}

// raceCandidates поднимает по одному теневому туннелю НА КАЖДОГО кандидата
// параллельно (горутина на кандидата, никакого "по одному с рестартом", как
// в bash), пробует все и оставляет живым только самый быстрый успешный —
// остальные закрываются. Это то самое параллельное сканирование, которое в
// bash-версии физически невозможно без кучи отдельных процессов.
func raceCandidates(ctx context.Context, acct *account, endpoints []string, probeTimeout time.Duration) (*tunnel, []raceResult) {
	tunnels := make([]*tunnel, len(endpoints))
	results := make([]raceResult, len(endpoints))
	var wg sync.WaitGroup
	for i, ep := range endpoints {
		wg.Add(1)
		go func(i int, ep string) {
			defer wg.Done()
			results[i].endpoint = ep
			t, err := dialTunnel(acct, ep)
			if err != nil {
				results[i].err = err
				return
			}
			elapsed, trace, err := probeTunnel(ctx, t, probeTimeout)
			results[i].elapsed = elapsed
			results[i].trace = trace
			if err != nil {
				results[i].err = err
				t.Close()
				return
			}
			tunnels[i] = t
		}(i, ep)
	}
	wg.Wait()

	bestIdx := pickFastest(results)

	var winner *tunnel
	for i, t := range tunnels {
		if t == nil {
			continue
		}
		if i == bestIdx {
			winner = t
			continue
		}
		t.Close()
	}
	return winner, results
}

// pickFastest — тот же принцип, что и pick_best_line в bash: из успешных
// результатов берём тот, у кого меньше elapsed. Чистая функция без сети —
// именно поэтому тестируется без реальных туннелей.
func pickFastest(results []raceResult) int {
	best := -1
	for i := range results {
		if results[i].err != nil {
			continue
		}
		if best == -1 || results[i].elapsed < results[best].elapsed {
			best = i
		}
	}
	return best
}

func logRaceResults(results []raceResult) {
	for _, r := range results {
		if r.err != nil {
			log.Printf("  %-24s FAIL  %v", r.endpoint, r.err)
			continue
		}
		log.Printf("  %-24s OK    %s", r.endpoint, r.elapsed)
	}
}
