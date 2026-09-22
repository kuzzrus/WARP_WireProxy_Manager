// Четвёртый срез: персистентный аккаунт (не регистрируем новый WARP-девайс
// на каждый запуск) + подкоманды status/rescan поверх control-API вместо
// голого curl. Демон (serve) — то же самое, что было, плюс -account/-force-register.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// version подставляется на сборке из тега релиза:
// -ldflags "-X main.version=$TAG" (см. .github/workflows/go-release.yml).
// Локальная сборка (go build без ldflags) остаётся "dev".
var version = "dev"

func main() {
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		switch os.Args[1] {
		case "version":
			fmt.Println(version)
			return
		case "status":
			cliStatus(os.Args[2:])
			return
		case "rescan":
			cliRescan(os.Args[2:])
			return
		case "menu":
			runMenu(os.Args[2:])
			return
		case "install-nfqws":
			installNfqws(os.Args[2:])
			return
		case "serve":
			if err := runDaemon(os.Args[2:]); err != nil {
				log.Printf("daemon: %v", err)
				os.Exit(1)
			}
			return
		default:
			log.Fatalf("неизвестная подкоманда %q (ожидалось: serve, status, rescan, menu, install-nfqws, version)", os.Args[1])
		}
	}
	if err := runDaemon(os.Args[1:]); err != nil { // без подкоманды и с флагами сразу — как раньше, для обратной совместимости
		log.Printf("daemon: %v", err)
		os.Exit(1)
	}
}

func runDaemon(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:41080", "куда слушать SOCKS5 (не боевой порт wireproxy!)")
	control := fs.String("control", "127.0.0.1:41081", "куда слушать контрольный HTTP (/status, /rescan)")
	accountPath := fs.String("account", "/etc/wireguard/warpwp-go-account.json", "куда сохранять/откуда переиспользовать WARP-аккаунт")
	forceRegister := fs.Bool("force-register", false, "зарегистрировать новый WARP-аккаунт, даже если сохранённый уже есть")
	randomCount := fs.Int("random", 6, "сколько случайных кандидатов добавлять к заведомо рабочим при (пере)скане")
	probeTimeout := fs.Duration("probe-timeout", 8*time.Second, "таймаут пробы одного кандидата")
	checkInterval := fs.Duration("check-interval", 2*time.Minute, "как часто фоново проверять активный туннель")
	duration := fs.Duration("duration", 0, "0 = работать до SIGINT/SIGTERM; иначе завершиться самостоятельно (удобно для тестов)")
	obfuscate := fs.Bool("obfuscate", false, "опционально: поднять nfqws (zapret) на WARP-портах для обхода DPI на плече VPS-Cloudflare")
	nfqwsBin := fs.String("nfqws-bin", "nfqws", "путь к бинарнику nfqws")
	nfqwsQueue := fs.Int("nfqws-queue", 20000, "номер netfilter queue для nfqws")
	nfqwsFwmark := fs.Uint("nfqws-fwmark", uint(defaultNfqwsDesyncMark), "метка fake-пакетов nfqws (должна совпадать с --dpi-desync-fwmark)")
	warpFwmark := fs.Uint("warp-fwmark", uint(defaultWarpSocketMark), "метка UDP-сокетов этого WARP-демона для точного nft-фильтра")
	nfqwsArgs := fs.String("nfqws-args", defaultNfqwsStrategy, "аргументы стратегии nfqws (это рабочая стартовая точка на fake-пакете под протокол wireguard, подбирается под конкретную DPI)")
	fs.Parse(args)
	if err := validateDaemonNumericOptions(*randomCount, *probeTimeout, *checkInterval, *duration, *nfqwsQueue); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *obfuscate {
		if *nfqwsFwmark == 0 || uint64(*nfqwsFwmark) > uint64(^uint32(0)) {
			return fmt.Errorf("-nfqws-fwmark должен быть ненулевой 32-битной меткой")
		}
		if *warpFwmark == 0 || uint64(*warpFwmark) > uint64(^uint32(0)) {
			return fmt.Errorf("-warp-fwmark должен быть ненулевой 32-битной меткой")
		}
		if uint32(*nfqwsFwmark)&uint32(*warpFwmark) != 0 {
			return fmt.Errorf("-nfqws-fwmark и -warp-fwmark не должны пересекаться по битам")
		}
		warpSocketFwmark.Store(uint32(*warpFwmark))
		sup, err := startNfqws(ctx, nfqwsConfig{
			bin: *nfqwsBin, queueNum: *nfqwsQueue, extraArgs: *nfqwsArgs, ports: warpPorts,
			desyncMark: uint32(*nfqwsFwmark), socketMark: uint32(*warpFwmark),
		})
		if err != nil {
			return fmt.Errorf("-obfuscate включён, но не удалось поднять nfqws: %w", err)
		}
		defer sup.Stop()
		log.Printf("nfqws: обфускация включена, очередь %d, портов %d", *nfqwsQueue, len(warpPorts))
	} else {
		warpSocketFwmark.Store(0)
	}

	acct, err := loadOrRegisterAccount(ctx, *accountPath, *forceRegister)
	if err != nil {
		return err
	}
	log.Printf("аккаунт готов: v4=%s v6=%s", acct.addr4, acct.addr6)

	candidates := append(knownGoodEndpoints(), randomEndpoints(*randomCount)...)
	log.Printf("первичная гонка: %d кандидатов параллельно (таймаут %s)...", len(candidates), *probeTimeout)

	raceCtx, cancelRace := context.WithTimeout(ctx, *probeTimeout+5*time.Second)
	winner, results := raceCandidates(raceCtx, acct, candidates, *probeTimeout)
	cancelRace()
	logRaceResults(results)

	// Пока шла гонка, мог прийти SIGTERM/SIGINT (например, systemctl restart
	// послал его ещё не остановившемуся старому процессу). Без этой проверки
	// умирающий процесс всё равно лез слушать порт и сталкивался с новым
	// экземпляром, который тем временем уже успел его занять.
	if err := ctx.Err(); err != nil {
		log.Printf("получен сигнал остановки во время запуска, выхожу не открывая портов")
		if winner != nil {
			winner.Close()
		}
		return nil
	}
	if winner == nil {
		return fmt.Errorf("ни один кандидат не прошёл проверку, дальше запускаться некуда")
	}
	log.Printf("победитель первичной гонки: %s", winner.endpoint)

	var active atomic.Pointer[tunnel]
	active.Store(winner)

	d := newDaemon(acct, &active, *probeTimeout, *randomCount)

	socksLn, err := listenWithRetry(ctx, *listen)
	if err != nil {
		return fmt.Errorf("не удалось слушать SOCKS5 на %s: %w", *listen, err)
	}
	defer socksLn.Close()
	go serveSOCKS5(ctx, socksLn, &active)

	controlLn, err := listenWithRetry(ctx, *control)
	if err != nil {
		return fmt.Errorf("не удалось слушать control на %s: %w", *control, err)
	}
	defer controlLn.Close()
	go serveControl(controlLn, d)

	go d.healthLoop(ctx, *checkInterval)

	log.Printf("демон работает: SOCKS5 %s, control %s, health-check каждые %s", *listen, *control, *checkInterval)
	log.Printf("curl -x socks5h://%s https://www.cloudflare.com/cdn-cgi/trace", *listen)

	if *duration > 0 {
		select {
		case <-ctx.Done():
		case <-time.After(*duration):
			log.Printf("истёк -duration, завершаюсь")
		}
	} else {
		<-ctx.Done()
		log.Printf("получен сигнал остановки")
	}

	log.Printf("закрываю активный туннель и выхожу")
	active.Load().Close()
	return nil
}

func validateDaemonNumericOptions(randomCount int, probeTimeout, checkInterval, duration time.Duration, nfqwsQueue int) error {
	if randomCount < 0 || randomCount > 256 {
		return fmt.Errorf("-random должен быть в диапазоне 0..256 (получено %d)", randomCount)
	}
	if probeTimeout < 100*time.Millisecond || probeTimeout > 5*time.Minute {
		return fmt.Errorf("-probe-timeout должен быть в диапазоне 100ms..5m (получено %s)", probeTimeout)
	}
	if checkInterval < time.Second || checkInterval > 24*time.Hour {
		return fmt.Errorf("-check-interval должен быть в диапазоне 1s..24h (получено %s)", checkInterval)
	}
	if duration < 0 {
		return fmt.Errorf("-duration не может быть отрицательным (получено %s)", duration)
	}
	if nfqwsQueue < 0 || nfqwsQueue > 65535 {
		return fmt.Errorf("-nfqws-queue должен быть в диапазоне 0..65535 (получено %d)", nfqwsQueue)
	}
	return nil
}

// listenWithRetry — защита от гонки на systemctl restart: старый процесс ещё
// не успел освободить порт, когда новый уже пытается его занять. Несколько
// коротких попыток вместо мгновенного отказа.
func listenWithRetry(ctx context.Context, addr string) (net.Listener, error) {
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			return ln, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	return nil, lastErr
}

func cliStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	control := fs.String("control", "127.0.0.1:41081", "адрес control API демона")
	fs.Parse(args)
	printControlJSON(fmt.Sprintf("http://%s/status", *control), http.MethodGet)
}

func cliRescan(args []string) {
	fs := flag.NewFlagSet("rescan", flag.ExitOnError)
	control := fs.String("control", "127.0.0.1:41081", "адрес control API демона")
	fs.Parse(args)
	printControlJSON(fmt.Sprintf("http://%s/rescan", *control), http.MethodPost)
}

func printControlJSON(url, method string) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		log.Fatalf("%v", err)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("не достучался до демона (%s): %v", url, err)
	}
	defer resp.Body.Close()
	var v map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		log.Fatalf("плохой ответ демона: %v", err)
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}
