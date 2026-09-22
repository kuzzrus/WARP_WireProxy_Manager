package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Опциональная обфускация: не переизобретаем DPI-обход, а оркестрируем уже
// существующий nfqws (проект zapret, https://github.com/bol-van/zapret) —
// ровно та же логика, что и ZAPRET_PORTS/zapret4rocket в bash-версии, только
// сама nftables-очередь и процесс nfqws теперь поднимает и следит за ними
// демон, а не сторонняя ручная настройка.
const (
	nfqwsTableName         = "warpwp_nfqws"
	defaultNfqwsDesyncMark = uint32(0x40000000)
	defaultWarpSocketMark  = uint32(0x20000000)
)

// fakeWireguardInitiationHex — официальный fake-пакет из zapret
// (files/fake/wireguard_initiation.bin), 148 байт — ровно размер настоящего
// WireGuard handshake initiation. nfqws поддерживает такой payload как
// inline-hex через --dpi-desync-fake-wireguard=0x..., поэтому зашиваем его
// прямо в бинарь вместо внешнего файла: --dpi-desync=fake отправляет этот
// пакет-приманку с низким TTL ПЕРЕД настоящим, чтобы DPI на пути (обычно в
// паре хопов от клиента) увидела его и сделала неверные выводы о протоколе,
// а сам пакет умер по TTL раньше, чем дошёл до Cloudflare — настоящий пакет
// идёт следом с обычным TTL и не мутируется вообще.
const fakeWireguardInitiationHex = "01000000053fa03f793219e2b0c19463809a368eca4b075d6b60adafe610b880689c1309c85b51123c40215f01f78c7e6aaf7686d046f6a46702d231751b3707060324bc9e0f84e7b6383807cecbf238dde9df4dc2e9225c590147ce6e4062eb4379fc1fa1f404a262f3d2aec5156fef4422abd6f4ae428ee9f90d8125f00769d504c07e00000000000000000000000000000000"

// defaultNfqwsStrategy — стартовая стратегия под протокол wireguard:
// --filter-l7=wireguard просит nfqws сначала распознать трафик именно как
// WireGuard, --dpi-desync=fake + --dpi-desync-fake-wireguard шлёт поддельный
// handshake initiation ПЕРЕД настоящим пакетом, --dpi-desync-ttl=3 гасит
// подделку через несколько хопов (до Cloudflare она дойти не должна —
// это только приманка для DPI на пути), настоящий пакет при этом не
// модифицируется вообще.
var defaultNfqwsStrategy = fmt.Sprintf(
	"--filter-l7=wireguard --dpi-desync=fake --dpi-desync-fake-wireguard=0x%s --dpi-desync-fwmark=0x%x --dpi-desync-ttl=3 --dpi-desync-repeats=6",
	fakeWireguardInitiationHex, defaultNfqwsDesyncMark,
)

type nfqwsConfig struct {
	bin        string
	queueNum   int
	extraArgs  string
	ports      []int
	desyncMark uint32
	socketMark uint32
}

type nfqwsSupervisor struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func runNft(args ...string) error {
	cmd := exec.Command("nft", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// portSetTokens строит nft-набор портов как отдельные argv-токены —
// { 500, 854, ..., 8886 } — ровно так, как это разбил бы обычный шелл без
// кавычек. nft капризен к тому, как склеены токены набора, поэтому строим
// их явно, а не форматируем одной строкой и не режем по пробелам.
func portSetTokens(ports []int) []string {
	toks := make([]string, 0, len(ports)+2)
	toks = append(toks, "{")
	for i, p := range ports {
		if i < len(ports)-1 {
			toks = append(toks, fmt.Sprintf("%d,", p))
		} else {
			toks = append(toks, fmt.Sprintf("%d", p))
		}
	}
	toks = append(toks, "}")
	return toks
}

func stringSetTokens(values []string) []string {
	toks := make([]string, 0, len(values)+2)
	toks = append(toks, "{")
	for i, value := range values {
		if i < len(values)-1 {
			toks = append(toks, value+",")
		} else {
			toks = append(toks, value)
		}
	}
	toks = append(toks, "}")
	return toks
}

func warpPrefixCIDRs() []string {
	cidrs := make([]string, 0, len(warpPrefixes))
	for _, prefix := range warpPrefixes {
		cidrs = append(cidrs, prefix+".0/24")
	}
	return cidrs
}

func prepareNfqwsArgs(extraArgs string, expectedMark uint32) (string, error) {
	tokens := strings.Fields(extraArgs)
	found := false
	for _, token := range tokens {
		const prefix = "--dpi-desync-fwmark="
		if !strings.HasPrefix(token, prefix) {
			continue
		}
		if found {
			return "", fmt.Errorf("--dpi-desync-fwmark указан больше одного раза")
		}
		value, err := strconv.ParseUint(strings.TrimPrefix(token, prefix), 0, 32)
		if err != nil {
			return "", fmt.Errorf("неверный --dpi-desync-fwmark: %w", err)
		}
		if uint32(value) != expectedMark {
			return "", fmt.Errorf("--dpi-desync-fwmark=0x%x не совпадает с -nfqws-fwmark=0x%x", value, expectedMark)
		}
		found = true
	}
	if !found {
		tokens = append(tokens, fmt.Sprintf("--dpi-desync-fwmark=0x%x", expectedMark))
	}
	return strings.Join(tokens, " "), nil
}

func nfqwsMarkExclusionRuleArgs(cfg nfqwsConfig) []string {
	return []string{
		"add", "rule", "inet", nfqwsTableName, "output",
		"meta", "mark", "&", fmt.Sprintf("0x%x", cfg.desyncMark), "!=", "0", "return",
	}
}

func nfqwsQueueRuleArgs(cfg nfqwsConfig) []string {
	args := []string{
		"add", "rule", "inet", nfqwsTableName, "output",
		"meta", "mark", "&", fmt.Sprintf("0x%x", cfg.socketMark), "!=", "0",
		"ip", "daddr",
	}
	args = append(args, stringSetTokens(warpPrefixCIDRs())...)
	args = append(args, "udp", "dport")
	args = append(args, portSetTokens(cfg.ports)...)
	args = append(args, "queue", "num", fmt.Sprintf("%d", cfg.queueNum), "bypass")
	return args
}

// setupNfqwsQueue создаёт свою изолированную nftables-таблицу. В очередь
// попадают только помеченные сокеты этого WARP-демона, адреса WARP и нужные
// UDP-порты. Fake-пакеты nfqws исключаются по отдельной mark-маске. bypass
// обязателен — если nfqws не запущен или упал, пакеты идут как обычно, а не
// теряются в никуда.
func setupNfqwsQueue(cfg nfqwsConfig) error {
	if err := runNft("add", "table", "inet", nfqwsTableName); err != nil {
		return err
	}
	if err := runNft("add", "chain", "inet", nfqwsTableName, "output",
		"{", "type", "filter", "hook", "output", "priority", "0", ";", "}"); err != nil {
		teardownNfqwsQueue()
		return err
	}
	if err := runNft(nfqwsMarkExclusionRuleArgs(cfg)...); err != nil {
		teardownNfqwsQueue()
		return err
	}
	if err := runNft(nfqwsQueueRuleArgs(cfg)...); err != nil {
		teardownNfqwsQueue()
		return err
	}
	return nil
}

func teardownNfqwsQueue() {
	_ = runNft("delete", "table", "inet", nfqwsTableName)
}

// startNfqws поднимает nftables-очередь и запускает supervise-цикл над самим
// nfqws (перезапуск при падении, как Restart=always у systemd, но локально).
func startNfqws(ctx context.Context, cfg nfqwsConfig) (*nfqwsSupervisor, error) {
	if _, err := exec.LookPath(cfg.bin); err != nil {
		return nil, fmt.Errorf("nfqws бинарник %q не найден в PATH — поставь его: warpwp-go install-nfqws (или вручную из https://github.com/bol-van/zapret): %w", cfg.bin, err)
	}
	preparedArgs, err := prepareNfqwsArgs(cfg.extraArgs, cfg.desyncMark)
	if err != nil {
		return nil, err
	}
	cfg.extraArgs = preparedArgs
	if err := setupNfqwsQueue(cfg); err != nil {
		return nil, fmt.Errorf("nftables: %w", err)
	}
	sctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		superviseNfqws(sctx, cfg)
	}()
	return &nfqwsSupervisor{cancel: cancel, done: done}, nil
}

func (s *nfqwsSupervisor) Stop() {
	s.cancel()
	<-s.done
	teardownNfqwsQueue()
}

func superviseNfqws(ctx context.Context, cfg nfqwsConfig) {
	args := []string{fmt.Sprintf("--qnum=%d", cfg.queueNum)}
	if cfg.extraArgs != "" {
		args = append(args, strings.Fields(cfg.extraArgs)...)
	}
	for ctx.Err() == nil {
		log.Printf("nfqws: запускаю %s %s", cfg.bin, strings.Join(args, " "))
		cmd := exec.CommandContext(ctx, cfg.bin, args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Run()
		if ctx.Err() != nil {
			return
		}
		log.Printf("nfqws: процесс завершился (%v), перезапущу через 3с", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
}
