package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/curve25519"
)

const (
	warpRegistrationURL     = "https://api.cloudflareclient.com/v0a2158/reg"
	warpRegistrationTimeout = 30 * time.Second
	maxRegistrationBody     = 1 << 20
)

// account — данные одного зарегистрированного WARP-аккаунта: свой ключ плюс
// то, что вернул Cloudflare (адреса интерфейса и публичный ключ peer'а).
// Один account используется для гонки любого числа endpoint'ов — peer и
// адреса не меняются, меняется только Endpoint при подъёме туннеля.
type account struct {
	privHex    string
	peerPubHex string
	addr4      netip.Addr
	addr6      netip.Addr
}

func genKeyPair() (priv, pub [32]byte) {
	if _, err := rand.Read(priv[:]); err != nil {
		panic(fmt.Sprintf("rand.Read: %v", err))
	}
	// Стандартное WireGuard-клэмпирование curve25519-ключа.
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	curve25519.ScalarBaseMult(&pub, &priv)
	return
}

type regResponse struct {
	ID     string `json:"id"`
	Config struct {
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				Host string `json:"host"`
			} `json:"endpoint"`
		} `json:"peers"`
	} `json:"config"`
}

func registerWarpAccount(ctx context.Context, pub [32]byte) (*regResponse, error) {
	body, _ := json.Marshal(map[string]string{
		"key":        base64.StdEncoding.EncodeToString(pub[:]),
		"install_id": "",
		"fcm_token":  "",
		"tos":        time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"type":       "Android",
		"model":      "PC",
		"locale":     "en_US",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, warpRegistrationURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	req.Header.Set("CF-Client-Version", "a-6.11-2223")
	client := &http.Client{Timeout: warpRegistrationTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRegistrationBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("cloudflare reg: HTTP %d: %s", resp.StatusCode, data)
	}
	var out regResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("decode reg response: %w (body=%s)", err, data)
	}
	return &out, nil
}

func b64KeyToHex(b64key string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64key)
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("unexpected key length %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// newAccount регистрирует свежий временный WARP-аккаунт через настоящий
// Cloudflare API — ровно тот же вызов, что и в bash-версии.
func newAccount(ctx context.Context) (*account, error) {
	priv, pub := genKeyPair()
	reg, err := registerWarpAccount(ctx, pub)
	if err != nil {
		return nil, fmt.Errorf("регистрация WARP: %w", err)
	}
	if len(reg.Config.Peers) == 0 {
		return nil, fmt.Errorf("Cloudflare не вернул ни одного peer'а")
	}
	peerPubHex, err := b64KeyToHex(reg.Config.Peers[0].PublicKey)
	if err != nil {
		return nil, fmt.Errorf("публичный ключ peer'а: %w", err)
	}
	acct := &account{
		privHex:    hex.EncodeToString(priv[:]),
		peerPubHex: peerPubHex,
	}
	var errAddr error
	acct.addr4, errAddr = netip.ParseAddr(reg.Config.Interface.Addresses.V4)
	if errAddr != nil {
		return nil, fmt.Errorf("bad v4 addr: %w", errAddr)
	}
	acct.addr6, errAddr = netip.ParseAddr(reg.Config.Interface.Addresses.V6)
	if errAddr != nil {
		return nil, fmt.Errorf("bad v6 addr: %w", errAddr)
	}
	if err := validateAccount(acct); err != nil {
		return nil, err
	}
	return acct, nil
}

// accountFile — то же самое, что account, но в виде, пригодном для JSON:
// netip.Addr там сериализуется как объект, а не как строка, поэтому храним
// адреса отдельно строками. Отдельный файл от bash-проекта (не
// warp-account.json/warp-private.key) — это независимый WARP-девайс своего
// прототипа, мешать его с боевым аккаунтом не нужно.
type accountFile struct {
	PrivateKeyHex    string    `json:"private_key_hex"`
	PeerPublicKeyHex string    `json:"peer_public_key_hex"`
	AddressV4        string    `json:"address_v4"`
	AddressV6        string    `json:"address_v6"`
	RegisteredAt     time.Time `json:"registered_at"`
}

func loadAccount(path string) (*account, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var af accountFile
	if err := json.Unmarshal(data, &af); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	addr4, err := netip.ParseAddr(af.AddressV4)
	if err != nil {
		return nil, fmt.Errorf("%s: bad address_v4: %w", path, err)
	}
	addr6, err := netip.ParseAddr(af.AddressV6)
	if err != nil {
		return nil, fmt.Errorf("%s: bad address_v6: %w", path, err)
	}
	acct := &account{
		privHex:    af.PrivateKeyHex,
		peerPubHex: af.PeerPublicKeyHex,
		addr4:      addr4,
		addr6:      addr6,
	}
	if err := validateAccount(acct); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return acct, nil
}

func validateAccount(acct *account) error {
	if acct == nil {
		return errors.New("пустой WARP account")
	}
	for name, key := range map[string]string{"private key": acct.privHex, "peer public key": acct.peerPubHex} {
		raw, err := hex.DecodeString(key)
		if err != nil || len(raw) != 32 {
			return fmt.Errorf("некорректный %s", name)
		}
	}
	if !acct.addr4.Is4() || acct.addr4.IsUnspecified() || acct.addr4.IsMulticast() {
		return errors.New("некорректный IPv4-адрес WARP")
	}
	if !acct.addr6.Is6() || acct.addr6.Is4In6() || acct.addr6.IsUnspecified() || acct.addr6.IsMulticast() {
		return errors.New("некорректный IPv6-адрес WARP")
	}
	return nil
}

func saveAccount(path string, acct *account) error {
	af := accountFile{
		PrivateKeyHex:    acct.privHex,
		PeerPublicKeyHex: acct.peerPubHex,
		AddressV4:        acct.addr4.String(),
		AddressV6:        acct.addr6.String(),
		RegisteredAt:     time.Now().UTC(),
	}
	data, err := json.MarshalIndent(af, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".warpwp-go-account.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		defer d.Close()
		_ = d.Sync() // not supported on every filesystem, but rename is already atomic
	}
	return nil
}

// loadOrRegisterAccount — как register_warp_account в bash: переиспользует
// сохранённый аккаунт, если он есть и валиден, иначе регистрирует новый и
// сохраняет. force=true всегда регистрирует заново (аналог --force-register).
func loadOrRegisterAccount(ctx context.Context, path string, force bool) (*account, error) {
	if !force {
		if acct, err := loadAccount(path); err == nil {
			log.Printf("переиспользую сохранённый WARP-аккаунт: %s", path)
			return acct, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("не могу безопасно прочитать account %s: %w", path, err)
		}
	}
	log.Printf("регистрирую новый WARP-аккаунт...")
	acct, err := newAccount(ctx)
	if err != nil {
		return nil, err
	}
	if err := saveAccount(path, acct); err != nil {
		return nil, fmt.Errorf("не удалось сохранить account в %s: %w", path, err)
	}
	log.Printf("аккаунт сохранён: %s", path)
	return acct, nil
}
