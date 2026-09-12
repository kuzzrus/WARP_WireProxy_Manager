package main

import (
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGenKeyPairClamping(t *testing.T) {
	priv, pub := genKeyPair()
	if priv[0]&0x07 != 0 {
		t.Fatalf("младшие 3 бита private key не обнулены: %08b", priv[0])
	}
	if priv[31]&0x80 != 0 {
		t.Fatalf("старший бит private key не обнулён: %08b", priv[31])
	}
	if priv[31]&0x40 == 0 {
		t.Fatalf("бит 6 private key не установлен: %08b", priv[31])
	}
	if pub == ([32]byte{}) {
		t.Fatal("публичный ключ нулевой — ScalarBaseMult не отработал")
	}
}

func TestB64KeyToHexRoundTrip(t *testing.T) {
	const b64 = "bmXOC+F1QSPGQ2ObwTOu6NWKSLW89kykyGw4RrHkGOU="
	got, err := b64KeyToHex(b64)
	if err != nil {
		t.Fatalf("b64KeyToHex: %v", err)
	}
	if len(got) != 64 {
		t.Fatalf("got hex length %d, want 64: %q", len(got), got)
	}
}

func TestB64KeyToHexRejectsBadInput(t *testing.T) {
	for _, bad := range []string{"", "not-base64!!!", "aGVsbG8="} { // "hello" - неверная длина ключа
		if _, err := b64KeyToHex(bad); err == nil {
			t.Fatalf("b64KeyToHex(%q) должен был вернуть ошибку", bad)
		}
	}
}

func TestAccountPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "account.json")

	priv, pub := genKeyPair()
	orig := &account{
		privHex:    hex.EncodeToString(priv[:]),
		peerPubHex: hex.EncodeToString(pub[:]),
		addr4:      netip.MustParseAddr("172.16.0.2"),
		addr6:      netip.MustParseAddr("2606:4700:110::2"),
	}
	if err := saveAccount(path, orig); err != nil {
		t.Fatalf("saveAccount: %v", err)
	}
	// NTFS не выражает POSIX-биты владельца так же, как Linux (реальная
	// цель деплоя) — там 0600 уже подтверждён живым тестом на VPS.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("got perms %v, want 0600", info.Mode().Perm())
		}
	}

	loaded, err := loadAccount(path)
	if err != nil {
		t.Fatalf("loadAccount: %v", err)
	}
	if loaded.privHex != orig.privHex || loaded.peerPubHex != orig.peerPubHex {
		t.Fatalf("round-trip ключей не совпал: got %+v, want %+v", loaded, orig)
	}
	if loaded.addr4 != orig.addr4 || loaded.addr6 != orig.addr6 {
		t.Fatalf("round-trip адресов не совпал: got v4=%s v6=%s, want v4=%s v6=%s",
			loaded.addr4, loaded.addr6, orig.addr4, orig.addr6)
	}
}

func TestLoadAccountRejectsCorrupted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`{"private_key_hex":"tooshort"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAccount(path); err == nil {
		t.Fatal("loadAccount должен был отклонить повреждённый файл")
	}
}

func TestLoadAccountMissingFile(t *testing.T) {
	if _, err := loadAccount(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("loadAccount должен был вернуть ошибку для несуществующего файла")
	}
}

// Сеть здесь не нужна: файл уже есть и валиден, поэтому loadOrRegisterAccount
// обязан взять его, а не пытаться зарегистрировать новый через Cloudflare.
func TestLoadOrRegisterAccountReusesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "account.json")
	priv, pub := genKeyPair()
	seed := &account{
		privHex:    hex.EncodeToString(priv[:]),
		peerPubHex: hex.EncodeToString(pub[:]),
		addr4:      netip.MustParseAddr("172.16.0.5"),
		addr6:      netip.MustParseAddr("2606:4700:110::5"),
	}
	if err := saveAccount(path, seed); err != nil {
		t.Fatal(err)
	}
	got, err := loadOrRegisterAccount(path, false)
	if err != nil {
		t.Fatalf("loadOrRegisterAccount: %v", err)
	}
	if got.privHex != seed.privHex {
		t.Fatal("должен был переиспользовать существующий аккаунт, а не создать новый")
	}
}
