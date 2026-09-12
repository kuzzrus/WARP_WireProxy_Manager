package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func TestMenuViewShowsStatus(t *testing.T) {
	m := menuModel{
		control: "127.0.0.1:41081",
		status: &statusResponse{
			Version:        "go-v0.1.0",
			ActiveEndpoint: "188.114.96.10:2408",
			LastHealthy:    true,
			SwitchCount:    2,
		},
	}
	view := m.View()
	for _, want := range []string{"go-v0.1.0", "188.114.96.10:2408", "2"} {
		if !strings.Contains(view, want) {
			t.Fatalf("View() не содержит %q:\n%s", want, view)
		}
	}
}

func TestMenuViewShowsUnreachableDaemon(t *testing.T) {
	m := menuModel{control: "127.0.0.1:41081", err: errors.New("connection refused")}
	view := m.View()
	if !strings.Contains(view, "connection refused") {
		t.Fatalf("View() не показал ошибку недоступности демона:\n%s", view)
	}
	if !strings.Contains(view, "warpwp-go serve") {
		t.Fatalf("View() не подсказал, как запустить демон:\n%s", view)
	}
}

func TestMenuUpdateAppliesStatus(t *testing.T) {
	m := menuModel{control: "127.0.0.1:41081", rescanning: true}
	next, _ := m.Update(statusMsg{s: &statusResponse{ActiveEndpoint: "1.2.3.4:2408"}})
	nm := next.(menuModel)
	if nm.rescanning {
		t.Fatal("rescanning должен сброситься после получения statusMsg")
	}
	if nm.status == nil || nm.status.ActiveEndpoint != "1.2.3.4:2408" {
		t.Fatalf("status не применился: %+v", nm.status)
	}
}

func TestMenuUpdateAppliesError(t *testing.T) {
	m := menuModel{control: "127.0.0.1:41081", status: &statusResponse{ActiveEndpoint: "old:1"}}
	next, _ := m.Update(statusMsg{err: errors.New("boom")})
	nm := next.(menuModel)
	if nm.err == nil || nm.err.Error() != "boom" {
		t.Fatalf("err не применился: %v", nm.err)
	}
}

func TestMenuQuitOnQ(t *testing.T) {
	m := menuModel{control: "127.0.0.1:41081"}
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	if cmd == nil {
		t.Fatal("нажатие q должно вернуть команду (tea.Quit)")
	}
	msg := cmd()
	if _, ok := msg.(tea.QuitMsg); !ok {
		t.Fatalf("got %T, want tea.QuitMsg", msg)
	}
}

func TestMenuRescanKeyTriggersOnlyOnce(t *testing.T) {
	m := menuModel{control: "127.0.0.1:41081"}
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
	nm := next.(menuModel)
	if !nm.rescanning {
		t.Fatal("после 'r' должен выставиться rescanning=true")
	}
	if cmd == nil {
		t.Fatal("после 'r' должна вернуться команда rescan")
	}

	// повторное нажатие 'r' во время уже идущего rescan не должно
	// запускать вторую параллельную гонку
	next2, cmd2 := nm.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
	if cmd2 != nil {
		t.Fatal("повторное 'r' во время rescanning не должно порождать новую команду")
	}
	if !next2.(menuModel).rescanning {
		t.Fatal("rescanning должен остаться true")
	}
}

func TestFormatLastCheckZero(t *testing.T) {
	if got := formatLastCheck(time.Time{}); !strings.Contains(got, "не было") {
		t.Fatalf("got %q, want упоминание что проверки ещё не было", got)
	}
}
