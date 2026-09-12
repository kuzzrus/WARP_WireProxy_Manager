package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Тонкий TUI-клиент поверх control API — ровно то же самое, что делает
// `warpwp-go status`/`rescan`, только живьём и с автообновлением. Демон он
// не запускает и не встраивает: архитектура и так разделяет "демон — это
// сервис" и "клиент — тонкая обвязка сверху", меню просто ещё один такой
// клиент, как и CLI-подкоманды.
type statusResponse struct {
	Version        string    `json:"version"`
	ActiveEndpoint string    `json:"active_endpoint"`
	LastCheck      time.Time `json:"last_check"`
	LastHealthy    bool      `json:"last_healthy"`
	LastError      string    `json:"last_error"`
	LastRaceTook   string    `json:"last_race_took"`
	SwitchCount    int       `json:"switch_count"`
}

func fetchControlJSON(url, method string) (*statusResponse, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var s statusResponse
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

var (
	styleTitle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	styleOK    = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	styleBad   = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	styleDim   = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	styleLabel = lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Width(16)
	styleBox   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1).BorderForeground(lipgloss.Color("240"))
)

type statusMsg struct {
	s   *statusResponse
	err error
}

type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(3*time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func fetchCmd(control string) tea.Cmd {
	return func() tea.Msg {
		s, err := fetchControlJSON(fmt.Sprintf("http://%s/status", control), http.MethodGet)
		return statusMsg{s, err}
	}
}

func rescanCmd(control string) tea.Cmd {
	return func() tea.Msg {
		s, err := fetchControlJSON(fmt.Sprintf("http://%s/rescan", control), http.MethodPost)
		return statusMsg{s, err}
	}
}

type menuModel struct {
	control    string
	status     *statusResponse
	err        error
	rescanning bool
	updatedAt  time.Time
}

func (m menuModel) Init() tea.Cmd {
	return tea.Batch(fetchCmd(m.control), tickCmd())
}

func (m menuModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "r":
			if m.rescanning {
				return m, nil
			}
			m.rescanning = true
			return m, rescanCmd(m.control)
		}
	case tickMsg:
		return m, tea.Batch(fetchCmd(m.control), tickCmd())
	case statusMsg:
		m.rescanning = false
		m.updatedAt = time.Now()
		if msg.err != nil {
			m.err = msg.err
		} else {
			m.err = nil
			m.status = msg.s
		}
	}
	return m, nil
}

func (m menuModel) View() string {
	title := styleTitle.Render("warpwp-go — панель управления")
	target := styleDim.Render(fmt.Sprintf("control: %s", m.control))

	var body string
	switch {
	case m.err != nil:
		body = styleBox.Render(styleBad.Render("Демон недоступен: "+m.err.Error()) + "\n" +
			styleDim.Render("Запусти его: warpwp-go serve -control "+m.control))
	case m.status == nil:
		body = styleBox.Render(styleDim.Render("Загрузка..."))
	default:
		s := m.status
		healthLine := styleOK.Render("работает")
		if !s.LastHealthy {
			healthLine = styleBad.Render("проверка не прошла")
		}
		rows := []string{
			styleLabel.Render("Версия:") + s.Version,
			styleLabel.Render("Endpoint:") + s.ActiveEndpoint,
			styleLabel.Render("Статус:") + healthLine,
			styleLabel.Render("Проверка:") + formatLastCheck(s.LastCheck),
			styleLabel.Render("Переключений:") + fmt.Sprintf("%d", s.SwitchCount),
		}
		if s.LastRaceTook != "" && s.LastRaceTook != "0s" {
			rows = append(rows, styleLabel.Render("Гонка заняла:")+s.LastRaceTook)
		}
		if s.LastError != "" {
			rows = append(rows, styleLabel.Render("Посл. ошибка:")+styleBad.Render(s.LastError))
		}
		body = styleBox.Render(joinRows(rows))
	}

	action := styleDim.Render("[r] пересканировать   [q] выход")
	if m.rescanning {
		action = styleOK.Render("пересканирую...")
	}

	return title + "\n" + target + "\n\n" + body + "\n\n" + action + "\n"
}

func formatLastCheck(t time.Time) string {
	if t.IsZero() {
		return styleDim.Render("ещё не было")
	}
	return fmt.Sprintf("%s назад", time.Since(t).Round(time.Second))
}

func joinRows(rows []string) string {
	out := ""
	for i, r := range rows {
		if i > 0 {
			out += "\n"
		}
		out += r
	}
	return out
}

func runMenu(args []string) {
	fs := flag.NewFlagSet("menu", flag.ExitOnError)
	control := fs.String("control", "127.0.0.1:41081", "адрес control API демона")
	fs.Parse(args)

	p := tea.NewProgram(menuModel{control: *control})
	if _, err := p.Run(); err != nil {
		fmt.Println("ошибка TUI:", err)
	}
}
