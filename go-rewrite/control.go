package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"time"
)

// Минимальный контрольный API поверх loopback HTTP — первый набросок того
// самого IPC, которым в реальном проекте CLI (`warpwp status`/`warpwp scan`)
// говорил бы с демоном вместо флоков и файлов конфига.
func serveControl(ln net.Listener, d *daemon) {
	mux := http.NewServeMux()

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		t := d.active.Load()
		lastCheck, healthy, lastErr, raceTook, switches := d.state.snapshot()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":         version,
			"active_endpoint": t.endpoint,
			"last_check":      lastCheck,
			"last_healthy":    healthy,
			"last_error":      lastErr,
			"last_race_took":  raceTook.String(),
			"switch_count":    switches,
		})
	})

	mux.HandleFunc("/rescan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), d.probeTimeout+10*time.Second)
		defer cancel()
		d.checkAndHeal(ctx, true)
		t := d.active.Load()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"active_endpoint": t.endpoint})
	})

	srv := &http.Server{Handler: mux}
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Printf("control: %v", err)
	}
}
