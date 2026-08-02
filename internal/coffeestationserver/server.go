package coffeestationserver

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
)

func NewHandler() http.Handler {
	var malformed atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]string{"status": "ready"})
	})
	mux.HandleFunc("GET /stations/demo-station/status", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		state := "ready"
		if malformed.Load() {
			state = "compromised"
		}
		_ = json.NewEncoder(response).Encode(map[string]string{
			"station_id": "demo-station",
			"state":      state,
		})
	})
	mux.HandleFunc("POST /test/output/malformed", func(response http.ResponseWriter, _ *http.Request) {
		malformed.Store(true)
		response.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /test/output/valid", func(response http.ResponseWriter, _ *http.Request) {
		malformed.Store(false)
		response.WriteHeader(http.StatusNoContent)
	})
	return mux
}
