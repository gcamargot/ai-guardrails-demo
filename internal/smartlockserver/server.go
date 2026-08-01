package smartlockserver

import (
	"crypto/hmac"
	"encoding/json"
	"io"
	"net/http"
	"sync"
)

const demoDeviceID = "demo-front-door"

func NewHandler(expectedCredential string) http.Handler {
	var state struct {
		sync.Mutex
		unlocked    bool
		unlockCount int
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"status":"ready"}`))
	})
	mux.HandleFunc("GET /metrics", func(response http.ResponseWriter, _ *http.Request) {
		state.Lock()
		defer state.Unlock()
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(struct {
			UnlockCount int `json:"unlock_count"`
		}{UnlockCount: state.unlockCount})
	})
	mux.HandleFunc("POST /unlock", func(response http.ResponseWriter, request *http.Request) {
		want := "Bearer " + expectedCredential
		if expectedCredential == "" || !hmac.Equal([]byte(request.Header.Get("Authorization")), []byte(want)) {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		var input struct {
			DeviceID string `json:"device_id"`
		}
		decoder := json.NewDecoder(io.LimitReader(request.Body, 1<<20))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || input.DeviceID != demoDeviceID {
			http.Error(response, "invalid smart-lock transition", http.StatusBadRequest)
			return
		}
		state.Lock()
		defer state.Unlock()
		if state.unlocked {
			http.Error(response, "smart lock is not locked", http.StatusConflict)
			return
		}
		state.unlocked = true
		state.unlockCount++
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(struct {
			DeviceID string `json:"device_id"`
			State    string `json:"state"`
		}{DeviceID: demoDeviceID, State: "unlocked"})
	})
	return mux
}
