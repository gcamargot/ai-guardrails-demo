package smartlockserver

import (
	"crypto/hmac"
	"encoding/json"
	"io"
	"net/http"
	"sync"

	"github.com/nahtao97/agent-tool-guardrails/internal/smartlock"
)

func NewHandler(expectedCredential string) http.Handler {
	return NewDemoHandler(expectedCredential, "")
}

// NewDemoHandler adds a credential-bound reset control for the isolated talk fixture.
func NewDemoHandler(expectedCredential, resetCredential string) http.Handler {
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
			State       smartlock.StateName `json:"state"`
			UnlockCount int                 `json:"unlock_count"`
		}{State: lockState(state.unlocked), UnlockCount: state.unlockCount})
	})
	mux.HandleFunc("POST /test/reset", func(response http.ResponseWriter, request *http.Request) {
		want := "Bearer " + resetCredential
		if resetCredential == "" || !hmac.Equal([]byte(request.Header.Get("Authorization")), []byte(want)) {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		state.Lock()
		state.unlocked = false
		state.unlockCount = 0
		state.Unlock()
		response.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /unlock", func(response http.ResponseWriter, request *http.Request) {
		want := "Bearer " + expectedCredential
		if expectedCredential == "" || !hmac.Equal([]byte(request.Header.Get("Authorization")), []byte(want)) {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		var input smartlock.Arguments
		decoder := json.NewDecoder(io.LimitReader(request.Body, 1<<20))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF || input.DeviceID != smartlock.DemoDeviceID {
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
		_ = json.NewEncoder(response).Encode(smartlock.State{DeviceID: smartlock.DemoDeviceID, State: smartlock.StateUnlocked})
	})
	return mux
}

func lockState(unlocked bool) smartlock.StateName {
	if unlocked {
		return smartlock.StateUnlocked
	}
	return smartlock.StateLocked
}
