package smartlockserver_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nahtao97/agent-tool-guardrails/internal/smartlockserver"
)

func TestAdapterUnlocksOnlyFixedDemoDeviceOnce(t *testing.T) {
	server := httptest.NewServer(smartlockserver.NewHandler("trusted-lock-credential"))
	t.Cleanup(server.Close)
	trailing := rawUnlock(t, server.URL, `{"device_id":"demo-front-door"}{"device_id":"demo-front-door"}`, "trusted-lock-credential")
	if trailing.StatusCode != http.StatusBadRequest {
		trailing.Body.Close()
		t.Fatalf("trailing JSON status = %d, want %d", trailing.StatusCode, http.StatusBadRequest)
	}
	trailing.Body.Close()

	first := unlock(t, server.URL, "demo-front-door", "trusted-lock-credential")
	defer first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first unlock status = %d, want %d", first.StatusCode, http.StatusOK)
	}
	var state struct {
		DeviceID string `json:"device_id"`
		State    string `json:"state"`
	}
	if err := json.NewDecoder(first.Body).Decode(&state); err != nil || state.DeviceID != "demo-front-door" || state.State != "unlocked" {
		t.Fatalf("decode unlocked state: state=%#v err=%v", state, err)
	}

	if response := unlock(t, server.URL, "demo-front-door", "trusted-lock-credential"); response.StatusCode != http.StatusConflict {
		response.Body.Close()
		t.Fatalf("second transition status = %d, want %d", response.StatusCode, http.StatusConflict)
	} else {
		response.Body.Close()
	}
	if response := unlock(t, server.URL, "garage-door", "trusted-lock-credential"); response.StatusCode != http.StatusBadRequest {
		response.Body.Close()
		t.Fatalf("different device status = %d, want %d", response.StatusCode, http.StatusBadRequest)
	} else {
		response.Body.Close()
	}
	if response := unlock(t, server.URL, "demo-front-door", "wrong-credential"); response.StatusCode != http.StatusUnauthorized {
		response.Body.Close()
		t.Fatalf("untrusted caller status = %d, want %d", response.StatusCode, http.StatusUnauthorized)
	} else {
		response.Body.Close()
	}

	metrics, err := http.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatalf("read smart-lock metrics: %v", err)
	}
	defer metrics.Body.Close()
	var counts struct {
		UnlockCount int `json:"unlock_count"`
	}
	if json.NewDecoder(metrics.Body).Decode(&counts) != nil || counts.UnlockCount != 1 {
		t.Fatalf("unlock_count = %d, want 1", counts.UnlockCount)
	}
}

func unlock(t *testing.T, serverURL, deviceID, credential string) *http.Response {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"device_id": deviceID})
	return rawUnlock(t, serverURL, string(body), credential)
}

func rawUnlock(t *testing.T, serverURL, body, credential string) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, serverURL+"/unlock", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("create unlock request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+credential)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("unlock request: %v", err)
	}
	return response
}
