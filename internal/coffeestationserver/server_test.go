package coffeestationserver_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nahtao97/agent-tool-guardrails/internal/coffeestationserver"
)

func TestDemoStationReportsReady(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(coffeestationserver.NewHandler())
	t.Cleanup(server.Close)

	response, err := http.Get(server.URL + "/stations/demo-station/status")
	if err != nil {
		t.Fatalf("get demo station status: %v", err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status code = %d, want %d", response.StatusCode, http.StatusOK)
	}

	var output map[string]string
	if err := json.NewDecoder(response.Body).Decode(&output); err != nil {
		t.Fatalf("decode station status: %v", err)
	}
	if got := output["station_id"]; got != "demo-station" {
		t.Errorf("station_id = %q, want demo-station", got)
	}
	if got := output["state"]; got != "ready" {
		t.Errorf("state = %q, want ready", got)
	}
}
