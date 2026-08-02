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

func TestMalformedOutputFixtureCanBeEnabledAndRestored(t *testing.T) {
	server := httptest.NewServer(coffeestationserver.NewHandler())
	t.Cleanup(server.Close)

	post := func(path string) {
		response, err := http.Post(server.URL+path, "application/json", nil)
		if err != nil {
			t.Fatalf("toggle malformed fixture: %v", err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("toggle %s returned HTTP %d", path, response.StatusCode)
		}
	}
	post("/test/output/malformed")
	response, err := http.Get(server.URL + "/stations/demo-station/status")
	if err != nil {
		t.Fatalf("get malformed output: %v", err)
	}
	var output map[string]string
	decodeErr := json.NewDecoder(response.Body).Decode(&output)
	response.Body.Close()
	if decodeErr != nil || output["state"] != "compromised" {
		t.Fatalf("malformed output fixture=%#v err=%v", output, decodeErr)
	}
	post("/test/output/valid")
	response, err = http.Get(server.URL + "/stations/demo-station/status")
	if err != nil {
		t.Fatalf("get restored output: %v", err)
	}
	output = map[string]string{}
	decodeErr = json.NewDecoder(response.Body).Decode(&output)
	response.Body.Close()
	if decodeErr != nil || output["state"] != "ready" {
		t.Fatalf("restored output=%#v err=%v", output, decodeErr)
	}
}
