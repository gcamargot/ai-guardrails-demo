package calendarserver_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nahtao97/agent-tool-guardrails/internal/calendarserver"
	"github.com/nahtao97/agent-tool-guardrails/internal/meeting"
)

func TestApprovedRequestRetriesCreateAtMostOneCalendarEvent(t *testing.T) {
	server := httptest.NewServer(calendarserver.NewHandler("calendar-credential"))
	t.Cleanup(server.Close)
	arguments := meeting.EventArguments{
		ProposalID: "proposal-1", Start: "2026-08-03T13:00:00Z", End: "2026-08-03T13:30:00Z",
		RequesterSubject: "external-alice-subject-id", Reason: "Platform sync", Contact: "alice@example.invalid",
		IdempotencyKey: "meeting-proposal:proposal-1",
	}
	first := createEvent(t, server, arguments)
	second := createEvent(t, server, arguments)
	if first.EventID != "demo-event-1" || !first.Created || second.EventID != first.EventID || second.Created {
		t.Fatalf("first=%#v second=%#v", first, second)
	}
	response, err := http.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatalf("read calendar effect count: %v", err)
	}
	defer response.Body.Close()
	var stats struct {
		EventCount int `json:"event_count"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&stats) != nil || stats.EventCount != 1 {
		t.Fatalf("calendar stats status=%d body=%#v", response.StatusCode, stats)
	}
}

func createEvent(t *testing.T, server *httptest.Server, arguments meeting.EventArguments) meeting.Event {
	t.Helper()
	body, _ := json.Marshal(arguments)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/events", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create event request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer calendar-credential")
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("create synthetic event: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		t.Fatalf("create event status = %d", response.StatusCode)
	}
	var event meeting.Event
	if err := json.NewDecoder(response.Body).Decode(&event); err != nil {
		t.Fatalf("decode synthetic event: %v", err)
	}
	return event
}
