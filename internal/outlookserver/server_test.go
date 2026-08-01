package outlookserver_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nahtao97/agent-tool-guardrails/internal/outlook"
	"github.com/nahtao97/agent-tool-guardrails/internal/outlookserver"
)

func TestDemoOutlookIsReadOnlyAndMinimizesUntrustedContent(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(outlookserver.NewHandler("demo-outlook-credential"))
	t.Cleanup(server.Close)

	search := authorizedRequest(t, http.MethodGet, server.URL+"/messages/search?query=Project+Phoenix&limit=5")
	searchResponse, err := http.DefaultClient.Do(search)
	if err != nil {
		t.Fatalf("search demo Outlook: %v", err)
	}
	defer searchResponse.Body.Close()
	var searchView struct {
		Messages []outlook.SearchResult `json:"messages"`
	}
	if searchResponse.StatusCode != http.StatusOK || json.NewDecoder(searchResponse.Body).Decode(&searchView) != nil || len(searchView.Messages) != 1 {
		t.Fatalf("search status=%d view=%#v", searchResponse.StatusCode, searchView)
	}

	read := authorizedRequest(t, http.MethodGet, server.URL+"/messages/demo-injection-message")
	readResponse, err := http.DefaultClient.Do(read)
	if err != nil {
		t.Fatalf("read demo Outlook message: %v", err)
	}
	defer readResponse.Body.Close()
	payload, _ := io.ReadAll(readResponse.Body)
	if readResponse.StatusCode != http.StatusOK || strings.Contains(string(payload), "PROMPT_INJECTION_SENTINEL_7F3A") || strings.Contains(string(payload), "calendar.approve_meeting_proposal") {
		t.Fatalf("read status=%d payload=%s", readResponse.StatusCode, payload)
	}
	var view outlook.MessageView
	if json.Unmarshal(payload, &view) != nil || view.MessageID != "demo-injection-message" || view.UntrustedContent != "Project Phoenix status update; embedded instructions were ignored." {
		t.Fatalf("minimized Message View = %#v", view)
	}

	write := authorizedRequest(t, http.MethodPost, server.URL+"/messages/demo-injection-message")
	writeResponse, err := http.DefaultClient.Do(write)
	if err != nil {
		t.Fatalf("attempt Outlook write: %v", err)
	}
	defer writeResponse.Body.Close()
	if writeResponse.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("write status = %d, want %d", writeResponse.StatusCode, http.StatusMethodNotAllowed)
	}
}

func authorizedRequest(t *testing.T, method, url string) *http.Request {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, url, nil)
	if err != nil {
		t.Fatalf("create Outlook request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer demo-outlook-credential")
	return request
}
