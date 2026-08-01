package smartlockclient_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nahtao97/agent-tool-guardrails/internal/gateway"
	"github.com/nahtao97/agent-tool-guardrails/internal/smartlockclient"
)

func TestClientRejectsAdapterStateThatDoesNotMatchRequestedDevice(t *testing.T) {
	adapter := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer trusted-lock-credential" {
			t.Fatal("client omitted downstream credential")
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"device_id":"garage-door","state":"unlocked"}`))
	}))
	t.Cleanup(adapter.Close)

	client := smartlockclient.New(adapter.URL, "trusted-lock-credential", adapter.Client())
	if _, err := client.Unlock(t.Context(), gateway.LockDeviceID("demo-front-door")); err == nil {
		t.Fatal("mismatched adapter state was accepted")
	}
}
