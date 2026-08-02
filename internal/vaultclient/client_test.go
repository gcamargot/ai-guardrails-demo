package vaultclient_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nahtao97/agent-tool-guardrails/internal/vaultclient"
)

func TestDemoResetCredentialComesFromItsNarrowVaultPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/secret/data/demo-reset" || request.Header.Get("X-Vault-Token") != "workload-token" {
			http.Error(response, "forbidden", http.StatusForbidden)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"data":{"data":{"credential":"vault-reset-credential"}}}`))
	}))
	t.Cleanup(server.Close)

	credential, err := vaultclient.New(server.URL, "workload-token", server.Client()).DemoResetCredential(t.Context())
	if err != nil || credential != "vault-reset-credential" {
		t.Fatalf("Demo Reset credential = %q, err=%v", credential, err)
	}
}
