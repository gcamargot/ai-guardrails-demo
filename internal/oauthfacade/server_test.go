package oauthfacade_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nahtao97/agent-tool-guardrails/internal/oauthfacade"
)

func TestFacadeDisablesRFC9207AdvertisementForCodexCallbackCompatibility(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{
			"issuer": "http://127.0.0.1:8082/realms/agent-tools",
			"authorization_response_iss_parameter_supported": true,
		})
	}))
	defer backend.Close()
	facade := httptest.NewServer(oauthfacade.NewHandler(backend.URL))
	defer facade.Close()

	for _, path := range []string{
		"/realms/agent-tools/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server/realms/agent-tools",
	} {
		response, err := http.Get(facade.URL + path)
		if err != nil {
			t.Fatalf("get facade metadata %s: %v", path, err)
		}
		var metadata map[string]any
		decodeErr := json.NewDecoder(response.Body).Decode(&metadata)
		response.Body.Close()
		if decodeErr != nil || metadata["issuer"] != "http://127.0.0.1:8082/realms/agent-tools" || metadata["authorization_response_iss_parameter_supported"] != false {
			t.Fatalf("facade metadata %s = %#v", path, metadata)
		}
	}
}

func TestIdentityFaultFixtureCanMakeJWKSUnavailableAndRestoreIt(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"keys":[]}`))
	}))
	defer backend.Close()
	facade := httptest.NewServer(oauthfacade.NewHandler(backend.URL))
	defer facade.Close()

	post := func(path string) {
		response, err := http.Post(facade.URL+path, "application/json", nil)
		if err != nil {
			t.Fatalf("toggle identity fixture: %v", err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("toggle %s returned HTTP %d", path, response.StatusCode)
		}
	}
	post("/test/identity/unavailable")
	response, err := http.Get(facade.URL + "/realms/agent-tools/protocol/openid-connect/certs")
	if err != nil {
		t.Fatalf("get unavailable JWKS: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unavailable JWKS returned HTTP %d", response.StatusCode)
	}
	post("/test/identity/available")
	response, err = http.Get(facade.URL + "/realms/agent-tools/protocol/openid-connect/certs")
	if err != nil {
		t.Fatalf("get restored JWKS: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("restored JWKS returned HTTP %d", response.StatusCode)
	}
}
