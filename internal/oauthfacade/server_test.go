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
