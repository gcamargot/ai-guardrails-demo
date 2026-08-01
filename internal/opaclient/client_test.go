package opaclient_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nahtao97/agent-tool-guardrails/internal/gateway"
	"github.com/nahtao97/agent-tool-guardrails/internal/opaclient"
)

func TestGatewayUsesOPADecisionToAllowToolCall(t *testing.T) {
	t.Parallel()

	policyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/data/agent_tools/decision" {
			t.Errorf("OPA path = %q, want /v1/data/agent_tools/decision", request.URL.Path)
		}
		var document struct {
			Input gateway.PolicyInput `json:"input"`
		}
		if err := json.NewDecoder(request.Body).Decode(&document); err != nil {
			t.Fatalf("decode OPA input: %v", err)
		}
		if document.Input.SecurityContext.Subject != "owner" {
			t.Errorf("OPA subject = %q, want owner", document.Input.SecurityContext.Subject)
		}
		if document.Input.Tool != "coffee_station.get_status" {
			t.Errorf("OPA tool = %q, want coffee_station.get_status", document.Input.Tool)
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"decision_id":"opa-allow","result":{"allow":true,"policy_revision":"ticket-01"}}`))
	}))
	t.Cleanup(policyServer.Close)

	server := httptest.NewServer(gateway.NewHandler(gateway.Dependencies{
		SecurityContext: gateway.SecurityContext{Subject: "owner"},
		Policy:          opaclient.New(policyServer.URL, policyServer.Client()),
		CoffeeStation:   readyCoffeeStation{},
	}))
	t.Cleanup(server.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "opa-contract-test", Version: "v1.0.0"}, nil)
	session, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{
		Endpoint:             server.URL + "/mcp",
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("connect to MCP gateway: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "coffee_station.get_status",
		Arguments: map[string]any{"station_id": "demo-station"},
	})
	if err != nil {
		t.Fatalf("call coffee station tool: %v", err)
	}
	if result.IsError {
		t.Fatalf("OPA-authorized Tool Call failed: %v", result.GetError())
	}
	if got := result.Meta["decision_id"]; got != "opa-allow" {
		t.Errorf("decision_id = %v, want opa-allow", got)
	}
	if got := result.Meta["policy_revision"]; got != "ticket-01" {
		t.Errorf("policy_revision = %v, want ticket-01", got)
	}
}

type readyCoffeeStation struct{}

func (readyCoffeeStation) Status(context.Context, gateway.StationID) (gateway.CoffeeStationStatus, error) {
	return gateway.CoffeeStationStatus{StationID: "demo-station", State: "ready"}, nil
}

func (readyCoffeeStation) Health(context.Context) error { return nil }
