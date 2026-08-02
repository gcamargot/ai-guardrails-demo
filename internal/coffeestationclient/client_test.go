package coffeestationclient_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nahtao97/agent-tool-guardrails/internal/coffeestationclient"
	"github.com/nahtao97/agent-tool-guardrails/internal/gateway"
	"github.com/nahtao97/agent-tool-guardrails/internal/testsupport"
	"golang.org/x/oauth2"
)

func TestGatewayReturnsStatusFromProtectedResource(t *testing.T) {
	t.Parallel()

	resourceServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/stations/demo-station/status" {
			t.Errorf("resource path = %q, want /stations/demo-station/status", request.URL.Path)
		}
		if request.Header.Get("X-Guardrails-Trace-ID") == "" || request.Header.Get("X-Guardrails-Correlation-ID") == "" ||
			request.Header.Get("X-Guardrails-Decision-ID") != "resource-test" || request.Header.Get("Traceparent") == "" ||
			request.Header.Get("X-Guardrails-Tool") != "coffee_station.get_status" {
			t.Errorf("missing adapter correlation headers: %v", request.Header)
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"station_id":"demo-station","state":"ready"}`))
	}))
	t.Cleanup(resourceServer.Close)

	server := httptest.NewServer(gateway.NewHandler(gateway.Dependencies{
		Identity: gateway.IdentityVerifierFunc(func(context.Context, string) (gateway.TrustedIdentity, error) {
			return gateway.TrustedIdentity{Subject: "owner-subject-id", Actor: "coding-agent", TurnCapabilities: []gateway.Capability{"coffee_station.read"}}, nil
		}),
		Channel:       "streamable-http",
		Policy:        allowPolicy{},
		CoffeeStation: coffeestationclient.New(resourceServer.URL, resourceServer.Client()),
		Approvals:     testsupport.HealthyApprovals{},
		Audit:         testsupport.DiscardAudit{},
	}))
	t.Cleanup(server.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "resource-contract-test", Version: "v1.0.0"}, nil)
	session, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{
		Endpoint:             server.URL + "/mcp",
		DisableStandaloneSSE: true,
		HTTPClient: oauth2.NewClient(t.Context(), oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: "valid-token",
		})),
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
		t.Fatalf("Tool Call failed: %v", result.GetError())
	}
	output := result.StructuredContent.(map[string]any)
	if got := output["state"]; got != "ready" {
		t.Errorf("state = %v, want ready", got)
	}
}

type allowPolicy struct{}

func (allowPolicy) Decide(context.Context, gateway.PolicyInput) (gateway.PolicyDecision, error) {
	return gateway.PolicyDecision{Allow: true, DecisionID: "resource-test", PolicyRevision: "ticket-09", Reason: "owner_demo_station"}, nil
}

func (allowPolicy) Health(context.Context) error { return nil }
