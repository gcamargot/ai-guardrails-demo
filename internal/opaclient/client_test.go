package opaclient_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nahtao97/agent-tool-guardrails/internal/approvalauthority"
	"github.com/nahtao97/agent-tool-guardrails/internal/gateway"
	"github.com/nahtao97/agent-tool-guardrails/internal/opaclient"
	"golang.org/x/oauth2"
)

func TestGatewayUsesOPADecisionToAllowToolCall(t *testing.T) {
	t.Parallel()
	var observedCorrelation gateway.CorrelationID

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
		if document.Input.SecurityContext.Subject != "owner-subject-id" {
			t.Errorf("OPA subject = %q, want owner-subject-id", document.Input.SecurityContext.Subject)
		}
		if document.Input.Tool != "coffee_station.get_status" {
			t.Errorf("OPA tool = %q, want coffee_station.get_status", document.Input.Tool)
		}
		if document.Input.CorrelationID == "" {
			t.Error("OPA input is missing correlation_id")
		}
		observedCorrelation = document.Input.CorrelationID
		response.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(response, `{"decision_id":"opa-allow","result":{"allow":true,"correlation_id":%q,"obligations":["exact_approval"],"policy_revision":"ticket-08"}}`, document.Input.CorrelationID)
	}))
	t.Cleanup(policyServer.Close)

	server := httptest.NewServer(gateway.NewHandler(gateway.Dependencies{
		Identity: gateway.IdentityVerifierFunc(func(context.Context, string) (gateway.TrustedIdentity, error) {
			return gateway.TrustedIdentity{Subject: "owner-subject-id", Actor: "coding-agent", TurnCapabilities: []gateway.Capability{"coffee_station.read"}}, nil
		}),
		Channel:       "streamable-http",
		Policy:        opaclient.New(policyServer.URL, policyServer.Client()),
		CoffeeStation: readyCoffeeStation{},
		Approvals:     healthyApprovals{},
		Audit:         discardAudit{},
	}))
	t.Cleanup(server.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "opa-contract-test", Version: "v1.0.0"}, nil)
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
		t.Fatalf("OPA-authorized Tool Call failed: %v", result.GetError())
	}
	if got := result.Meta["decision_id"]; got != "opa-allow" {
		t.Errorf("decision_id = %v, want opa-allow", got)
	}
	if got := result.Meta["correlation_id"]; got != string(observedCorrelation) {
		t.Errorf("correlation_id = %v, want %s", got, observedCorrelation)
	}
	if got := result.Meta["obligations"]; !reflect.DeepEqual(got, []any{"exact_approval"}) {
		t.Errorf("obligations = %v, want exact_approval", got)
	}
	if got := result.Meta["policy_revision"]; got != "ticket-08" {
		t.Errorf("policy_revision = %v, want ticket-08", got)
	}
}

type readyCoffeeStation struct{}

func (readyCoffeeStation) Status(context.Context, gateway.StationID) (gateway.CoffeeStationStatus, error) {
	return gateway.CoffeeStationStatus{StationID: "demo-station", State: "ready"}, nil
}

func (readyCoffeeStation) Health(context.Context) error { return nil }

type healthyApprovals struct{}

func (healthyApprovals) ConsumeExact(context.Context, string, approvalauthority.Binding) (approvalauthority.Consumption, error) {
	return approvalauthority.Consumption{}, nil
}

func (healthyApprovals) Health(context.Context) error { return nil }

type discardAudit struct{}

func (discardAudit) Record(context.Context, gateway.AuditRecord) error { return nil }
func (discardAudit) Health(context.Context) error                      { return nil }
