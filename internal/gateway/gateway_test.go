package gateway_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nahtao97/agent-tool-guardrails/internal/gateway"
)

func connectGateway(t *testing.T, dependencies gateway.Dependencies) *mcp.ClientSession {
	t.Helper()

	server := httptest.NewServer(gateway.NewHandler(dependencies))
	t.Cleanup(server.Close)
	client := mcp.NewClient(&mcp.Implementation{Name: "gateway-test", Version: "v1.0.0"}, nil)
	session, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{
		Endpoint:             server.URL + "/mcp",
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("connect to MCP gateway: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func TestAuthorizedCallerCanReadCoffeeStationStatus(t *testing.T) {
	t.Parallel()

	session := connectGateway(t, gateway.Dependencies{
		SecurityContext: gateway.SecurityContext{Subject: "owner"},
		Policy:          allowPolicy{},
		CoffeeStation:   readyCoffeeStation{},
	})

	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "coffee_station.get_status",
		Arguments: map[string]any{"station_id": "demo-station"},
	})
	if err != nil {
		t.Fatalf("call coffee station tool: %v", err)
	}
	if result.IsError {
		t.Fatalf("tool returned an error: %v", result.GetError())
	}

	output, ok := result.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structured result has type %T, want map[string]any", result.StructuredContent)
	}
	if got := output["station_id"]; got != "demo-station" {
		t.Errorf("station_id = %v, want demo-station", got)
	}
	if got := output["state"]; got != "ready" {
		t.Errorf("state = %v, want ready", got)
	}
}

func TestDeniedCallerCannotReachCoffeeStation(t *testing.T) {
	t.Parallel()

	session := connectGateway(t, gateway.Dependencies{
		SecurityContext: gateway.SecurityContext{Subject: "external"},
		Policy:          denyPolicy{},
		CoffeeStation:   unreachableCoffeeStation{t: t},
	})

	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "coffee_station.get_status",
		Arguments: map[string]any{"station_id": "demo-station"},
	})
	if err != nil {
		t.Fatalf("call coffee station tool: %v", err)
	}
	if !result.IsError {
		t.Fatal("denied tool call succeeded")
	}
	if got := result.Meta["decision_id"]; got != "decision-deny" {
		t.Errorf("decision_id = %v, want decision-deny", got)
	}
}

func TestDeniedCallerCannotDiscoverCoffeeStationTool(t *testing.T) {
	t.Parallel()

	session := connectGateway(t, gateway.Dependencies{
		SecurityContext: gateway.SecurityContext{Subject: "external"},
		Policy:          denyPolicy{},
		CoffeeStation:   readyCoffeeStation{},
	})

	result, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("list MCP tools: %v", err)
	}
	if len(result.Tools) != 0 {
		t.Fatalf("denied caller discovered %d Tools, want 0", len(result.Tools))
	}
}

func TestUnknownInputFieldIsRejected(t *testing.T) {
	t.Parallel()

	session := connectGateway(t, gateway.Dependencies{
		SecurityContext: gateway.SecurityContext{Subject: "owner"},
		Policy:          unreachablePolicy{t: t},
		CoffeeStation:   unreachableCoffeeStation{t: t},
	})

	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "coffee_station.get_status",
		Arguments: map[string]any{
			"station_id": "demo-station",
			"command":    "brew",
		},
	})
	if err != nil {
		t.Fatalf("call coffee station tool: %v", err)
	}
	if !result.IsError {
		t.Fatal("Tool Call with an unknown field succeeded")
	}
}

func TestInvalidCoffeeStationResponseIsRejected(t *testing.T) {
	t.Parallel()

	session := connectGateway(t, gateway.Dependencies{
		SecurityContext: gateway.SecurityContext{Subject: "owner"},
		Policy:          allowPolicy{},
		CoffeeStation:   invalidCoffeeStation{},
	})

	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "coffee_station.get_status",
		Arguments: map[string]any{"station_id": "demo-station"},
	})
	if err != nil {
		t.Fatalf("call coffee station tool: %v", err)
	}
	if !result.IsError {
		t.Fatal("invalid adapter response reached the MCP client")
	}
	if got := result.Meta["decision_id"]; got != "decision-allow" {
		t.Errorf("decision_id = %v, want decision-allow", got)
	}
}

func TestHealthReportsReadyWhenPolicyIsAvailable(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(gateway.NewHandler(gateway.Dependencies{
		SecurityContext: gateway.SecurityContext{Subject: "owner"},
		Policy:          allowPolicy{},
		CoffeeStation:   readyCoffeeStation{},
	}))
	t.Cleanup(server.Close)

	response, err := http.Get(server.URL + "/healthz")
	if err != nil {
		t.Fatalf("get gateway health: %v", err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })

	if response.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	var body map[string]string
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if got := body["status"]; got != "ready" {
		t.Errorf("status = %q, want ready", got)
	}
	if got := body["policy"]; got != "ready" {
		t.Errorf("policy = %q, want ready", got)
	}
}

func TestHealthReportsUnavailableWhenPolicyCannotBeReached(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(gateway.NewHandler(gateway.Dependencies{
		SecurityContext: gateway.SecurityContext{Subject: "owner"},
		Policy:          unavailablePolicy{},
		CoffeeStation:   readyCoffeeStation{},
	}))
	t.Cleanup(server.Close)

	response, err := http.Get(server.URL + "/healthz")
	if err != nil {
		t.Fatalf("get gateway health: %v", err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })

	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("health status = %d, want %d", response.StatusCode, http.StatusServiceUnavailable)
	}
	var body map[string]string
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if got := body["status"]; got != "unavailable" {
		t.Errorf("status = %q, want unavailable", got)
	}
}

func TestHealthReportsUnavailableWhenProtectedResourceCannotBeReached(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(gateway.NewHandler(gateway.Dependencies{
		SecurityContext: gateway.SecurityContext{Subject: "owner"},
		Policy:          allowPolicy{},
		CoffeeStation:   unavailableCoffeeStation{},
	}))
	t.Cleanup(server.Close)

	response, err := http.Get(server.URL + "/healthz")
	if err != nil {
		t.Fatalf("get gateway health: %v", err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })

	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("health status = %d, want %d", response.StatusCode, http.StatusServiceUnavailable)
	}
	var body map[string]string
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if got := body["resource"]; got != "unavailable" {
		t.Errorf("resource = %q, want unavailable", got)
	}
}

type allowPolicy struct{}

func (allowPolicy) Decide(context.Context, gateway.PolicyInput) (gateway.PolicyDecision, error) {
	return gateway.PolicyDecision{Allow: true, DecisionID: "decision-allow"}, nil
}

func (allowPolicy) Health(context.Context) error { return nil }

type denyPolicy struct{}

func (denyPolicy) Decide(context.Context, gateway.PolicyInput) (gateway.PolicyDecision, error) {
	return gateway.PolicyDecision{Allow: false, DecisionID: "decision-deny"}, nil
}

func (denyPolicy) Health(context.Context) error { return nil }

type unreachablePolicy struct {
	t *testing.T
}

func (policy unreachablePolicy) Decide(context.Context, gateway.PolicyInput) (gateway.PolicyDecision, error) {
	policy.t.Fatal("invalid Tool Call reached policy evaluation")
	return gateway.PolicyDecision{}, nil
}

func (unreachablePolicy) Health(context.Context) error { return nil }

type unavailablePolicy struct{}

func (unavailablePolicy) Decide(context.Context, gateway.PolicyInput) (gateway.PolicyDecision, error) {
	return gateway.PolicyDecision{}, errors.New("OPA unavailable")
}

func (unavailablePolicy) Health(context.Context) error { return errors.New("OPA unavailable") }

type readyCoffeeStation struct{}

func (readyCoffeeStation) Status(context.Context, gateway.StationID) (gateway.CoffeeStationStatus, error) {
	return gateway.CoffeeStationStatus{StationID: "demo-station", State: "ready"}, nil
}

func (readyCoffeeStation) Health(context.Context) error { return nil }

type invalidCoffeeStation struct{}

func (invalidCoffeeStation) Status(context.Context, gateway.StationID) (gateway.CoffeeStationStatus, error) {
	return gateway.CoffeeStationStatus{StationID: "another-station", State: "compromised"}, nil
}

func (invalidCoffeeStation) Health(context.Context) error { return nil }

type unavailableCoffeeStation struct{}

func (unavailableCoffeeStation) Status(context.Context, gateway.StationID) (gateway.CoffeeStationStatus, error) {
	return gateway.CoffeeStationStatus{}, errors.New("coffee station unavailable")
}

func (unavailableCoffeeStation) Health(context.Context) error {
	return errors.New("coffee station unavailable")
}

type unreachableCoffeeStation struct {
	t *testing.T
}

func (station unreachableCoffeeStation) Status(context.Context, gateway.StationID) (gateway.CoffeeStationStatus, error) {
	station.t.Fatal("denied Tool Call reached the coffee station")
	return gateway.CoffeeStationStatus{}, nil
}

func (unreachableCoffeeStation) Health(context.Context) error { return nil }
