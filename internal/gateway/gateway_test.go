package gateway_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nahtao97/agent-tool-guardrails/internal/approvalauthority"
	"github.com/nahtao97/agent-tool-guardrails/internal/calendarclient"
	"github.com/nahtao97/agent-tool-guardrails/internal/freebusy"
	"github.com/nahtao97/agent-tool-guardrails/internal/gateway"
	"github.com/nahtao97/agent-tool-guardrails/internal/meeting"
	"golang.org/x/oauth2"
)

func connectGateway(t *testing.T, dependencies gateway.Dependencies) *mcp.ClientSession {
	t.Helper()
	if dependencies.Identity == nil {
		dependencies.Identity = fixedIdentity{
			Subject:          "owner",
			Actor:            "demo-mcp-client",
			TurnCapabilities: []gateway.Capability{"coffee_station.read"},
		}
	}
	if dependencies.Channel == "" {
		dependencies.Channel = "streamable-http"
	}

	server := httptest.NewServer(gateway.NewHandler(dependencies))
	t.Cleanup(server.Close)
	client := mcp.NewClient(&mcp.Implementation{Name: "gateway-test", Version: "v1.0.0"}, nil)
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
	return session
}

func TestMissingBearerTokenFailsBeforePolicyAndProtectedResource(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(gateway.NewHandler(gateway.Dependencies{
		Identity:      fixedIdentity{Subject: "owner", Actor: "demo-mcp-client"},
		Channel:       "streamable-http",
		Policy:        unreachablePolicy{t: t},
		CoffeeStation: unreachableCoffeeStation{t: t},
	}))
	t.Cleanup(server.Close)

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/mcp", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("create unauthenticated MCP request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("send unauthenticated MCP request: %v", err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })

	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusUnauthorized)
	}
}

func TestInvalidBearerTokenFailsBeforePolicyAndProtectedResource(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(gateway.NewHandler(gateway.Dependencies{
		Identity:      rejectingIdentity{},
		Channel:       "streamable-http",
		Policy:        unreachablePolicy{t: t},
		CoffeeStation: unreachableCoffeeStation{t: t},
	}))
	t.Cleanup(server.Close)

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/mcp", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("create invalid-token MCP request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer malformed-token")
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("send invalid-token MCP request: %v", err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })

	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusUnauthorized)
	}
}

func TestEffectiveSecurityContextComesFromBearerTokenAndChannelBinding(t *testing.T) {
	t.Parallel()

	policy := &capturingPolicy{}
	session := connectGateway(t, gateway.Dependencies{
		Identity: fixedIdentity{
			Subject:          "owner-subject-id",
			Actor:            "coding-agent",
			TurnCapabilities: []gateway.Capability{"coffee_station.read"},
		},
		Channel:       "streamable-http",
		Policy:        policy,
		CoffeeStation: readyCoffeeStation{},
	})

	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Meta: mcp.Meta{"model_interpretation": map[string]any{
			"user":         "attacker",
			"actor":        "telegram-agent",
			"capabilities": []string{"smart_lock.write"},
		}},
		Name:      "coffee_station.get_status",
		Arguments: map[string]any{"station_id": "demo-station"},
	})
	if err != nil {
		t.Fatalf("call coffee station tool: %v", err)
	}
	if result.IsError {
		t.Fatalf("tool returned an error: %v", result.GetError())
	}

	got := policy.lastInput.SecurityContext
	want := gateway.SecurityContext{
		Subject:          "owner-subject-id",
		Actor:            "coding-agent",
		Channel:          "streamable-http",
		TurnCapabilities: []gateway.Capability{"coffee_station.read"},
	}
	if got.Subject != want.Subject || got.Actor != want.Actor || got.Channel != want.Channel ||
		len(got.TurnCapabilities) != 1 || got.TurnCapabilities[0] != want.TurnCapabilities[0] {
		t.Fatalf("effective Security Context = %#v, want %#v", got, want)
	}
}

func TestAuthorizedCallerCanReadCoffeeStationStatus(t *testing.T) {
	t.Parallel()

	session := connectGateway(t, gateway.Dependencies{
		Policy:        allowPolicy{},
		CoffeeStation: readyCoffeeStation{},
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
		Policy:        denyPolicy{},
		CoffeeStation: unreachableCoffeeStation{t: t},
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
		Policy:        denyPolicy{},
		CoffeeStation: readyCoffeeStation{},
	})

	result, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("list MCP tools: %v", err)
	}
	if len(result.Tools) != 0 {
		t.Fatalf("denied caller discovered %d Tools, want 0", len(result.Tools))
	}
}

func TestExternalSubjectDiscoversOnlyAvailabilityTool(t *testing.T) {
	t.Parallel()

	session := connectGateway(t, gateway.Dependencies{
		Identity: fixedIdentity{
			Subject:          "external-alice-subject-id",
			Actor:            "telegram-agent",
			TurnCapabilities: []gateway.Capability{"calendar.free_busy.read"},
		},
		Channel:       "telegram",
		Policy:        availabilityOnlyPolicy{},
		CoffeeStation: readyCoffeeStation{},
		Calendar:      availableCalendar{},
	})

	result, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("list MCP Tools: %v", err)
	}
	if len(result.Tools) != 1 || result.Tools[0].Name != "calendar.find_availability" {
		t.Fatalf("discovered Tools = %#v, want only calendar.find_availability", result.Tools)
	}
}

func TestExternalSubjectReceivesOnlyAvailableIntervals(t *testing.T) {
	t.Parallel()

	session := connectGateway(t, gateway.Dependencies{
		Identity: fixedIdentity{
			Subject:          "external-alice-subject-id",
			Actor:            "telegram-agent",
			TurnCapabilities: []gateway.Capability{"calendar.free_busy.read"},
		},
		Channel:       "telegram",
		Policy:        availabilityOnlyPolicy{},
		CoffeeStation: readyCoffeeStation{},
		Calendar:      availableCalendar{},
	})

	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "calendar.find_availability",
		Arguments: map[string]any{
			"start": "2026-08-03T09:00:00Z",
			"end":   "2026-08-03T12:00:00Z",
		},
	})
	if err != nil {
		t.Fatalf("find availability: %v", err)
	}
	if result.IsError {
		t.Fatalf("availability Tool returned an error: %v", result.GetError())
	}
	view, ok := result.StructuredContent.(map[string]any)
	if !ok || len(view) != 1 {
		t.Fatalf("Free/Busy View = %#v, want one available_intervals field", result.StructuredContent)
	}
	intervals, ok := view["available_intervals"].([]any)
	if !ok || len(intervals) != 1 {
		t.Fatalf("available_intervals = %#v", view["available_intervals"])
	}
	interval, ok := intervals[0].(map[string]any)
	if !ok || len(interval) != 2 || interval["start"] != "2026-08-03T10:00:00Z" || interval["end"] != "2026-08-03T10:30:00Z" {
		t.Fatalf("available interval = %#v, want only start and end", intervals[0])
	}
}

func TestExternalProposalHasNoEffectAndOwnerReviewsExactNormalizedOperation(t *testing.T) {
	t.Parallel()

	proposals := meeting.NewStore()
	external := connectGateway(t, gateway.Dependencies{
		Identity: fixedIdentity{
			Subject:          "external-alice-subject-id",
			Actor:            "telegram-agent",
			TurnCapabilities: []gateway.Capability{"calendar.meeting.propose"},
		},
		Channel:        "telegram",
		Policy:         meetingPolicy{},
		CoffeeStation:  readyCoffeeStation{},
		Proposals:      proposals,
		CalendarEvents: unreachableCalendarEvents{t: t},
	})
	created, err := external.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "calendar.submit_meeting_proposal",
		Arguments: map[string]any{
			"start":   "2026-08-03T13:00:00+00:00",
			"end":     "2026-08-03T13:30:00+00:00",
			"reason":  "  Platform sync  ",
			"contact": "alice@example.invalid",
		},
	})
	if err != nil || created.IsError {
		t.Fatalf("submit Meeting Proposal: result=%#v err=%v", created, err)
	}

	owner := connectGateway(t, gateway.Dependencies{
		Identity: fixedIdentity{
			Subject:          "owner-subject-id",
			Actor:            "telegram-agent",
			TurnCapabilities: []gateway.Capability{"calendar.meeting.approve"},
		},
		Channel:        "telegram",
		Policy:         meetingPolicy{},
		CoffeeStation:  readyCoffeeStation{},
		Proposals:      proposals,
		CalendarEvents: unreachableCalendarEvents{t: t},
	})
	reviewed, err := owner.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "calendar.review_meeting_proposal",
		Arguments: map[string]any{"proposal_id": "proposal-1"},
	})
	if err != nil || reviewed.IsError {
		t.Fatalf("review Meeting Proposal: result=%#v err=%v", reviewed, err)
	}
	encoded, _ := json.Marshal(reviewed.StructuredContent)
	want := `{"arguments":{"contact":"alice@example.invalid","end":"2026-08-03T13:30:00Z","idempotency_key":"meeting-proposal:proposal-1","proposal_id":"proposal-1","reason":"Platform sync","requester_subject":"external-alice-subject-id","start":"2026-08-03T13:00:00Z"},"tool":"calendar.create_event","trace_id":"meeting-trace-1"}`
	if string(encoded) != want {
		t.Fatalf("exact normalized operation = %s, want %s", encoded, want)
	}
}

func TestApprovalMustBeExactActiveAndSingleUseBeforeCalendarEffect(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	authorityServer := httptest.NewServer(approvalauthority.NewHandler(approvalauthority.Config{
		SigningKey:         []byte("test-signing-key-with-at-least-32-bytes"),
		IssuerCredential:   "trusted-issuer-credential",
		ConsumerCredential: "trusted-consumer-credential",
		OwnerSubject:       "owner-subject-id",
		TTL:                time.Minute,
		Now:                func() time.Time { return now },
		StateFile:          t.TempDir() + "/nonces",
	}))
	t.Cleanup(authorityServer.Close)
	issuer := approvalauthority.NewClient(authorityServer.URL, "trusted-issuer-credential", authorityServer.Client())
	consumer := approvalauthority.NewClient(authorityServer.URL, "trusted-consumer-credential", authorityServer.Client())
	proposals := meeting.NewStore()
	proposal := proposals.Submit("external-alice-subject-id", meeting.ProposalInput{
		Start: time.Date(2026, 8, 3, 13, 0, 0, 0, time.UTC), End: time.Date(2026, 8, 3, 13, 30, 0, 0, time.UTC),
		Reason: "Platform sync", Contact: "alice@example.invalid",
	})
	operation, _ := proposals.Review(proposal.ProposalID)
	binding := approvalauthority.Binding{
		Subject: "owner-subject-id", Actor: "telegram-agent", Tool: operation.Tool,
		Arguments: operation.Arguments, TraceID: string(operation.TraceID),
	}
	events := &countingCalendarEvents{}
	owner := connectGateway(t, gateway.Dependencies{
		Identity: fixedIdentity{Subject: "owner-subject-id", Actor: "telegram-agent", TurnCapabilities: []gateway.Capability{"calendar.meeting.approve"}},
		Channel:  "telegram", Policy: meetingPolicy{}, CoffeeStation: readyCoffeeStation{},
		Proposals: proposals, Approvals: consumer, CalendarEvents: events,
	})

	mismatch := binding
	changed := operation.Arguments
	changed.Start = "2026-08-03T14:00:00Z"
	mismatch.Arguments = changed
	mismatchToken, err := issuer.Issue(t.Context(), mismatch)
	if err != nil {
		t.Fatalf("issue mismatched Approval: %v", err)
	}
	if result := approveMeeting(t, owner, proposal.ProposalID, mismatchToken); !result.IsError || events.count != 0 {
		t.Fatalf("mismatched Approval result=%#v calendar effects=%d", result, events.count)
	}

	expiredToken, err := issuer.Issue(t.Context(), binding)
	if err != nil {
		t.Fatalf("issue expiring Approval: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if result := approveMeeting(t, owner, proposal.ProposalID, expiredToken); !result.IsError || events.count != 0 {
		t.Fatalf("expired Approval result=%#v calendar effects=%d", result, events.count)
	}

	now = now.Add(-2 * time.Minute)
	validToken, err := issuer.Issue(t.Context(), binding)
	if err != nil {
		t.Fatalf("issue valid Approval: %v", err)
	}
	if result := approveMeeting(t, owner, proposal.ProposalID, validToken); result.IsError || events.count != 1 {
		t.Fatalf("valid Approval result=%#v calendar effects=%d", result, events.count)
	}
	if result := approveMeeting(t, owner, proposal.ProposalID, validToken); !result.IsError || events.count != 1 {
		t.Fatalf("replayed Approval result=%#v calendar effects=%d", result, events.count)
	}

	deniedProposal := proposals.Submit("external-alice-subject-id", meeting.ProposalInput{
		Start: time.Date(2026, 8, 3, 14, 0, 0, 0, time.UTC), End: time.Date(2026, 8, 3, 14, 30, 0, 0, time.UTC),
		Reason: "Denied sync", Contact: "alice@example.invalid",
	})
	deniedOperation, _ := proposals.Review(deniedProposal.ProposalID)
	deniedBinding := approvalauthority.Binding{
		Subject: "owner-subject-id", Actor: "telegram-agent", Tool: deniedOperation.Tool,
		Arguments: deniedOperation.Arguments, TraceID: string(deniedOperation.TraceID),
	}
	denialToken, _ := issuer.Issue(t.Context(), deniedBinding)
	denial, err := owner.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "calendar.deny_meeting_proposal",
		Arguments: map[string]any{"proposal_id": deniedProposal.ProposalID, "approval": denialToken},
	})
	if err != nil || denial.IsError {
		t.Fatalf("deny reviewed Meeting Proposal: result=%#v err=%v", denial, err)
	}
	lateApproval, _ := issuer.Issue(t.Context(), deniedBinding)
	if result := approveMeeting(t, owner, deniedProposal.ProposalID, lateApproval); !result.IsError || events.count != 1 {
		t.Fatalf("denied proposal approval result=%#v calendar effects=%d", result, events.count)
	}
}

func approveMeeting(t *testing.T, session *mcp.ClientSession, proposalID meeting.ProposalID, approval string) *mcp.CallToolResult {
	t.Helper()
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "calendar.approve_meeting_proposal",
		Arguments: map[string]any{"proposal_id": proposalID, "approval": approval},
	})
	if err != nil {
		t.Fatalf("approve Meeting Proposal: %v", err)
	}
	return result
}

func TestCalendarEventDetailsAreRejectedAtTheMCPBoundary(t *testing.T) {
	t.Parallel()

	calendar := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/free-busy" {
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{
				"available_intervals":[{"start":"2026-08-03T10:00:00Z","end":"2026-08-03T10:30:00Z"}],
				"occupied_events":[{"title":"Private appointment","attendees":["owner@example.invalid"]}]
			}`))
			return
		}
		http.NotFound(response, request)
	}))
	t.Cleanup(calendar.Close)

	session := connectGateway(t, gateway.Dependencies{
		Policy:        availabilityOnlyPolicy{},
		CoffeeStation: readyCoffeeStation{},
		Calendar:      calendarclient.New(calendar.URL, "calendar-credential", calendar.Client()),
	})
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "calendar.find_availability",
		Arguments: map[string]any{
			"start": "2026-08-03T09:00:00Z",
			"end":   "2026-08-03T12:00:00Z",
		},
	})
	if err == nil && !result.IsError {
		t.Fatal("calendar event contents crossed the MCP Enforcement Boundary")
	}
}

func TestAvailabilityOutsideRequestedWindowIsRejectedAtTheMCPBoundary(t *testing.T) {
	t.Parallel()

	session := connectGateway(t, gateway.Dependencies{
		Policy:        availabilityOnlyPolicy{},
		CoffeeStation: readyCoffeeStation{},
		Calendar:      outOfBoundsCalendar{},
	})
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "calendar.find_availability",
		Arguments: map[string]any{
			"start": "2026-08-03T09:00:00Z",
			"end":   "2026-08-03T12:00:00Z",
		},
	})
	if err == nil && !result.IsError {
		t.Fatal("out-of-bounds availability crossed the MCP Enforcement Boundary")
	}
}

func TestUnknownInputFieldIsRejected(t *testing.T) {
	t.Parallel()

	session := connectGateway(t, gateway.Dependencies{
		Policy:        unreachablePolicy{t: t},
		CoffeeStation: unreachableCoffeeStation{t: t},
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
		Policy:        allowPolicy{},
		CoffeeStation: invalidCoffeeStation{},
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
		Policy:        allowPolicy{},
		CoffeeStation: readyCoffeeStation{},
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
		Policy:        unavailablePolicy{},
		CoffeeStation: readyCoffeeStation{},
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
		Policy:        allowPolicy{},
		CoffeeStation: unavailableCoffeeStation{},
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

type fixedIdentity gateway.TrustedIdentity

func (identity fixedIdentity) Verify(context.Context, string) (gateway.TrustedIdentity, error) {
	return gateway.TrustedIdentity(identity), nil
}

type rejectingIdentity struct{}

func (rejectingIdentity) Verify(context.Context, string) (gateway.TrustedIdentity, error) {
	return gateway.TrustedIdentity{}, errors.New("token rejected")
}

type capturingPolicy struct {
	lastInput gateway.PolicyInput
}

func (policy *capturingPolicy) Decide(_ context.Context, input gateway.PolicyInput) (gateway.PolicyDecision, error) {
	policy.lastInput = input
	return gateway.PolicyDecision{Allow: true, DecisionID: "decision-allow"}, nil
}

func (*capturingPolicy) Health(context.Context) error { return nil }

type availabilityOnlyPolicy struct{}

func (availabilityOnlyPolicy) Decide(_ context.Context, input gateway.PolicyInput) (gateway.PolicyDecision, error) {
	return gateway.PolicyDecision{
		Allow:          input.Tool == "calendar.find_availability",
		DecisionID:     "decision-availability",
		PolicyRevision: "ticket-03",
	}, nil
}

func (availabilityOnlyPolicy) Health(context.Context) error { return nil }

type meetingPolicy struct{}

func (meetingPolicy) Decide(_ context.Context, input gateway.PolicyInput) (gateway.PolicyDecision, error) {
	allowed := input.Tool == "calendar.submit_meeting_proposal" || input.Tool == "calendar.review_meeting_proposal" || input.Tool == "calendar.approve_meeting_proposal" || input.Tool == "calendar.deny_meeting_proposal"
	return gateway.PolicyDecision{Allow: allowed, DecisionID: "decision-meeting", PolicyRevision: "ticket-04"}, nil
}

func (meetingPolicy) Health(context.Context) error { return nil }

type unreachableCalendarEvents struct{ t *testing.T }

func (calendar unreachableCalendarEvents) CreateEvent(context.Context, meeting.EventArguments) (meeting.Event, error) {
	calendar.t.Fatal("Meeting Proposal reached calendar before exact Approval")
	return meeting.Event{}, nil
}

type countingCalendarEvents struct{ count int }

func (calendar *countingCalendarEvents) CreateEvent(_ context.Context, _ meeting.EventArguments) (meeting.Event, error) {
	calendar.count++
	return meeting.Event{EventID: "event-1", Created: calendar.count == 1}, nil
}

type availableCalendar struct{}

func (availableCalendar) FindAvailability(context.Context, freebusy.Window) (freebusy.View, error) {
	return freebusy.View{AvailableIntervals: []freebusy.AvailableInterval{{
		Start: "2026-08-03T10:00:00Z",
		End:   "2026-08-03T10:30:00Z",
	}}}, nil
}

func (availableCalendar) Health(context.Context) error { return nil }

type outOfBoundsCalendar struct{}

func (outOfBoundsCalendar) FindAvailability(context.Context, freebusy.Window) (freebusy.View, error) {
	return freebusy.View{AvailableIntervals: []freebusy.AvailableInterval{{
		Start: "2026-08-03T08:00:00Z",
		End:   "2026-08-03T10:00:00Z",
	}}}, nil
}

func (outOfBoundsCalendar) Health(context.Context) error { return nil }
