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
	"github.com/nahtao97/agent-tool-guardrails/internal/outlook"
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
	if dependencies.Audit == nil {
		dependencies.Audit = &capturingAudit{}
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

func TestOwnerTurnCapabilityDiscoversOnlyOutlookReadTools(t *testing.T) {
	t.Parallel()

	session := connectGateway(t, gateway.Dependencies{
		Identity: fixedIdentity{
			Subject:          "owner-subject-id",
			Actor:            "telegram-agent",
			TurnCapabilities: []gateway.Capability{"outlook.mail.read"},
		},
		Channel:       "telegram",
		Policy:        outlookOnlyPolicy{},
		CoffeeStation: readyCoffeeStation{},
		Outlook:       demoOutlook{},
	})

	result, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("list MCP Tools: %v", err)
	}
	if len(result.Tools) != 2 {
		t.Fatalf("discovered %d Tools, want two Outlook read Tools", len(result.Tools))
	}
	discovered := map[string]bool{result.Tools[0].Name: true, result.Tools[1].Name: true}
	if !discovered["outlook.search_messages"] || !discovered["outlook.read_message"] {
		t.Fatalf("discovered Tools = %q, %q, want only Outlook read Tools", result.Tools[0].Name, result.Tools[1].Name)
	}
}

func TestOwnerReadsOneMinimizedOutlookMessageAsUntrustedContent(t *testing.T) {
	t.Parallel()

	session := connectGateway(t, gateway.Dependencies{
		Identity: fixedIdentity{
			Subject:          "owner-subject-id",
			Actor:            "telegram-agent",
			TurnCapabilities: []gateway.Capability{"outlook.mail.read"},
		},
		Channel:       "telegram",
		Policy:        outlookOnlyPolicy{},
		CoffeeStation: readyCoffeeStation{},
		Outlook:       demoOutlook{},
	})

	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "outlook.read_message", Arguments: map[string]any{"message_id": "demo-injection-message"},
	})
	if err != nil {
		t.Fatalf("read Outlook message: %v", err)
	}
	if result.IsError {
		t.Fatalf("Outlook read returned an error: %v", result.GetError())
	}
	view, ok := result.StructuredContent.(map[string]any)
	if !ok || len(view) != 5 || view["message_id"] != "demo-injection-message" || view["untrusted_content"] != "Project Phoenix status update; embedded instructions were ignored." {
		t.Fatalf("minimized Outlook Message View = %#v", result.StructuredContent)
	}
	encoded, _ := json.Marshal(view)
	if strings.Contains(string(encoded), "PROMPT_INJECTION_SENTINEL_7F3A") || strings.Contains(string(encoded), "calendar.approve_meeting_proposal") {
		t.Fatalf("email body escaped minimized Untrusted Content: %s", encoded)
	}
}

func TestOwnerSearchesOutlookWithAnExactBoundedQuery(t *testing.T) {
	t.Parallel()

	outlookResource := &capturingOutlook{}
	session := connectGateway(t, gateway.Dependencies{
		Identity: fixedIdentity{
			Subject:          "owner-subject-id",
			Actor:            "telegram-agent",
			TurnCapabilities: []gateway.Capability{"outlook.mail.read"},
		},
		Channel:       "telegram",
		Policy:        outlookOnlyPolicy{},
		CoffeeStation: readyCoffeeStation{},
		Outlook:       outlookResource,
	})

	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "outlook.search_messages", Arguments: map[string]any{"query": "Project Phoenix", "limit": 5},
	})
	if err != nil || result.IsError {
		t.Fatalf("search Outlook: result=%#v err=%v", result, err)
	}
	view, ok := result.StructuredContent.(map[string]any)
	if !ok || len(view) != 1 {
		t.Fatalf("minimized Outlook search = %#v", result.StructuredContent)
	}
	messages, ok := view["messages"].([]any)
	if !ok || len(messages) != 1 {
		t.Fatalf("Outlook search messages = %#v", view["messages"])
	}
	message, ok := messages[0].(map[string]any)
	if !ok || len(message) != 4 || message["message_id"] != "demo-injection-message" {
		t.Fatalf("minimized search result = %#v", messages[0])
	}
	if outlookResource.query != (outlook.SearchQuery{Query: "Project Phoenix", Limit: 5}) {
		t.Fatalf("Outlook query = %#v", outlookResource.query)
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

func TestOwnerTelegramTurnWithExactApprovalUnlocksFixedDemoLockOnce(t *testing.T) {
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
	binding := approvalauthority.Binding{
		Subject: "owner-subject-id", Actor: "telegram-agent", Tool: "smart_lock.unlock",
		Arguments: map[string]any{"device_id": "demo-front-door"}, TraceID: "smart-lock-trace-1",
	}
	approval, err := issuer.Issue(t.Context(), binding)
	if err != nil {
		t.Fatalf("issue smart-lock Approval: %v", err)
	}
	lock := &countingSmartLock{}
	audit := &capturingAudit{}
	session := connectGateway(t, gateway.Dependencies{
		Identity: fixedIdentity{Subject: "owner-subject-id", Actor: "telegram-agent", TurnCapabilities: []gateway.Capability{"smart_lock.write"}},
		Channel:  "telegram", Policy: smartLockPolicy{}, CoffeeStation: readyCoffeeStation{}, Approvals: consumer, SmartLock: lock, Audit: audit,
	})
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "smart_lock.unlock", Arguments: map[string]any{"device_id": "demo-front-door", "trace_id": "changed-trace", "approval": approval},
	})
	if err != nil || !result.IsError || lock.effects != 0 {
		t.Fatalf("trace-mismatched Approval: result=%#v err=%v effects=%d", result, err, lock.effects)
	}
	result, err = session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "smart_lock.unlock", Arguments: map[string]any{"device_id": "demo-front-door", "trace_id": "smart-lock-trace-1", "approval": approval},
	})
	if err != nil || result.IsError {
		t.Fatalf("unlock fixed demo lock: result=%#v err=%v", result, err)
	}
	output, ok := result.StructuredContent.(map[string]any)
	if !ok || output["device_id"] != "demo-front-door" || output["state"] != "unlocked" || lock.effects != 1 {
		t.Fatalf("smart-lock result=%#v effects=%d", result.StructuredContent, lock.effects)
	}
}

func TestSmartLockFailsClosedBeforeEffectWhenAuditIsUnavailable(t *testing.T) {
	authorityServer := httptest.NewServer(approvalauthority.NewHandler(approvalauthority.Config{
		SigningKey: []byte("test-signing-key-with-at-least-32-bytes"), IssuerCredential: "trusted-issuer-credential",
		ConsumerCredential: "trusted-consumer-credential", OwnerSubject: "owner-subject-id", TTL: time.Minute,
		StateFile: t.TempDir() + "/nonces",
	}))
	t.Cleanup(authorityServer.Close)
	issuer := approvalauthority.NewClient(authorityServer.URL, "trusted-issuer-credential", authorityServer.Client())
	consumer := approvalauthority.NewClient(authorityServer.URL, "trusted-consumer-credential", authorityServer.Client())
	binding := approvalauthority.Binding{
		Subject: "owner-subject-id", Actor: "telegram-agent", Tool: "smart_lock.unlock",
		Arguments: map[string]any{"device_id": "demo-front-door"}, TraceID: "smart-lock-trace-audit-down",
	}
	approval, err := issuer.Issue(t.Context(), binding)
	if err != nil {
		t.Fatalf("issue Approval: %v", err)
	}
	lock := &countingSmartLock{}
	session := connectGateway(t, gateway.Dependencies{
		Identity: fixedIdentity{Subject: "owner-subject-id", Actor: "telegram-agent", TurnCapabilities: []gateway.Capability{"smart_lock.write"}},
		Channel:  "telegram", Policy: smartLockPolicy{}, CoffeeStation: readyCoffeeStation{}, Approvals: consumer,
		SmartLock: lock, Audit: unavailableAudit{},
	})
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "smart_lock.unlock", Arguments: map[string]any{
			"device_id": "demo-front-door", "trace_id": "smart-lock-trace-audit-down", "approval": approval,
		},
	})
	if err == nil && !result.IsError {
		t.Fatal("smart-lock call succeeded without durable audit")
	}
	if lock.effects != 0 {
		t.Fatalf("audit-unavailable call produced %d Effects", lock.effects)
	}
}

func TestUnauthorizedContextsCannotDiscoverOrReachSmartLockDependencies(t *testing.T) {
	tests := []struct {
		name      string
		identity  fixedIdentity
		channel   gateway.Channel
		deviceID  string
		discovers bool
	}{
		{name: "External Subject", identity: fixedIdentity{Subject: "external-alice-subject-id", Actor: "telegram-agent", TurnCapabilities: []gateway.Capability{"smart_lock.write"}}, channel: "telegram", deviceID: "demo-front-door"},
		{name: "Unknown Subject", identity: fixedIdentity{Subject: "unknown", Actor: "telegram-agent", TurnCapabilities: []gateway.Capability{"smart_lock.write"}}, channel: "telegram", deviceID: "demo-front-door"},
		{name: "non-Telegram Actor", identity: fixedIdentity{Subject: "owner-subject-id", Actor: "coding-agent", TurnCapabilities: []gateway.Capability{"smart_lock.write"}}, channel: "telegram", deviceID: "demo-front-door"},
		{name: "missing capability", identity: fixedIdentity{Subject: "owner-subject-id", Actor: "telegram-agent"}, channel: "telegram", deviceID: "demo-front-door"},
		{name: "different device", identity: fixedIdentity{Subject: "owner-subject-id", Actor: "telegram-agent", TurnCapabilities: []gateway.Capability{"smart_lock.write"}}, channel: "telegram", deviceID: "garage-door", discovers: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := connectGateway(t, gateway.Dependencies{
				Identity: test.identity, Channel: test.channel, Policy: smartLockPolicy{}, CoffeeStation: readyCoffeeStation{},
				Approvals: unreachableApprovalConsumer{t: t}, SmartLock: unreachableSmartLock{t: t}, Audit: &capturingAudit{},
			})
			listed, err := session.ListTools(t.Context(), nil)
			if err != nil {
				t.Fatalf("list Tools: %v", err)
			}
			found := false
			for _, tool := range listed.Tools {
				if tool.Name == "smart_lock.unlock" {
					found = true
				}
			}
			if found != test.discovers {
				t.Fatalf("smart_lock.unlock discovery = %v, want %v", found, test.discovers)
			}
			result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
				Name: "smart_lock.unlock", Arguments: map[string]any{"device_id": test.deviceID, "trace_id": "untrusted-trace", "approval": "must-not-be-consumed"},
			})
			if err != nil {
				t.Fatalf("call denied smart-lock Tool: %v", err)
			}
			if !result.IsError {
				t.Fatal("unauthorized smart-lock Tool Call succeeded")
			}
		})
	}
}

func TestSmartLockAllowAndApprovalDenyProduceCorrelatedNonSensitiveAudit(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	authorityServer := httptest.NewServer(approvalauthority.NewHandler(approvalauthority.Config{
		SigningKey: []byte("test-signing-key-with-at-least-32-bytes"), IssuerCredential: "trusted-issuer-credential",
		ConsumerCredential: "trusted-consumer-credential", OwnerSubject: "owner-subject-id", TTL: time.Minute,
		Now: func() time.Time { return now }, StateFile: t.TempDir() + "/nonces",
	}))
	t.Cleanup(authorityServer.Close)
	issuer := approvalauthority.NewClient(authorityServer.URL, "trusted-issuer-credential", authorityServer.Client())
	consumer := approvalauthority.NewClient(authorityServer.URL, "trusted-consumer-credential", authorityServer.Client())
	binding := approvalauthority.Binding{
		Subject: "owner-subject-id", Actor: "telegram-agent", Tool: "smart_lock.unlock",
		Arguments: map[string]any{"device_id": "demo-front-door"}, TraceID: "smart-lock-trace-audit",
	}
	approval, err := issuer.Issue(t.Context(), binding)
	if err != nil {
		t.Fatalf("issue Approval: %v", err)
	}
	audit := &capturingAudit{}
	session := connectGateway(t, gateway.Dependencies{
		Identity: fixedIdentity{Subject: "owner-subject-id", Actor: "telegram-agent", TurnCapabilities: []gateway.Capability{"smart_lock.write"}},
		Channel:  "telegram", Policy: smartLockPolicy{}, CoffeeStation: readyCoffeeStation{}, Approvals: consumer,
		SmartLock: &countingSmartLock{}, Audit: audit,
	})
	listed, err := session.ListTools(t.Context(), nil)
	if err != nil || len(listed.Tools) == 0 {
		t.Fatalf("discover smart-lock Tool: tools=%d err=%v", len(listed.Tools), err)
	}
	call := func() *mcp.CallToolResult {
		result, callErr := session.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "smart_lock.unlock", Arguments: map[string]any{"device_id": "demo-front-door", "trace_id": "smart-lock-trace-audit", "approval": approval},
		})
		if callErr != nil {
			t.Fatalf("call smart-lock Tool: %v", callErr)
		}
		return result
	}
	if result := call(); result.IsError {
		t.Fatalf("first smart-lock call failed: %v", result.GetError())
	}
	if result := call(); !result.IsError {
		t.Fatal("Approval replay succeeded")
	}

	if len(audit.records) < 3 {
		t.Fatalf("audit records = %d, want discovery and two executions", len(audit.records))
	}
	encoded, _ := json.Marshal(audit.records)
	if strings.Contains(string(encoded), approval) || strings.Contains(string(encoded), "owner-subject-id") {
		t.Fatalf("audit leaked sensitive value: %s", encoded)
	}
	last := audit.records[len(audit.records)-1]
	if last.Outcome != "deny" || last.DecisionID != "decision-smart-lock" || last.Tool != "smart_lock.unlock" {
		t.Fatalf("replay audit = %#v", last)
	}
	foundCorrelatedAllow := false
	for _, record := range audit.records {
		foundCorrelatedAllow = foundCorrelatedAllow || (record.Outcome == "allow" && record.TraceID == "smart-lock-trace-audit")
	}
	if !foundCorrelatedAllow {
		t.Fatalf("no trace-correlated allow record: %#v", audit.records)
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

func TestHealthReportsUnavailableWhenApprovalOrAuditCannotBeReached(t *testing.T) {
	tests := []struct {
		name      string
		approvals gateway.ApprovalConsumer
		audit     gateway.AuditSink
		field     string
	}{
		{name: "Approval Authority", approvals: unavailableApprovalConsumer{}, audit: &capturingAudit{}, field: "approval"},
		{name: "audit collector", approvals: healthyApprovalConsumer{}, audit: unavailableAudit{}, field: "audit"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(gateway.NewHandler(gateway.Dependencies{
				Policy: allowPolicy{}, CoffeeStation: readyCoffeeStation{}, Approvals: test.approvals, Audit: test.audit,
			}))
			t.Cleanup(server.Close)
			response, err := http.Get(server.URL + "/healthz")
			if err != nil {
				t.Fatalf("get gateway health: %v", err)
			}
			defer response.Body.Close()
			var body map[string]string
			_ = json.NewDecoder(response.Body).Decode(&body)
			if response.StatusCode != http.StatusServiceUnavailable || body[test.field] != "unavailable" {
				t.Fatalf("health status=%d body=%#v", response.StatusCode, body)
			}
		})
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
	return gateway.PolicyDecision{Allow: allowed, DecisionID: "decision-meeting", PolicyRevision: "ticket-05"}, nil
}

func (meetingPolicy) Health(context.Context) error { return nil }

type outlookOnlyPolicy struct{}

func (outlookOnlyPolicy) Decide(_ context.Context, input gateway.PolicyInput) (gateway.PolicyDecision, error) {
	allowed := input.Tool == "outlook.search_messages" || input.Tool == "outlook.read_message"
	return gateway.PolicyDecision{Allow: allowed, DecisionID: "decision-outlook", PolicyRevision: "ticket-05"}, nil
}

func (outlookOnlyPolicy) Health(context.Context) error { return nil }

type smartLockPolicy struct{}

func (smartLockPolicy) Decide(_ context.Context, input gateway.PolicyInput) (gateway.PolicyDecision, error) {
	context := input.SecurityContext
	capable := false
	for _, capability := range context.TurnCapabilities {
		capable = capable || capability == "smart_lock.write"
	}
	var arguments struct {
		DeviceID gateway.LockDeviceID `json:"device_id"`
	}
	encoded, _ := json.Marshal(input.Arguments)
	_ = json.Unmarshal(encoded, &arguments)
	allowed := input.Tool == "smart_lock.unlock" && context.Subject == "owner-subject-id" && context.Actor == "telegram-agent" &&
		context.Channel == "telegram" && capable && (input.Operation == "discover" || arguments.DeviceID == "demo-front-door")
	return gateway.PolicyDecision{
		Allow: allowed, DecisionID: "decision-smart-lock", PolicyRevision: "ticket-06", Reason: "owner_exact_smart_lock",
	}, nil
}

func (smartLockPolicy) Health(context.Context) error { return nil }

type countingSmartLock struct{ effects int }

func (lock *countingSmartLock) Unlock(_ context.Context, deviceID gateway.LockDeviceID) (gateway.SmartLockState, error) {
	lock.effects++
	return gateway.SmartLockState{DeviceID: deviceID, State: "unlocked"}, nil
}

func (*countingSmartLock) Health(context.Context) error { return nil }

type unreachableSmartLock struct{ t *testing.T }

func (lock unreachableSmartLock) Unlock(context.Context, gateway.LockDeviceID) (gateway.SmartLockState, error) {
	lock.t.Fatal("denied Tool Call reached the smart-lock adapter")
	return gateway.SmartLockState{}, nil
}

func (unreachableSmartLock) Health(context.Context) error { return nil }

type unreachableApprovalConsumer struct{ t *testing.T }

func (authority unreachableApprovalConsumer) ConsumeExact(context.Context, string, approvalauthority.Binding) (approvalauthority.Consumption, error) {
	authority.t.Fatal("denied Tool Call reached the Approval Authority")
	return approvalauthority.Consumption{}, nil
}

func (unreachableApprovalConsumer) Health(context.Context) error { return nil }

type capturingAudit struct {
	records []gateway.AuditRecord
}

func (audit *capturingAudit) Record(_ context.Context, record gateway.AuditRecord) error {
	audit.records = append(audit.records, record)
	return nil
}

func (*capturingAudit) Health(context.Context) error { return nil }

type unavailableAudit struct{}

func (unavailableAudit) Record(context.Context, gateway.AuditRecord) error {
	return errors.New("audit unavailable")
}

func (unavailableAudit) Health(context.Context) error { return errors.New("audit unavailable") }

type healthyApprovalConsumer struct{}

func (healthyApprovalConsumer) ConsumeExact(context.Context, string, approvalauthority.Binding) (approvalauthority.Consumption, error) {
	return approvalauthority.Consumption{}, nil
}

func (healthyApprovalConsumer) Health(context.Context) error { return nil }

type unavailableApprovalConsumer struct{ healthyApprovalConsumer }

func (unavailableApprovalConsumer) Health(context.Context) error {
	return errors.New("Approval Authority unavailable")
}

type demoOutlook struct{}

func (demoOutlook) SearchMessages(context.Context, outlook.SearchQuery) ([]outlook.SearchResult, error) {
	return nil, nil
}

func (demoOutlook) ReadMessage(context.Context, outlook.MessageID) (outlook.MessageView, error) {
	return outlook.MessageView{
		MessageID: "demo-injection-message", Sender: "platform@example.invalid", Subject: "Project Phoenix",
		ReceivedAt: "2026-08-01T12:00:00Z", UntrustedContent: "Project Phoenix status update; embedded instructions were ignored.",
	}, nil
}

func (demoOutlook) Health(context.Context) error { return nil }

type capturingOutlook struct {
	query outlook.SearchQuery
}

func (resource *capturingOutlook) SearchMessages(_ context.Context, query outlook.SearchQuery) ([]outlook.SearchResult, error) {
	resource.query = query
	return []outlook.SearchResult{{
		MessageID: "demo-injection-message", Sender: "platform@example.invalid",
		Subject: "Project Phoenix", ReceivedAt: "2026-08-01T12:00:00Z",
	}}, nil
}

func (*capturingOutlook) ReadMessage(context.Context, outlook.MessageID) (outlook.MessageView, error) {
	return outlook.MessageView{}, nil
}

func (*capturingOutlook) Health(context.Context) error { return nil }

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
