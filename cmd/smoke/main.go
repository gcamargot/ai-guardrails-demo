package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nahtao97/agent-tool-guardrails/internal/oidcclient"
	"golang.org/x/oauth2"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	endpoint := environment("GATEWAY_MCP_URL", "http://127.0.0.1:8080/mcp")
	telegramGatewayEndpoint := environment("TELEGRAM_GATEWAY_MCP_URL", "http://127.0.0.1:8080/mcp")
	telegramWebhookEndpoint := environment("TELEGRAM_WEBHOOK_URL", "http://127.0.0.1:8084/telegram/webhook")
	calendarDemoEndpoint := environment("CALENDAR_DEMO_URL", "http://127.0.0.1:8083")
	tokenEndpoint := environment("KEYCLOAK_TOKEN_URL", "http://127.0.0.1:8082/realms/agent-tools/protocol/openid-connect/token")
	if status := unauthenticatedStatus(ctx, endpoint); status != http.StatusUnauthorized {
		log.Fatalf("unauthenticated MCP status = %d, want %d", status, http.StatusUnauthorized)
	}

	telegramToken := obtainToken(ctx, tokenEndpoint, "telegram-agent", "telegram-demo-secret", "owner", "owner-demo-password")
	codingToken := obtainToken(ctx, tokenEndpoint, "coding-agent", "coding-demo-secret", "owner", "owner-demo-password")
	telegramClaims := readClaims(telegramToken)
	codingClaims := readClaims(codingToken)
	if telegramClaims.Subject == "" || telegramClaims.Subject != codingClaims.Subject {
		log.Fatalf("OAuth clients did not preserve Subject: telegram=%q coding=%q", telegramClaims.Subject, codingClaims.Subject)
	}
	if telegramClaims.Actor != "telegram-agent" || codingClaims.Actor != "coding-agent" {
		log.Fatalf("OAuth clients were not distinguishable Actors: telegram=%q coding=%q", telegramClaims.Actor, codingClaims.Actor)
	}

	telegramDecision := callCoffeeStation(ctx, endpoint, telegramToken, nil)
	codingDecision := callCoffeeStation(ctx, endpoint, codingToken, mcp.Meta{
		"model_interpretation": map[string]any{
			"user":         "attacker",
			"actor":        "telegram-agent",
			"capabilities": []string{"smart_lock.write"},
		},
	})
	externalToken := obtainToken(
		ctx,
		tokenEndpoint,
		"telegram-agent",
		"telegram-demo-secret",
		"external-alice",
		"external-demo-password",
	)
	verifyExternalDiscoveryAndDenial(ctx, telegramGatewayEndpoint, externalToken)
	intervals := callTelegramWebhook(ctx, telegramWebhookEndpoint)
	secondAvailability := telegramCommand(ctx, telegramWebhookEndpoint, 4242, "otra consulta de disponibilidad", http.StatusOK)
	_ = secondAvailability.Body.Close()
	limitedAvailability := telegramCommand(ctx, telegramWebhookEndpoint, 4242, "una consulta de disponibilidad más", http.StatusTooManyRequests)
	_ = limitedAvailability.Body.Close()
	proposalID, eventID := runMeetingFlow(ctx, telegramWebhookEndpoint, calendarDemoEndpoint)

	fmt.Printf(
		"PASS subject=%s actors=%s,%s telegram_decision=%v coding_decision=%v available_intervals=%d proposal=%s event=%s event_count=1 policy_revision=ticket-04\n",
		telegramClaims.Subject,
		telegramClaims.Actor,
		codingClaims.Actor,
		telegramDecision,
		codingDecision,
		intervals,
		proposalID,
		eventID,
	)
}

func obtainToken(ctx context.Context, endpoint, clientID, clientSecret, username, password string) string {
	token, err := (oidcclient.Client{
		Endpoint:     endpoint,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		HTTPClient:   http.DefaultClient,
	}).PasswordToken(ctx, username, password)
	if err != nil {
		log.Fatalf("request %s token: %v", clientID, err)
	}
	return token
}

func callCoffeeStation(ctx context.Context, endpoint, token string, meta mcp.Meta) any {
	client := mcp.NewClient(&mcp.Implementation{Name: "compose-smoke", Version: "v0.2.0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             endpoint,
		DisableStandaloneSSE: true,
		HTTPClient: oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: token,
		})),
	}, nil)
	if err != nil {
		log.Fatalf("connect to authenticated gateway: %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Meta:      meta,
		Name:      "coffee_station.get_status",
		Arguments: map[string]any{"station_id": "demo-station"},
	})
	if err != nil {
		log.Fatalf("authenticated Tool Call: %v", err)
	}
	if result.IsError {
		log.Fatalf("authenticated Tool Call was denied: %v", result.GetError())
	}
	output, ok := result.StructuredContent.(map[string]any)
	if !ok || output["state"] != "ready" {
		log.Fatalf("unexpected authenticated result: %#v", result.StructuredContent)
	}
	if result.Meta["policy_revision"] != "ticket-04" {
		log.Fatalf("unexpected policy revision: %v", result.Meta["policy_revision"])
	}
	return result.Meta["decision_id"]
}

func verifyExternalDiscoveryAndDenial(ctx context.Context, endpoint, token string) {
	session := connectMCP(ctx, endpoint, token)
	defer session.Close()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		log.Fatalf("list External Subject Tools: %v", err)
	}
	if len(tools.Tools) != 2 || tools.Tools[0].Name != "calendar.find_availability" || tools.Tools[1].Name != "calendar.submit_meeting_proposal" {
		log.Fatalf("External Subject discovered unexpected Tools: %#v", tools.Tools)
	}
	day := nextWorkingDay(time.Now().UTC().AddDate(0, 0, 20))
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "calendar.find_availability",
		Arguments: map[string]any{
			"start": time.Date(day.Year(), day.Month(), day.Day(), 9, 0, 0, 0, time.UTC).Format(time.RFC3339),
			"end":   time.Date(day.Year(), day.Month(), day.Day(), 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
		},
	})
	if err != nil {
		log.Fatalf("call out-of-window availability Tool: %v", err)
	}
	if !result.IsError {
		log.Fatal("out-of-window availability request succeeded")
	}
}

func runMeetingFlow(ctx context.Context, webhookEndpoint, calendarEndpoint string) (string, string) {
	day := nextWorkingDay(time.Now().UTC().AddDate(0, 0, 1))
	start := time.Date(day.Year(), day.Month(), day.Day(), 13, 0, 0, 0, time.UTC).Format(time.RFC3339)
	end := time.Date(day.Year(), day.Month(), day.Day(), 13, 30, 0, 0, time.UTC).Format(time.RFC3339)
	proposalResponse := telegramCommand(ctx, webhookEndpoint, 4242, "/propose "+start+" "+end+" alice@example.invalid Platform sync", http.StatusAccepted)
	var submitted struct {
		MeetingProposal struct {
			ProposalID string `json:"proposal_id"`
		} `json:"meeting_proposal"`
	}
	decodeJSON(proposalResponse, &submitted, "Meeting Proposal")
	if submitted.MeetingProposal.ProposalID == "" {
		log.Fatal("Meeting Proposal response has no proposal_id")
	}
	limitedProposal := telegramCommand(ctx, webhookEndpoint, 4242, "/propose "+start+" "+end+" alice@example.invalid Duplicate", http.StatusTooManyRequests)
	_ = limitedProposal.Body.Close()

	reviewResponse := telegramCommand(ctx, webhookEndpoint, 9001, "/review "+submitted.MeetingProposal.ProposalID, http.StatusOK)
	var operation struct {
		Tool      string `json:"tool"`
		TraceID   string `json:"trace_id"`
		Arguments struct {
			ProposalID       string `json:"proposal_id"`
			Start            string `json:"start"`
			End              string `json:"end"`
			RequesterSubject string `json:"requester_subject"`
			Reason           string `json:"reason"`
			Contact          string `json:"contact"`
			IdempotencyKey   string `json:"idempotency_key"`
		} `json:"arguments"`
	}
	decodeJSON(reviewResponse, &operation, "exact operation")
	if operation.Tool != "calendar.create_event" || operation.Arguments.ProposalID != submitted.MeetingProposal.ProposalID ||
		operation.Arguments.Start != start || operation.Arguments.End != end || operation.Arguments.RequesterSubject != "external-alice-subject-id" ||
		operation.Arguments.Reason != "Platform sync" || operation.Arguments.Contact != "alice@example.invalid" ||
		operation.Arguments.IdempotencyKey != "meeting-proposal:"+submitted.MeetingProposal.ProposalID || operation.TraceID == "" {
		log.Fatalf("Owner review did not expose exact normalized operation: %#v", operation)
	}

	approvedResponse := telegramCommand(ctx, webhookEndpoint, 9001, "/approve "+submitted.MeetingProposal.ProposalID, http.StatusOK)
	var first struct {
		EventID string `json:"event_id"`
		Created bool   `json:"created"`
	}
	decodeJSON(approvedResponse, &first, "approved event")
	if first.EventID == "" || !first.Created {
		log.Fatalf("first approved event = %#v", first)
	}
	retryResponse := telegramCommand(ctx, webhookEndpoint, 9001, "/approve "+submitted.MeetingProposal.ProposalID, http.StatusOK)
	var retry struct {
		EventID string `json:"event_id"`
		Created bool   `json:"created"`
	}
	decodeJSON(retryResponse, &retry, "retried event")
	if retry.EventID != first.EventID || retry.Created {
		log.Fatalf("idempotent retry = %#v, first = %#v", retry, first)
	}

	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, calendarEndpoint+"/demo/event-count", nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Fatalf("read synthetic event count: %v", err)
	}
	defer response.Body.Close()
	var count struct {
		EventCount int `json:"event_count"`
	}
	if json.NewDecoder(response.Body).Decode(&count) != nil || count.EventCount != 1 {
		log.Fatalf("synthetic event count = %#v, want 1", count)
	}
	return submitted.MeetingProposal.ProposalID, first.EventID
}

func telegramCommand(ctx context.Context, endpoint string, userID int64, text string, wantStatus int) *http.Response {
	body, _ := json.Marshal(map[string]any{"message": map[string]any{"from": map[string]int64{"id": userID}, "text": text}})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		log.Fatalf("create Telegram command: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Telegram-Bot-Api-Secret-Token", "demo-telegram-webhook-secret")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Fatalf("send Telegram command: %v", err)
	}
	if response.StatusCode != wantStatus {
		defer response.Body.Close()
		log.Fatalf("Telegram command %q returned HTTP %d, want %d", text, response.StatusCode, wantStatus)
	}
	return response
}

func decodeJSON(response *http.Response, destination any, label string) {
	defer response.Body.Close()
	if err := json.NewDecoder(response.Body).Decode(destination); err != nil {
		log.Fatalf("decode %s: %v", label, err)
	}
}

func callTelegramWebhook(ctx context.Context, endpoint string) int {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(`{
		"message":{"from":{"id":4242},"text":"¿Cuándo estás libre el próximo día laboral?"}
	}`))
	if err != nil {
		log.Fatalf("create verified Telegram webhook: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Telegram-Bot-Api-Secret-Token", "demo-telegram-webhook-secret")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Fatalf("send verified Telegram webhook: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		log.Fatalf("verified Telegram webhook returned HTTP %d", response.StatusCode)
	}
	var view map[string]any
	if err := json.NewDecoder(response.Body).Decode(&view); err != nil {
		log.Fatalf("decode minimized Telegram response: %v", err)
	}
	if len(view) != 1 {
		log.Fatalf("Telegram response was not minimized: %#v", view)
	}
	intervals, ok := view["available_intervals"].([]any)
	if !ok || len(intervals) == 0 {
		log.Fatalf("Telegram response has no availability: %#v", view)
	}
	for _, item := range intervals {
		interval, ok := item.(map[string]any)
		if !ok || len(interval) != 2 || interval["start"] == nil || interval["end"] == nil {
			log.Fatalf("Telegram interval was not minimized: %#v", item)
		}
	}
	return len(intervals)
}

func connectMCP(ctx context.Context, endpoint, token string) *mcp.ClientSession {
	client := mcp.NewClient(&mcp.Implementation{Name: "compose-smoke", Version: "v0.3.0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             endpoint,
		DisableStandaloneSSE: true,
		HTTPClient: oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: token,
		})),
	}, nil)
	if err != nil {
		log.Fatalf("connect to authenticated gateway: %v", err)
	}
	return session
}

func nextWorkingDay(day time.Time) time.Time {
	for day.Weekday() == time.Saturday || day.Weekday() == time.Sunday {
		day = day.AddDate(0, 0, 1)
	}
	return day
}

func unauthenticatedStatus(ctx context.Context, endpoint string) int {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(`{}`))
	if err != nil {
		log.Fatalf("create unauthenticated request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Fatalf("send unauthenticated request: %v", err)
	}
	defer response.Body.Close()
	return response.StatusCode
}

type tokenClaims struct {
	Subject string `json:"sub"`
	Actor   string `json:"azp"`
}

func readClaims(token string) tokenClaims {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		log.Fatal("Keycloak returned a malformed access token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		log.Fatalf("decode access token claims: %v", err)
	}
	var claims tokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		log.Fatalf("parse access token claims: %v", err)
	}
	return claims
}

func environment(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
