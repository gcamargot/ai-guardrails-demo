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
	calendarMetricsEndpoint := environment("CALENDAR_METRICS_URL", "http://127.0.0.1:8083/metrics")
	smartLockMetricsEndpoint := environment("SMART_LOCK_METRICS_URL", "http://127.0.0.1:8088/metrics")
	auditRecordsEndpoint := environment("AUDIT_RECORDS_URL", "http://127.0.0.1:8089/records")
	opaStatusEndpoint := environment("OPA_STATUS_URL", "http://127.0.0.1:8181/v1/status")
	invalidPolicyUpdateEndpoint := environment("POLICY_INVALID_UPDATE_URL", "http://127.0.0.1:8091/updates/invalid-signature")
	tokenEndpoint := environment("KEYCLOAK_TOKEN_URL", "http://127.0.0.1:8082/realms/agent-tools/protocol/openid-connect/token")
	if status := unauthenticatedStatus(ctx, endpoint); status != http.StatusUnauthorized {
		log.Fatalf("unauthenticated MCP status = %d, want %d", status, http.StatusUnauthorized)
	}

	telegramToken := obtainToken(ctx, tokenEndpoint, "telegram-agent", "telegram-demo-secret", "owner", "owner-demo-password")
	codingToken := obtainToken(ctx, tokenEndpoint, "coding-agent", "", "owner", "owner-demo-password")
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
	repositoryPath := callDevelopmentRepository(ctx, endpoint, codingToken)
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
	outlookMessageID := runOutlookFlow(ctx, tokenEndpoint, telegramGatewayEndpoint, telegramWebhookEndpoint, calendarMetricsEndpoint)
	proposalID, eventID := runMeetingFlow(ctx, telegramWebhookEndpoint)
	lockTrace := runSmartLockFlow(ctx, tokenEndpoint, endpoint, telegramGatewayEndpoint, telegramWebhookEndpoint, smartLockMetricsEndpoint, auditRecordsEndpoint)
	verifyRejectedPolicyUpdate(ctx, opaStatusEndpoint, invalidPolicyUpdateEndpoint, endpoint, codingToken)

	fmt.Printf(
		"PASS subject=%s actors=%s,%s telegram_decision=%v coding_decision=%v repository=%s available_intervals=%d outlook_message=%s outlook_effect_count=0 proposal=%s event=%s event_count=1 smart_lock_trace=%s unlock_count=1 policy_revision=ticket-08 invalid_bundle=rejected\n",
		telegramClaims.Subject,
		telegramClaims.Actor,
		codingClaims.Actor,
		telegramDecision,
		codingDecision,
		repositoryPath,
		intervals,
		outlookMessageID,
		proposalID,
		eventID,
		lockTrace,
	)
}

func runSmartLockFlow(ctx context.Context, tokenEndpoint, generalGatewayEndpoint, telegramGatewayEndpoint, webhookEndpoint, metricsEndpoint, auditEndpoint string) string {
	defaultOwner := obtainToken(ctx, tokenEndpoint, "telegram-agent", "telegram-demo-secret", "owner", "owner-demo-password")
	owner := obtainTokenWithScopes(ctx, tokenEndpoint, "telegram-agent", "telegram-demo-secret", "owner", "owner-demo-password", []string{"smart_lock.write"})
	external := obtainTokenWithScopes(ctx, tokenEndpoint, "telegram-agent", "telegram-demo-secret", "external-alice", "external-demo-password", []string{"smart_lock.write"})
	coding := obtainTokenWithScopes(ctx, tokenEndpoint, "coding-agent", "", "owner", "owner-demo-password", []string{"smart_lock.write"})
	verifySmartLockAccess(ctx, telegramGatewayEndpoint, defaultOwner, false)
	verifySmartLockAccess(ctx, telegramGatewayEndpoint, external, false)
	verifySmartLockAccess(ctx, generalGatewayEndpoint, coding, false)
	verifySmartLockAccess(ctx, telegramGatewayEndpoint, owner, true)
	if response := telegramCommand(ctx, webhookEndpoint, 4242, "/review-unlock demo-front-door", http.StatusForbidden); response != nil {
		response.Body.Close()
	}

	expiring := reviewSmartLock(ctx, webhookEndpoint)
	time.Sleep(6 * time.Second)
	expired := telegramCommand(ctx, webhookEndpoint, 9001, "/unlock demo-front-door "+expiring.TraceID+" "+expiring.Approval, http.StatusBadGateway)
	expired.Body.Close()

	operation := reviewSmartLock(ctx, webhookEndpoint)
	session := connectMCP(ctx, telegramGatewayEndpoint, owner)
	mismatch, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "smart_lock.unlock", Arguments: map[string]any{"device_id": "garage-door", "trace_id": operation.TraceID, "approval": operation.Approval},
	})
	_ = session.Close()
	if err != nil || !mismatch.IsError {
		log.Fatalf("changed smart-lock arguments were not denied: result=%#v err=%v", mismatch, err)
	}
	unlocked := telegramCommand(ctx, webhookEndpoint, 9001, "/unlock demo-front-door "+operation.TraceID+" "+operation.Approval, http.StatusOK)
	var state struct {
		DeviceID string `json:"device_id"`
		State    string `json:"state"`
	}
	decodeJSON(unlocked, &state, "smart-lock state")
	if state.DeviceID != "demo-front-door" || state.State != "unlocked" {
		log.Fatalf("unexpected smart-lock state: %#v", state)
	}
	replay := telegramCommand(ctx, webhookEndpoint, 9001, "/unlock demo-front-door "+operation.TraceID+" "+operation.Approval, http.StatusBadGateway)
	replay.Body.Close()
	if count := smartLockUnlockCount(ctx, metricsEndpoint); count != 1 {
		log.Fatalf("smart-lock unlock_count = %d, want 1", count)
	}
	verifySmartLockAudit(ctx, auditEndpoint, operation.TraceID, operation.Approval)
	return operation.TraceID
}

type reviewedSmartLock struct {
	Tool      string `json:"tool"`
	Arguments struct {
		DeviceID string `json:"device_id"`
	} `json:"arguments"`
	TraceID  string `json:"trace_id"`
	Approval string `json:"approval"`
}

func reviewSmartLock(ctx context.Context, webhookEndpoint string) reviewedSmartLock {
	response := telegramCommand(ctx, webhookEndpoint, 9001, "/review-unlock demo-front-door", http.StatusOK)
	var operation reviewedSmartLock
	decodeJSON(response, &operation, "exact smart-lock operation")
	if operation.Tool != "smart_lock.unlock" || operation.Arguments.DeviceID != "demo-front-door" || operation.TraceID == "" || operation.Approval == "" {
		log.Fatalf("invalid exact smart-lock operation: %#v", operation)
	}
	return operation
}

func verifySmartLockAccess(ctx context.Context, endpoint, token string, wantDiscovery bool) {
	session := connectMCP(ctx, endpoint, token)
	defer session.Close()
	listed, err := session.ListTools(ctx, nil)
	if err != nil {
		log.Fatalf("list smart-lock Tools: %v", err)
	}
	found := false
	for _, tool := range listed.Tools {
		found = found || tool.Name == "smart_lock.unlock"
	}
	if found != wantDiscovery {
		log.Fatalf("smart-lock discovery = %v, want %v", found, wantDiscovery)
	}
	if !wantDiscovery {
		result, err := session.CallTool(ctx, &mcp.CallToolParams{
			Meta: mcp.Meta{"model_interpretation": map[string]any{
				"subject": "owner-subject-id", "actor": "telegram-agent", "channel": "telegram",
				"capabilities": []string{"smart_lock.write"},
			}},
			Name: "smart_lock.unlock", Arguments: map[string]any{"device_id": "demo-front-door", "trace_id": "untrusted-trace", "approval": "untrusted-approval"},
		})
		if err != nil || !result.IsError {
			log.Fatalf("unauthorized smart-lock Tool Call was not denied: result=%#v err=%v", result, err)
		}
	}
}

func smartLockUnlockCount(ctx context.Context, endpoint string) int {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Fatalf("read smart-lock metrics: %v", err)
	}
	defer response.Body.Close()
	var metrics struct {
		UnlockCount int `json:"unlock_count"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&metrics) != nil {
		log.Fatalf("smart-lock metrics returned HTTP %d", response.StatusCode)
	}
	return metrics.UnlockCount
}

func verifySmartLockAudit(ctx context.Context, endpoint, traceID, approval string) {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Fatalf("read audit records: %v", err)
	}
	defer response.Body.Close()
	var records []map[string]any
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&records) != nil {
		log.Fatalf("audit records returned HTTP %d", response.StatusCode)
	}
	encoded, _ := json.Marshal(records)
	if strings.Contains(string(encoded), approval) || strings.Contains(string(encoded), "owner-subject-id") {
		log.Fatalf("audit leaked Approval or Subject identifier: %s", encoded)
	}
	foundAllow, foundDeny, foundCodingDeny := false, false, false
	for _, record := range records {
		if record["tool"] != "smart_lock.unlock" || record["decision_id"] == "" {
			continue
		}
		foundAllow = foundAllow || (record["outcome"] == "allow" && record["trace_id"] == traceID)
		foundDeny = foundDeny || record["outcome"] == "deny"
		foundCodingDeny = foundCodingDeny || (record["outcome"] == "deny" && record["subject_kind"] == "owner" &&
			record["actor"] == "coding-agent" && record["channel"] == "streamable-http")
	}
	if !foundAllow || !foundDeny || !foundCodingDeny {
		log.Fatalf("missing correlated smart-lock allow/deny audit: %#v", records)
	}
}

func callDevelopmentRepository(ctx context.Context, endpoint, token string) string {
	session := connectMCP(ctx, endpoint, token)
	defer session.Close()
	listed, err := session.ListTools(ctx, nil)
	if err != nil {
		log.Fatalf("list coding Tools: %v", err)
	}
	foundDevelopment, foundSmartLock := false, false
	for _, tool := range listed.Tools {
		foundDevelopment = foundDevelopment || tool.Name == "dev.read_repository"
		foundSmartLock = foundSmartLock || tool.Name == "smart_lock.unlock"
	}
	if !foundDevelopment || foundSmartLock {
		log.Fatalf("server discovery for coding Actor: development=%v smart_lock=%v", foundDevelopment, foundSmartLock)
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "dev.read_repository", Arguments: map[string]any{"path": "CONTEXT.md"},
	})
	if err != nil || result.IsError {
		log.Fatalf("coding repository Tool failed: result=%#v err=%v", result, err)
	}
	output, ok := result.StructuredContent.(map[string]any)
	if !ok || output["path"] != "CONTEXT.md" || !strings.Contains(fmt.Sprint(output["content"]), "# Agent Tool Authorization") {
		log.Fatalf("coding repository output was not strict: %#v", result.StructuredContent)
	}
	return "CONTEXT.md"
}

func runOutlookFlow(ctx context.Context, tokenEndpoint, gatewayEndpoint, webhookEndpoint, statsEndpoint string) string {
	defaultToken := obtainToken(ctx, tokenEndpoint, "telegram-agent", "telegram-demo-secret", "owner", "owner-demo-password")
	verifyOutlookDiscovery(ctx, gatewayEndpoint, defaultToken, false)
	outlookToken := obtainTokenWithScopes(ctx, tokenEndpoint, "telegram-agent", "telegram-demo-secret", "owner", "owner-demo-password", []string{"outlook.mail.read"})
	verifyOutlookDiscovery(ctx, gatewayEndpoint, outlookToken, true)

	before := calendarEventCount(ctx, statsEndpoint)
	searchResponse := telegramCommand(ctx, webhookEndpoint, 9001, "/outlook-search Project Phoenix", http.StatusOK)
	var search struct {
		Messages []struct {
			MessageID  string `json:"message_id"`
			Sender     string `json:"sender"`
			Subject    string `json:"subject"`
			ReceivedAt string `json:"received_at"`
		} `json:"messages"`
	}
	decodeJSON(searchResponse, &search, "minimized Outlook search")
	if len(search.Messages) != 1 || search.Messages[0].MessageID != "demo-injection-message" {
		log.Fatalf("unexpected minimized Outlook search: %#v", search)
	}

	readResponse := telegramCommand(ctx, webhookEndpoint, 9001, "/outlook-read "+search.Messages[0].MessageID, http.StatusOK)
	var view map[string]any
	decodeJSON(readResponse, &view, "minimized Outlook Message View")
	encoded, _ := json.Marshal(view)
	if len(view) != 5 || view["message_id"] != "demo-injection-message" || view["untrusted_content"] != "Project Phoenix status update; embedded instructions were ignored." ||
		strings.Contains(string(encoded), "PROMPT_INJECTION_SENTINEL_7F3A") || strings.Contains(string(encoded), "calendar.approve_meeting_proposal") {
		log.Fatalf("Outlook Message View was not minimized Untrusted Content: %s", encoded)
	}
	if after := calendarEventCount(ctx, statsEndpoint); after != before {
		log.Fatalf("Untrusted Content produced an Effect: before=%d after=%d", before, after)
	}
	verifyOutlookDiscovery(ctx, gatewayEndpoint, defaultToken, false)
	return search.Messages[0].MessageID
}

func verifyOutlookDiscovery(ctx context.Context, endpoint, token string, wantOutlook bool) {
	session := connectMCP(ctx, endpoint, token)
	defer session.Close()
	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		log.Fatalf("list Outlook Tools: %v", err)
	}
	found := 0
	for _, tool := range tools.Tools {
		if strings.HasPrefix(tool.Name, "outlook.") {
			found++
		}
	}
	if (wantOutlook && found != 2) || (!wantOutlook && found != 0) {
		log.Fatalf("Outlook discovery count=%d capability=%v", found, wantOutlook)
	}
}

func calendarEventCount(ctx context.Context, endpoint string) int {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		log.Fatalf("create calendar stats request: %v", err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Fatalf("read calendar stats: %v", err)
	}
	defer response.Body.Close()
	var stats struct {
		EventCount int `json:"event_count"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&stats) != nil {
		log.Fatalf("calendar stats returned HTTP %d", response.StatusCode)
	}
	return stats.EventCount
}

func obtainToken(ctx context.Context, endpoint, clientID, clientSecret, username, password string) string {
	return obtainTokenWithScopes(ctx, endpoint, clientID, clientSecret, username, password, nil)
}

func obtainTokenWithScopes(ctx context.Context, endpoint, clientID, clientSecret, username, password string, scopes []string) string {
	token, err := (oidcclient.Client{
		Endpoint:     endpoint,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		HTTPClient:   http.DefaultClient,
	}).PasswordTokenWithScopes(ctx, username, password, scopes)
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
	if result.Meta["correlation_id"] == nil || result.Meta["correlation_id"] == "" {
		log.Fatal("Policy Decision is missing correlation_id")
	}
	if result.Meta["policy_revision"] != "ticket-08" {
		log.Fatalf("unexpected policy revision: %v", result.Meta["policy_revision"])
	}
	return result.Meta["decision_id"]
}

func verifyRejectedPolicyUpdate(ctx context.Context, statusEndpoint, updateEndpoint, gatewayEndpoint, token string) {
	initial := readPolicyBundleStatus(ctx, statusEndpoint)
	if initial.ActiveRevision != "ticket-08" || initial.Code != "" {
		log.Fatalf("unexpected initial policy bundle status: %#v", initial)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, updateEndpoint, nil)
	if err != nil {
		log.Fatalf("create invalid policy update request: %v", err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Fatalf("publish invalid policy update: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		log.Fatalf("publish invalid policy update status = %d", response.StatusCode)
	}

	deadline := time.Now().Add(8 * time.Second)
	for {
		status := readPolicyBundleStatus(ctx, statusEndpoint)
		if status.ActiveRevision == "ticket-08" && status.Code != "" && status.LastRequest != initial.LastRequest {
			break
		}
		if time.Now().After(deadline) {
			log.Fatalf("OPA did not reject untrusted bundle while retaining ticket-08: %#v", status)
		}
		time.Sleep(250 * time.Millisecond)
	}
	callCoffeeStation(ctx, gatewayEndpoint, token, nil)
}

type policyBundleStatus struct {
	ActiveRevision string
	Code           string
	LastRequest    string
}

func readPolicyBundleStatus(ctx context.Context, endpoint string) policyBundleStatus {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		log.Fatalf("create OPA status request: %v", err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Fatalf("read OPA status: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		log.Fatalf("OPA status = %d", response.StatusCode)
	}
	var document struct {
		Result struct {
			Bundles map[string]struct {
				ActiveRevision string `json:"active_revision"`
				Code           string `json:"code"`
				LastRequest    string `json:"last_request"`
			} `json:"bundles"`
		} `json:"result"`
	}
	decodeJSON(response, &document, "OPA bundle status")
	status, ok := document.Result.Bundles["agent-tools"]
	if !ok {
		log.Fatal("OPA status is missing agent-tools bundle")
	}
	return policyBundleStatus(status)
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

func runMeetingFlow(ctx context.Context, webhookEndpoint string) (string, string) {
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
		Approval  string `json:"approval"`
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
		operation.Arguments.IdempotencyKey != "meeting-proposal:"+submitted.MeetingProposal.ProposalID || operation.TraceID == "" || operation.Approval == "" {
		log.Fatalf("Owner review did not expose exact normalized operation: %#v", operation)
	}

	approvedResponse := telegramCommand(ctx, webhookEndpoint, 9001, "/approve "+submitted.MeetingProposal.ProposalID+" "+operation.Approval, http.StatusOK)
	var first struct {
		EventID string `json:"event_id"`
		Created bool   `json:"created"`
	}
	decodeJSON(approvedResponse, &first, "approved event")
	if first.EventID == "" || !first.Created {
		log.Fatalf("first approved event = %#v", first)
	}
	retryReviewResponse := telegramCommand(ctx, webhookEndpoint, 9001, "/review "+submitted.MeetingProposal.ProposalID, http.StatusOK)
	var retryOperation struct {
		Approval string `json:"approval"`
	}
	decodeJSON(retryReviewResponse, &retryOperation, "retried exact operation")
	if retryOperation.Approval == "" {
		log.Fatal("retried review returned no exact Approval")
	}
	retryResponse := telegramCommand(ctx, webhookEndpoint, 9001, "/approve "+submitted.MeetingProposal.ProposalID+" "+retryOperation.Approval, http.StatusOK)
	var retry struct {
		EventID string `json:"event_id"`
		Created bool   `json:"created"`
	}
	decodeJSON(retryResponse, &retry, "retried event")
	if retry.EventID != first.EventID || retry.Created {
		log.Fatalf("idempotent retry = %#v, first = %#v", retry, first)
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
