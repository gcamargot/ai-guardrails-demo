package approvalauthority_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/approvalauthority"
)

func TestExactApprovalIsConsumedOnlyOnce(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(approvalauthority.NewHandler(approvalauthority.Config{
		SigningKey:         []byte("test-signing-key-with-at-least-32-bytes"),
		IssuerCredential:   "trusted-issuer-credential",
		ConsumerCredential: "trusted-consumer-credential",
		OwnerSubject:       "owner-subject-id",
		TTL:                2 * time.Minute,
		Now:                func() time.Time { return now },
		StateFile:          t.TempDir() + "/nonces",
	}))
	t.Cleanup(server.Close)

	binding := exactBinding()
	token := issueApproval(t, server, binding)
	if status := consumeApproval(t, server, token, binding); status != http.StatusNoContent {
		t.Fatalf("first consume status = %d, want %d", status, http.StatusNoContent)
	}
	if status := consumeApproval(t, server, token, binding); status != http.StatusConflict {
		t.Fatalf("replay status = %d, want %d", status, http.StatusConflict)
	}
}

func TestArgumentMismatchedAndExpiredApprovalsAreDenied(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(approvalauthority.NewHandler(approvalauthority.Config{
		SigningKey:         []byte("test-signing-key-with-at-least-32-bytes"),
		IssuerCredential:   "trusted-issuer-credential",
		ConsumerCredential: "trusted-consumer-credential",
		OwnerSubject:       "owner-subject-id",
		TTL:                time.Minute,
		Now:                func() time.Time { return now },
		StateFile:          t.TempDir() + "/nonces",
	}))
	t.Cleanup(server.Close)

	binding := exactBinding()
	mismatchToken := issueApproval(t, server, binding)
	mismatch := binding
	mismatch.Arguments = map[string]any{"proposal_id": "proposal-1", "start": "2026-08-03T14:00:00Z"}
	if status := consumeApproval(t, server, mismatchToken, mismatch); status != http.StatusForbidden {
		t.Fatalf("argument mismatch status = %d, want %d", status, http.StatusForbidden)
	}

	expiredToken := issueApproval(t, server, binding)
	now = now.Add(2 * time.Minute)
	if status := consumeApproval(t, server, expiredToken, binding); status != http.StatusForbidden {
		t.Fatalf("expired status = %d, want %d", status, http.StatusForbidden)
	}
}

func TestSmartLockApprovalReturnsBoundTraceAndRejectsMismatchExpiryAndReplay(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(approvalauthority.NewHandler(approvalauthority.Config{
		SigningKey:         []byte("test-signing-key-with-at-least-32-bytes"),
		IssuerCredential:   "trusted-issuer-credential",
		ConsumerCredential: "trusted-consumer-credential",
		OwnerSubject:       "owner-subject-id",
		TTL:                time.Minute,
		Now:                func() time.Time { return now },
		StateFile:          t.TempDir() + "/nonces",
	}))
	t.Cleanup(server.Close)
	issuer := approvalauthority.NewClient(server.URL, "trusted-issuer-credential", server.Client())
	consumer := approvalauthority.NewClient(server.URL, "trusted-consumer-credential", server.Client())
	binding := approvalauthority.Binding{
		Subject: "owner-subject-id", Actor: "telegram-agent", Tool: "smart_lock.unlock",
		Arguments: map[string]any{"device_id": "demo-front-door"}, TraceID: "smart-lock-trace-42",
	}

	mismatchToken, err := issuer.Issue(t.Context(), binding)
	if err != nil {
		t.Fatalf("issue mismatch Approval: %v", err)
	}
	mismatch := binding
	mismatch.TraceID = ""
	mismatch.Arguments = map[string]any{"device_id": "garage-door"}
	if _, err := consumer.ConsumeExact(t.Context(), mismatchToken, mismatch); err == nil {
		t.Fatal("argument-mismatched smart-lock Approval was consumed")
	}

	expiredToken, err := issuer.Issue(t.Context(), binding)
	if err != nil {
		t.Fatalf("issue expiring Approval: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := consumer.ConsumeExact(t.Context(), expiredToken, binding); err == nil {
		t.Fatal("expired smart-lock Approval was consumed")
	}

	now = now.Add(-2 * time.Minute)
	validToken, err := issuer.Issue(t.Context(), binding)
	if err != nil {
		t.Fatalf("issue valid Approval: %v", err)
	}
	consumed, err := consumer.ConsumeExact(t.Context(), validToken, binding)
	if err != nil || consumed.TraceID != "smart-lock-trace-42" {
		t.Fatalf("consume exact smart-lock Approval: trace=%q err=%v", consumed.TraceID, err)
	}
	if _, err := consumer.ConsumeExact(t.Context(), validToken, binding); err == nil {
		t.Fatal("replayed smart-lock Approval was consumed")
	}
}

func TestConsumedApprovalRemainsSingleUseAfterAuthorityRestart(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	stateFile := t.TempDir() + "/consumed-nonces"
	config := approvalauthority.Config{
		SigningKey: []byte("test-signing-key-with-at-least-32-bytes"), IssuerCredential: "trusted-issuer-credential",
		ConsumerCredential: "trusted-consumer-credential", OwnerSubject: "owner-subject-id", TTL: time.Minute,
		Now: func() time.Time { return now }, StateFile: stateFile,
	}
	first := httptest.NewServer(approvalauthority.NewHandler(config))
	token := issueApproval(t, first, exactBinding())
	if status := consumeApproval(t, first, token, exactBinding()); status != http.StatusNoContent {
		t.Fatalf("first consume status = %d", status)
	}
	first.Close()

	restarted := httptest.NewServer(approvalauthority.NewHandler(config))
	t.Cleanup(restarted.Close)
	if status := consumeApproval(t, restarted, token, exactBinding()); status != http.StatusConflict {
		t.Fatalf("post-restart replay status = %d, want %d", status, http.StatusConflict)
	}
}

func TestApprovalConsumptionFailsClosedWhenReplayStateCannotLoad(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	config := approvalauthority.Config{
		SigningKey: []byte("test-signing-key-with-at-least-32-bytes"), IssuerCredential: "trusted-issuer-credential",
		ConsumerCredential: "trusted-consumer-credential", OwnerSubject: "owner-subject-id", TTL: time.Minute,
		Now: func() time.Time { return now }, StateFile: t.TempDir() + "/healthy-nonces",
	}
	healthy := httptest.NewServer(approvalauthority.NewHandler(config))
	t.Cleanup(healthy.Close)
	token := issueApproval(t, healthy, exactBinding())

	config.StateFile = t.TempDir()
	unavailable := httptest.NewServer(approvalauthority.NewHandler(config))
	t.Cleanup(unavailable.Close)
	if status := consumeApproval(t, unavailable, token, exactBinding()); status != http.StatusServiceUnavailable {
		t.Fatalf("unavailable replay state consume status = %d, want %d", status, http.StatusServiceUnavailable)
	}
}

func TestDemoMetricsResetRequiresCredentialAndDoesNotTouchApprovalState(t *testing.T) {
	server := httptest.NewServer(approvalauthority.NewHandler(approvalauthority.Config{
		SigningKey: []byte("test-signing-key-with-at-least-32-bytes"), IssuerCredential: "issuer",
		ConsumerCredential: "consumer", OwnerSubject: "owner-subject-id", StateFile: t.TempDir() + "/nonces",
		DemoResetCredential: "reset-credential",
	}))
	t.Cleanup(server.Close)
	invalid := postJSONWithCredential(t, server.URL+"/approvals/consume", map[string]any{}, "consumer")
	invalid.Body.Close()
	if count := approvalConsumeCount(t, server.URL); count != 1 {
		t.Fatalf("consume_count before reset = %d, want 1", count)
	}
	if status := resetApprovalMetrics(t, server.URL, "wrong"); status != http.StatusUnauthorized {
		t.Fatalf("untrusted metrics reset status = %d, want %d", status, http.StatusUnauthorized)
	}
	if status := resetApprovalMetrics(t, server.URL, "reset-credential"); status != http.StatusNoContent {
		t.Fatalf("metrics reset status = %d, want %d", status, http.StatusNoContent)
	}
	if count := approvalConsumeCount(t, server.URL); count != 0 {
		t.Fatalf("consume_count after reset = %d, want 0", count)
	}
}

func exactBinding() approvalauthority.Binding {
	return approvalauthority.Binding{
		Subject: "owner-subject-id",
		Actor:   "telegram-agent",
		Tool:    "calendar.create_event",
		Arguments: map[string]any{
			"proposal_id":     "proposal-1",
			"start":           "2026-08-03T13:00:00Z",
			"end":             "2026-08-03T13:30:00Z",
			"idempotency_key": "proposal-1",
		},
		TraceID: "trace-1",
	}
}

func issueApproval(t *testing.T, server *httptest.Server, binding approvalauthority.Binding) string {
	t.Helper()
	response := postJSON(t, server.URL+"/approvals/issue", map[string]any{"binding": binding})
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("issue status = %d, want %d", response.StatusCode, http.StatusCreated)
	}
	var body struct {
		Approval string `json:"approval"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil || body.Approval == "" {
		t.Fatalf("decode Approval: approval=%q err=%v", body.Approval, err)
	}
	return body.Approval
}

func consumeApproval(t *testing.T, server *httptest.Server, token string, binding approvalauthority.Binding) int {
	t.Helper()
	response := postJSONWithCredential(t, server.URL+"/approvals/consume", map[string]any{"approval": token, "binding": binding}, "trusted-consumer-credential")
	defer response.Body.Close()
	return response.StatusCode
}

func postJSON(t *testing.T, url string, value any) *http.Response {
	return postJSONWithCredential(t, url, value, "trusted-issuer-credential")
}

func postJSONWithCredential(t *testing.T, url string, value any, credential string) *http.Response {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+credential)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	return response
}

func approvalConsumeCount(t *testing.T, baseURL string) int {
	t.Helper()
	response, err := http.Get(baseURL + "/metrics")
	if err != nil {
		t.Fatalf("read Approval metrics: %v", err)
	}
	defer response.Body.Close()
	var metrics struct {
		ConsumeCount int `json:"consume_count"`
	}
	if err := json.NewDecoder(response.Body).Decode(&metrics); err != nil {
		t.Fatalf("decode Approval metrics: %v", err)
	}
	return metrics.ConsumeCount
}

func resetApprovalMetrics(t *testing.T, baseURL, credential string) int {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL+"/test/reset-metrics", nil)
	if err != nil {
		t.Fatalf("create Approval metrics reset: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+credential)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("reset Approval metrics: %v", err)
	}
	defer response.Body.Close()
	return response.StatusCode
}
