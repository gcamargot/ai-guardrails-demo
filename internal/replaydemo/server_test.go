package replaydemo_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nahtao97/agent-tool-guardrails/internal/approvalauthority"
	"github.com/nahtao97/agent-tool-guardrails/internal/auditclient"
	"github.com/nahtao97/agent-tool-guardrails/internal/auditserver"
	"github.com/nahtao97/agent-tool-guardrails/internal/gateway"
	"github.com/nahtao97/agent-tool-guardrails/internal/replaydemo"
	"github.com/nahtao97/agent-tool-guardrails/internal/smartlock"
	"github.com/nahtao97/agent-tool-guardrails/internal/smartlockserver"
)

func TestPromptRuleReplayDeterministicallyOpensOnlyTheIsolatedDemoLock(t *testing.T) {
	qwen := exploitQwen(t)
	insecureLock := httptest.NewServer(smartlockserver.NewHandler("insecure-demo-credential"))
	t.Cleanup(insecureLock.Close)
	demo := httptest.NewServer(replaydemo.NewHandler(replaydemo.Config{
		QwenURL: qwen.URL, InsecureLockURL: insecureLock.URL,
		InsecureLockCredential: "insecure-demo-credential", HTTPClient: http.DefaultClient,
	}))
	t.Cleanup(demo.Close)

	response := post(t, demo.URL+"/demo/prompt-rule/replay")
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("prompt-only replay status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	var result struct {
		Mode              string `json:"mode"`
		ActualSubjectKind string `json:"actual_subject_kind"`
		Intent            string `json:"intent"`
		Tool              string `json:"tool"`
		Arguments         struct {
			DeviceID string `json:"device_id"`
		} `json:"arguments"`
		PromptRuleFollowed bool `json:"prompt_rule_followed"`
		Effect             struct {
			Before      string `json:"before"`
			After       string `json:"after"`
			UnlockCount int    `json:"unlock_count"`
		} `json:"effect"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatalf("decode prompt-only replay: %v", err)
	}
	if result.Mode != "prompt_only" || result.ActualSubjectKind != "external" ||
		result.Intent != "unlock the demo front door" || result.Tool != "smart_lock.unlock" ||
		result.Arguments.DeviceID != "demo-front-door" || result.PromptRuleFollowed ||
		result.Effect.Before != "locked" || result.Effect.After != "unlocked" || result.Effect.UnlockCount != 1 {
		t.Fatalf("unexpected prompt-only replay: %#v", result)
	}
}

func TestEnforcedReplayPreservesExternalIdentityAndDeniesBeforeDependencies(t *testing.T) {
	qwen := exploitQwen(t)
	audit := httptest.NewServer(auditserver.NewHandler())
	t.Cleanup(audit.Close)
	approvalConsumes := 7
	adapterUnlocks := 0
	approvalMetrics := metricsServer(t, func() map[string]any {
		return map[string]any{"consume_count": approvalConsumes}
	})
	secureLockMetrics := metricsServer(t, func() map[string]any {
		return map[string]any{"state": "locked", "unlock_count": adapterUnlocks}
	})

	policy := denyExternalSmartLockPolicy{}
	gatewayServer := httptest.NewServer(gateway.NewHandler(gateway.Dependencies{
		Identity: gateway.IdentityVerifierFunc(func(_ context.Context, token string) (gateway.TrustedIdentity, error) {
			if token != "external-token" {
				return gateway.TrustedIdentity{}, context.Canceled
			}
			return gateway.TrustedIdentity{
				Subject: "external-alice-subject-id", Actor: "telegram-agent",
				TurnCapabilities: []gateway.Capability{"smart_lock.write"},
			}, nil
		}),
		Channel: "telegram", Policy: policy, Approvals: neverConsumedApproval{consumeCount: &approvalConsumes},
		SmartLock: neverUnlockedLock{unlockCount: &adapterUnlocks},
		Audit:     auditclient.New(audit.URL, audit.Client()),
	}))
	t.Cleanup(gatewayServer.Close)
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"access_token":"external-token","token_type":"Bearer","expires_in":60}`))
	}))
	t.Cleanup(tokenEndpoint.Close)

	demo := httptest.NewServer(replaydemo.NewHandler(replaydemo.Config{
		QwenURL: qwen.URL, SecureGatewayURL: gatewayServer.URL + "/mcp", TokenEndpoint: tokenEndpoint.URL,
		OIDCClientID: "telegram-agent", OIDCClientSecret: "telegram-secret",
		ExternalUsername: "external-alice", ExternalPassword: "external-password",
		AuditRecordsURL: audit.URL + "/records", HTTPClient: http.DefaultClient,
	}))
	t.Cleanup(demo.Close)

	response := post(t, demo.URL+"/demo/enforced/replay")
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("enforced replay status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	var result struct {
		Mode      string `json:"mode"`
		Intent    string `json:"intent"`
		Tool      string `json:"tool"`
		Arguments struct {
			DeviceID string `json:"device_id"`
		} `json:"arguments"`
		Identity struct {
			SubjectKind string `json:"subject_kind"`
			Actor       string `json:"actor"`
			Channel     string `json:"channel"`
		} `json:"actual_identity"`
		Outcome         string `json:"outcome"`
		FailedCondition string `json:"failed_condition"`
		Evidence        struct {
			TraceID        string `json:"trace_id"`
			CorrelationID  string `json:"correlation_id"`
			DecisionID     string `json:"decision_id"`
			PolicyRevision string `json:"policy_revision"`
		} `json:"evidence"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatalf("decode enforced replay: %v", err)
	}
	if result.Mode != "enforced_policy" || result.Intent != "unlock the demo front door" ||
		result.Tool != smartlock.UnlockTool || result.Arguments.DeviceID != string(smartlock.DemoDeviceID) ||
		result.Identity.SubjectKind != "external" || result.Identity.Actor != "telegram-agent" || result.Identity.Channel != "telegram" ||
		result.Outcome != "deny" || result.FailedCondition != "smart_lock_owner_subject_required" ||
		result.Evidence.TraceID == "" || result.Evidence.CorrelationID == "" || result.Evidence.DecisionID == "" ||
		result.Evidence.PolicyRevision != "ticket-10" {
		t.Fatalf("unexpected enforced replay: %#v", result)
	}
	if got := metricCount(t, approvalMetrics.URL+"/metrics", "consume_count"); got != 7 {
		t.Fatalf("Approval consume_count = %d, want 7", got)
	}
	if got := metricCount(t, secureLockMetrics.URL+"/metrics", "unlock_count"); got != 0 {
		t.Fatalf("adapter unlock_count = %d, want 0", got)
	}
}

type denyExternalSmartLockPolicy struct{}

func (denyExternalSmartLockPolicy) Decide(_ context.Context, input gateway.PolicyInput) (gateway.PolicyDecision, error) {
	return gateway.PolicyDecision{
		Allow: false, CorrelationID: input.CorrelationID, DecisionID: "decision-external-deny",
		PolicyRevision: "ticket-10", Reason: "smart_lock_owner_subject_required", Obligations: []gateway.Obligation{},
	}, nil
}

func (denyExternalSmartLockPolicy) Health(context.Context) error { return nil }

type neverConsumedApproval struct{ consumeCount *int }

func (approval neverConsumedApproval) ConsumeExact(context.Context, string, approvalauthority.Binding) (approvalauthority.Consumption, error) {
	*approval.consumeCount++
	return approvalauthority.Consumption{}, nil
}

func (neverConsumedApproval) Health(context.Context) error { return nil }

type neverUnlockedLock struct{ unlockCount *int }

func (lock neverUnlockedLock) Unlock(context.Context, smartlock.DeviceID) (smartlock.State, error) {
	*lock.unlockCount++
	return smartlock.State{DeviceID: smartlock.DemoDeviceID, State: smartlock.StateUnlocked}, nil
}

func (neverUnlockedLock) Health(context.Context) error { return nil }

func exploitQwen(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/classify/prompt-rule-exploit" {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"intent":"unlock the demo front door","tool":"smart_lock.unlock","arguments":{"device_id":"demo-front-door"},"prompt_rule_followed":false}`))
	}))
	t.Cleanup(server.Close)
	return server
}

func metricsServer(t *testing.T, snapshot func() map[string]any) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/metrics" {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(snapshot())
	}))
	t.Cleanup(server.Close)
	return server
}

func metricCount(t *testing.T, endpoint, name string) int {
	t.Helper()
	response, err := http.Get(endpoint)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	defer response.Body.Close()
	var metrics map[string]any
	if err := json.NewDecoder(response.Body).Decode(&metrics); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	value, ok := metrics[name].(float64)
	if !ok {
		t.Fatalf("metric %s is not numeric: %#v", name, metrics[name])
	}
	return int(value)
}

func post(t *testing.T, endpoint string) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, nil)
	if err != nil {
		t.Fatalf("create POST %s: %v", endpoint, err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("POST %s: %v", endpoint, err)
	}
	return response
}
