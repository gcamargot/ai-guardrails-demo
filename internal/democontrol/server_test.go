package democontrol_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nahtao97/agent-tool-guardrails/internal/democontrol"
)

func TestResetAuthenticatesAndRestoresLocksAndEvidenceForRepeatedRuns(t *testing.T) {
	const credential = "internal-reset-credential"
	insecureCount := map[string]int{"unlock_count": 1}
	secureCount := map[string]int{"unlock_count": 1}
	auditCount := map[string]int{"record_count": 4}
	approvalCount := map[string]int{"consume_count": 3}
	insecure := newResetFixture(t, credential, "/test/reset", insecureCount)
	secure := newResetFixture(t, credential, "/test/reset", secureCount)
	audit := newResetFixture(t, credential, "/test/reset", auditCount)
	approvals := newResetFixture(t, credential, "/test/reset-metrics", approvalCount)
	server := httptest.NewServer(democontrol.NewHandler(democontrol.Config{
		Credential: credential, InsecureLockURL: insecure.URL, SecureLockURL: secure.URL,
		AuditURL: audit.URL, ApprovalURL: approvals.URL, HTTPClient: http.DefaultClient,
	}))
	t.Cleanup(server.Close)

	if status := reset(t, server.URL, "wrong-credential", nil); status != http.StatusUnauthorized {
		t.Fatalf("untrusted reset status = %d, want %d", status, http.StatusUnauthorized)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		insecureCount["unlock_count"] = attempt
		secureCount["unlock_count"] = attempt
		auditCount["record_count"] = attempt
		approvalCount["consume_count"] = attempt
		var result struct {
			ScenarioState string `json:"scenario_state"`
			InsecureLock  struct {
				State       string `json:"state"`
				UnlockCount int    `json:"unlock_count"`
			} `json:"insecure_lock"`
			SecureLock struct {
				State       string `json:"state"`
				UnlockCount int    `json:"unlock_count"`
			} `json:"secure_lock"`
			Evidence struct {
				AuditRecordCount     int `json:"audit_record_count"`
				ApprovalConsumeCount int `json:"approval_consume_count"`
			} `json:"evidence"`
		}
		if status := reset(t, server.URL, credential, &result); status != http.StatusOK {
			t.Fatalf("reset %d status = %d, want %d", attempt, status, http.StatusOK)
		}
		if result.ScenarioState != "ready" || result.InsecureLock.State != "locked" || result.InsecureLock.UnlockCount != 0 ||
			result.SecureLock.State != "locked" || result.SecureLock.UnlockCount != 0 ||
			result.Evidence.AuditRecordCount != 0 || result.Evidence.ApprovalConsumeCount != 0 {
			t.Fatalf("unexpected reset %d: %#v", attempt, result)
		}
	}
}

func newResetFixture(t *testing.T, credential, resetPath string, count map[string]int) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == resetPath:
			if request.Header.Get("Authorization") != "Bearer "+credential {
				http.Error(response, "unauthorized", http.StatusUnauthorized)
				return
			}
			for key := range count {
				count[key] = 0
			}
			response.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodGet && request.URL.Path == "/metrics":
			response.Header().Set("Content-Type", "application/json")
			body := map[string]any{}
			if _, isLock := count["unlock_count"]; isLock {
				body["state"] = "locked"
			}
			for key, value := range count {
				body[key] = value
			}
			_ = json.NewEncoder(response).Encode(body)
		case request.Method == http.MethodGet && request.URL.Path == "/records":
			response.Header().Set("Content-Type", "application/json")
			records := make([]map[string]any, count["record_count"])
			_ = json.NewEncoder(response).Encode(records)
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func reset(t *testing.T, baseURL, credential string, destination any) int {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL+"/demo/reset", nil)
	if err != nil {
		t.Fatalf("create reset: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+credential)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	defer response.Body.Close()
	if destination != nil && response.StatusCode == http.StatusOK {
		if err := json.NewDecoder(response.Body).Decode(destination); err != nil {
			t.Fatalf("decode reset: %v", err)
		}
	}
	return response.StatusCode
}
