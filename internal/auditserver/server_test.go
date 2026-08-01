package auditserver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nahtao97/agent-tool-guardrails/internal/auditclient"
	"github.com/nahtao97/agent-tool-guardrails/internal/auditserver"
	"github.com/nahtao97/agent-tool-guardrails/internal/gateway"
)

func TestCollectorStoresOnlyTypedNonSensitiveAuditRecords(t *testing.T) {
	server := httptest.NewServer(auditserver.NewHandler())
	t.Cleanup(server.Close)
	client := auditclient.New(server.URL, server.Client())
	record := gateway.AuditRecord{
		TraceID: "smart-lock-trace-1", DecisionID: "decision-1", SubjectKind: "owner",
		Actor: "telegram-agent", Channel: "telegram", Operation: "execute", Tool: "smart_lock.unlock",
		Outcome: "allow", Reason: "owner_exact_smart_lock",
	}
	if err := client.Record(context.Background(), record); err != nil {
		t.Fatalf("record audit: %v", err)
	}

	response, err := http.Get(server.URL + "/records")
	if err != nil {
		t.Fatalf("read audit records: %v", err)
	}
	defer response.Body.Close()
	var records []gateway.AuditRecord
	if err := json.NewDecoder(response.Body).Decode(&records); err != nil {
		t.Fatalf("decode audit records: %v", err)
	}
	if len(records) != 1 || records[0] != record {
		t.Fatalf("audit records = %#v, want %#v", records, record)
	}
}
