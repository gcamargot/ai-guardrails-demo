package auditserver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
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
		TraceID: "trace-1", CorrelationID: "correlation-1", DecisionID: "decision-1", SubjectKind: "owner",
		SubjectRef: "sha256:owner", Stage: "gateway_result",
		Actor: "coding-agent", Channel: "streamable-http", Operation: "execute", Tool: "coffee_station.get_status",
		Outcome: "allow", Reason: "owner_demo_station", Rule: "owner_demo_station", PolicyRevision: "ticket-09",
		Obligations: []gateway.Obligation{}, SafeArguments: map[string]any{"station_id": "demo-station"}, DurationMicros: 42,
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
	if len(records) != 1 || !reflect.DeepEqual(records[0], record) {
		t.Fatalf("audit records = %#v, want %#v", records, record)
	}
}

func TestCollectorRejectsSensitiveArgumentKeys(t *testing.T) {
	server := httptest.NewServer(auditserver.NewHandler())
	t.Cleanup(server.Close)
	client := auditclient.New(server.URL, server.Client())
	record := gateway.AuditRecord{
		TraceID: "trace-1", CorrelationID: "correlation-1", DecisionID: "decision-1", SubjectKind: "owner",
		SubjectRef: "sha256:owner", Stage: "gateway_result",
		Actor: "coding-agent", Channel: "streamable-http", Operation: "execute", Tool: "coffee_station.get_status",
		Outcome: "allow", Reason: "owner_demo_station", Rule: "owner_demo_station", PolicyRevision: "ticket-09",
		Obligations: []gateway.Obligation{}, SafeArguments: map[string]any{"token": "must-not-be-stored"}, DurationMicros: 42,
	}
	if err := client.Record(context.Background(), record); err == nil {
		t.Fatal("collector accepted a sensitive argument key")
	}
}
