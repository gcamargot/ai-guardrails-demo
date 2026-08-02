package adaptertelemetry_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nahtao97/agent-tool-guardrails/internal/adaptertelemetry"
	"github.com/nahtao97/agent-tool-guardrails/internal/gateway"
)

func TestAdapterResultEmitsCorrelatedSafeSpan(t *testing.T) {
	var output bytes.Buffer
	handler := adaptertelemetry.NewHandler(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusBadGateway)
	}), &output)
	request := httptest.NewRequest(http.MethodGet, "/stations/demo-station/status?secret=must-not-log", nil)
	request.Header.Set(gateway.TraceHeader, "0123456789abcdef0123456789abcdef")
	request.Header.Set(gateway.CorrelationHeader, "policy-123")
	request.Header.Set(gateway.DecisionHeader, "decision-123")
	request.Header.Set(gateway.ToolHeader, "coffee_station.get_status")
	request.Header.Set("Traceparent", "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01")
	handler.ServeHTTP(httptest.NewRecorder(), request)

	var event map[string]any
	if err := json.NewDecoder(&output).Decode(&event); err != nil {
		t.Fatalf("decode adapter span: %v", err)
	}
	if event["stage"] != "adapter_result" || event["trace_id"] != "0123456789abcdef0123456789abcdef" ||
		event["correlation_id"] != "policy-123" || event["decision_id"] != "decision-123" ||
		event["tool"] != "coffee_station.get_status" || event["outcome"] != "error" || event["traceparent"] == "" {
		t.Fatalf("adapter span=%#v", event)
	}
	if bytes.Contains(output.Bytes(), []byte("must-not-log")) {
		t.Fatalf("adapter span leaked request data: %s", output.Bytes())
	}
}
