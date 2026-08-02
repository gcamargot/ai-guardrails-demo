package auditserver

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"

	"github.com/nahtao97/agent-tool-guardrails/internal/gateway"
	"github.com/nahtao97/agent-tool-guardrails/internal/httpauth"
)

func NewHandler() http.Handler {
	return NewDemoHandler("")
}

func NewDemoHandler(resetCredential string) http.Handler {
	var state struct {
		sync.Mutex
		records []gateway.AuditRecord
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"status":"ready"}`))
	})
	mux.HandleFunc("POST /records", func(response http.ResponseWriter, request *http.Request) {
		var record gateway.AuditRecord
		decoder := json.NewDecoder(io.LimitReader(request.Body, 1<<20))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&record) != nil || decoder.Decode(&struct{}{}) != io.EOF || !valid(record) {
			http.Error(response, "invalid audit record", http.StatusBadRequest)
			return
		}
		state.Lock()
		state.records = append(state.records, record)
		state.Unlock()
		response.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("GET /records", func(response http.ResponseWriter, _ *http.Request) {
		state.Lock()
		defer state.Unlock()
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(state.records)
	})
	mux.HandleFunc("POST /test/reset", httpauth.RequireBearer(resetCredential, func(response http.ResponseWriter, _ *http.Request) {
		state.Lock()
		state.records = nil
		state.Unlock()
		response.WriteHeader(http.StatusNoContent)
	}))
	return mux
}

func valid(record gateway.AuditRecord) bool {
	return record.TraceID != "" && record.CorrelationID != "" && record.DecisionID != "" &&
		(record.SubjectKind == "owner" || record.SubjectKind == "external" || record.SubjectKind == "unknown") && record.SubjectRef != "" &&
		record.Actor != "" && record.Channel != "" && (record.Operation == "execute" || record.Operation == "discover") && record.Tool != "" &&
		(record.Outcome == "allow" || record.Outcome == "deny") && record.Reason != "" && record.Rule != "" &&
		record.PolicyRevision != "" && record.DurationMicros >= 0 && record.Stage == "gateway_result" && gateway.AuditArgumentsAllowed(record.Tool, record.SafeArguments)
}
