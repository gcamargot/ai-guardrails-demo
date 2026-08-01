package auditserver

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"

	"github.com/nahtao97/agent-tool-guardrails/internal/gateway"
)

func NewHandler() http.Handler {
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
		if decoder.Decode(&record) != nil || !valid(record) {
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
	return mux
}

func valid(record gateway.AuditRecord) bool {
	return record.DecisionID != "" && record.SubjectKind != "" && record.Actor != "" && record.Channel != "" &&
		record.Operation != "" && record.Tool == "smart_lock.unlock" &&
		(record.Outcome == "allow" || record.Outcome == "deny") && record.Reason != ""
}
