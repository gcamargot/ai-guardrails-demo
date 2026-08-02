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
	return mux
}

func valid(record gateway.AuditRecord) bool {
	return record.TraceID != "" && record.CorrelationID != "" && record.DecisionID != "" &&
		(record.SubjectKind == "owner" || record.SubjectKind == "external" || record.SubjectKind == "unknown") &&
		record.Actor != "" && record.Channel != "" && (record.Operation == "execute" || record.Operation == "discover") && record.Tool != "" &&
		(record.Outcome == "allow" || record.Outcome == "deny") && record.Reason != "" && record.Rule != "" &&
		record.PolicyRevision != "" && record.DurationMicros >= 0 && safeArgumentKeys(record.Tool, record.SafeArguments)
}

func safeArgumentKeys(tool gateway.ToolName, arguments map[string]any) bool {
	allowedByTool := map[gateway.ToolName]map[string]bool{
		"mcp.request":                       {},
		"coffee_station.get_status":         {"station_id": true},
		"calendar.find_availability":        {"start": true, "end": true},
		"calendar.submit_meeting_proposal":  {"start": true, "end": true},
		"calendar.review_meeting_proposal":  {"proposal_id": true},
		"calendar.approve_meeting_proposal": {"proposal_id": true},
		"calendar.deny_meeting_proposal":    {"proposal_id": true},
		"smart_lock.unlock":                 {"device_id": true},
		"outlook.search_messages":           {"limit": true, "query_length": true},
		"outlook.read_message":              {"message_id": true},
		"dev.read_repository":               {"path": true},
	}
	allowed, ok := allowedByTool[tool]
	if !ok {
		return false
	}
	for key := range arguments {
		if !allowed[key] {
			return false
		}
	}
	return true
}
