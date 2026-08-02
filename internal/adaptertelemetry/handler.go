package adaptertelemetry

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/gateway"
)

type handler struct {
	next   http.Handler
	output io.Writer
	mu     sync.Mutex
}

type responseObserver struct {
	http.ResponseWriter
	status int
}

func (observer *responseObserver) WriteHeader(status int) {
	observer.status = status
	observer.ResponseWriter.WriteHeader(status)
}

func (observer *responseObserver) Write(value []byte) (int, error) {
	if observer.status == 0 {
		observer.status = http.StatusOK
	}
	return observer.ResponseWriter.Write(value)
}

// NewHandler emits a content-free span for protected-resource results.
func NewHandler(next http.Handler, output io.Writer) http.Handler {
	return &handler{next: next, output: output}
}

func (service *handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	started := time.Now()
	observed := &responseObserver{ResponseWriter: response}
	service.next.ServeHTTP(observed, request)
	if observed.status == 0 {
		observed.status = http.StatusOK
	}
	traceID := request.Header.Get(gateway.TraceHeader)
	correlationID := request.Header.Get(gateway.CorrelationHeader)
	decisionID := request.Header.Get(gateway.DecisionHeader)
	tool := request.Header.Get(gateway.ToolHeader)
	if traceID == "" || correlationID == "" || decisionID == "" || tool == "" {
		return
	}
	outcome := "success"
	if observed.status >= http.StatusBadRequest {
		outcome = "error"
	}
	event := struct {
		Stage          string `json:"stage"`
		TraceID        string `json:"trace_id"`
		Traceparent    string `json:"traceparent"`
		CorrelationID  string `json:"correlation_id"`
		DecisionID     string `json:"decision_id"`
		Tool           string `json:"tool"`
		Outcome        string `json:"outcome"`
		Status         int    `json:"status"`
		DurationMicros int64  `json:"duration_micros"`
	}{
		Stage: "adapter_result", TraceID: traceID, Traceparent: request.Header.Get("Traceparent"),
		CorrelationID: correlationID, DecisionID: decisionID, Tool: tool, Outcome: outcome,
		Status: observed.status, DurationMicros: time.Since(started).Microseconds(),
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	_ = json.NewEncoder(service.output).Encode(event)
}
