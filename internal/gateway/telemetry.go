package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const (
	TraceHeader       = "X-Guardrails-Trace-ID"
	CorrelationHeader = "X-Guardrails-Correlation-ID"
	DecisionHeader    = "X-Guardrails-Decision-ID"
	ToolHeader        = "X-Guardrails-Tool"
)

type toolCallObservationKey struct{}

type toolCallObservation struct {
	sync.RWMutex
	traceID       string
	tool          ToolName
	safeArguments map[string]any
	decision      PolicyDecision
	failureReason string
}

var traceSequence atomic.Uint64

func beginToolCall(ctx context.Context, tool ToolName, raw json.RawMessage) (context.Context, *toolCallObservation) {
	observation := &toolCallObservation{
		traceID:       randomTraceID(),
		tool:          tool,
		safeArguments: safeArguments(tool, raw),
	}
	return context.WithValue(ctx, toolCallObservationKey{}, observation), observation
}

func randomTraceID() string {
	return randomHexID(16)
}

func randomSpanID() string {
	return randomHexID(8)
}

func randomHexID(byteCount int) string {
	value := make([]byte, byteCount)
	if _, err := rand.Read(value); err == nil {
		return hex.EncodeToString(value)
	}
	return fmt.Sprintf("%0*x", byteCount*2, uint64(time.Now().UnixNano())^traceSequence.Add(1))
}

func observeDecision(ctx context.Context, decision PolicyDecision) {
	if observation, ok := ctx.Value(toolCallObservationKey{}).(*toolCallObservation); ok {
		observation.Lock()
		observation.decision = decision
		observation.Unlock()
	}
}

func observeFailure(ctx context.Context, reason string) {
	if observation, ok := ctx.Value(toolCallObservationKey{}).(*toolCallObservation); ok {
		observation.Lock()
		observation.failureReason = reason
		observation.Unlock()
	}
}

func (observation *toolCallObservation) snapshot() (string, ToolName, map[string]any, PolicyDecision, string) {
	observation.RLock()
	defer observation.RUnlock()
	return observation.traceID, observation.tool, observation.safeArguments, observation.decision, observation.failureReason
}

// ToolCallCorrelation exposes only non-sensitive identifiers to protected-resource adapters.
func ToolCallCorrelation(ctx context.Context) (string, CorrelationID, string) {
	if observation, ok := ctx.Value(toolCallObservationKey{}).(*toolCallObservation); ok {
		traceID, _, _, decision, _ := observation.snapshot()
		return traceID, decision.CorrelationID, decision.DecisionID
	}
	return "", "", ""
}

// ApplyToolCallCorrelation propagates the identifiers required to join adapter results to a Policy Decision.
func ApplyToolCallCorrelation(ctx context.Context, request *http.Request) {
	traceID, correlationID, decisionID := ToolCallCorrelation(ctx)
	if traceID != "" {
		request.Header.Set(TraceHeader, traceID)
		request.Header.Set("Traceparent", "00-"+traceID+"-"+randomSpanID()+"-01")
	}
	if correlationID != "" {
		request.Header.Set(CorrelationHeader, string(correlationID))
	}
	if decisionID != "" {
		request.Header.Set(DecisionHeader, decisionID)
	}
	if observation, ok := ctx.Value(toolCallObservationKey{}).(*toolCallObservation); ok {
		_, tool, _, _, _ := observation.snapshot()
		request.Header.Set(ToolHeader, string(tool))
	}
}

var auditArgumentKeysByTool = map[ToolName]map[string]struct{}{
	"mcp.request":           {},
	coffeeStationStatusTool: {"station_id": {}},
	findAvailabilityTool:    {"start": {}, "end": {}},
	submitMeetingTool:       {"start": {}, "end": {}},
	reviewMeetingTool:       {"proposal_id": {}},
	approveMeetingTool:      {"proposal_id": {}},
	denyMeetingTool:         {"proposal_id": {}},
	unlockSmartLockTool:     {"device_id": {}},
	searchOutlookTool:       {"limit": {}, "query_length": {}},
	readOutlookTool:         {"message_id": {}},
	readRepositoryTool:      {"path": {}},
}

func safeArguments(tool ToolName, raw json.RawMessage) map[string]any {
	var arguments map[string]any
	if json.Unmarshal(raw, &arguments) != nil {
		return map[string]any{}
	}
	allowed, ok := auditArgumentKeysByTool[tool]
	if !ok {
		return map[string]any{}
	}
	safe := make(map[string]any, len(allowed))
	for key := range allowed {
		if key == "query_length" {
			if query, ok := arguments["query"].(string); ok {
				safe[key] = len(query)
			}
			continue
		}
		if value, ok := arguments[key]; ok {
			safe[key] = value
		}
	}
	return safe
}

// AuditArgumentsAllowed is the collector's authoritative confidentiality schema.
func AuditArgumentsAllowed(tool ToolName, arguments map[string]any) bool {
	allowed, ok := auditArgumentKeysByTool[tool]
	if !ok {
		return false
	}
	for key := range arguments {
		if _, ok := allowed[key]; !ok {
			return false
		}
	}
	return true
}

type correlatedPolicy struct{ PolicyClient }

func (policy correlatedPolicy) Decide(ctx context.Context, input PolicyInput) (PolicyDecision, error) {
	decision, err := policy.PolicyClient.Decide(ctx, input)
	if err != nil {
		observeFailure(ctx, "policy_unavailable")
		return decision, err
	}
	if decision.CorrelationID == "" {
		decision.CorrelationID = input.CorrelationID
	}
	observeDecision(ctx, decision)
	return decision, nil
}
