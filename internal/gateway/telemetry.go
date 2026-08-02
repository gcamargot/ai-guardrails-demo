package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const (
	traceHeader       = "X-Guardrails-Trace-ID"
	correlationHeader = "X-Guardrails-Correlation-ID"
	decisionHeader    = "X-Guardrails-Decision-ID"
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
		traceID:       fmt.Sprintf("trace-%d-%d", time.Now().UnixNano(), traceSequence.Add(1)),
		tool:          tool,
		safeArguments: safeArguments(tool, raw),
	}
	return context.WithValue(ctx, toolCallObservationKey{}, observation), observation
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
		request.Header.Set(traceHeader, traceID)
	}
	if correlationID != "" {
		request.Header.Set(correlationHeader, string(correlationID))
	}
	if decisionID != "" {
		request.Header.Set(decisionHeader, decisionID)
	}
}

func safeArguments(tool ToolName, raw json.RawMessage) map[string]any {
	var arguments map[string]any
	if json.Unmarshal(raw, &arguments) != nil {
		return map[string]any{}
	}
	copyKeys := func(keys ...string) map[string]any {
		safe := make(map[string]any, len(keys))
		for _, key := range keys {
			if value, ok := arguments[key]; ok {
				safe[key] = value
			}
		}
		return safe
	}
	switch tool {
	case coffeeStationStatusTool:
		return copyKeys("station_id")
	case findAvailabilityTool:
		return copyKeys("start", "end")
	case submitMeetingTool:
		return copyKeys("start", "end")
	case reviewMeetingTool, approveMeetingTool, denyMeetingTool:
		return copyKeys("proposal_id")
	case unlockSmartLockTool:
		return copyKeys("device_id")
	case searchOutlookTool:
		safe := copyKeys("limit")
		if query, ok := arguments["query"].(string); ok {
			safe["query_length"] = len(query)
		}
		return safe
	case readOutlookTool:
		return copyKeys("message_id")
	case readRepositoryTool:
		return copyKeys("path")
	default:
		return map[string]any{}
	}
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
