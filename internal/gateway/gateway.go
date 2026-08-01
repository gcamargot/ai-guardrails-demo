package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nahtao97/agent-tool-guardrails/internal/approvalauthority"
	"github.com/nahtao97/agent-tool-guardrails/internal/freebusy"
	"github.com/nahtao97/agent-tool-guardrails/internal/meeting"
)

type Subject string
type Actor string
type Channel string
type Capability string
type ToolName string
type PolicyOperation string
type StationID string

const (
	coffeeStationStatusTool ToolName        = "coffee_station.get_status"
	findAvailabilityTool    ToolName        = "calendar.find_availability"
	submitMeetingTool       ToolName        = "calendar.submit_meeting_proposal"
	reviewMeetingTool       ToolName        = "calendar.review_meeting_proposal"
	approveMeetingTool      ToolName        = "calendar.approve_meeting_proposal"
	denyMeetingTool         ToolName        = "calendar.deny_meeting_proposal"
	discoverOperation       PolicyOperation = "discover"
	executeOperation        PolicyOperation = "execute"
)

type SecurityContext struct {
	Subject          Subject      `json:"subject"`
	Actor            Actor        `json:"actor"`
	Channel          Channel      `json:"channel"`
	TurnCapabilities []Capability `json:"turn_capabilities"`
}

type TrustedIdentity struct {
	Subject          Subject
	Actor            Actor
	TurnCapabilities []Capability
}

type IdentityVerifier interface {
	Verify(context.Context, string) (TrustedIdentity, error)
}

type IdentityVerifierFunc func(context.Context, string) (TrustedIdentity, error)

func (verify IdentityVerifierFunc) Verify(ctx context.Context, token string) (TrustedIdentity, error) {
	return verify(ctx, token)
}

type PolicyInput struct {
	SecurityContext SecurityContext `json:"security_context"`
	Operation       PolicyOperation `json:"operation"`
	Tool            ToolName        `json:"tool"`
	Arguments       any             `json:"arguments"`
}

type PolicyDecision struct {
	Allow          bool   `json:"allow"`
	DecisionID     string `json:"decision_id"`
	PolicyRevision string `json:"policy_revision"`
}

type PolicyClient interface {
	Decide(context.Context, PolicyInput) (PolicyDecision, error)
	Health(context.Context) error
}

type CoffeeStation interface {
	Status(context.Context, StationID) (CoffeeStationStatus, error)
	Health(context.Context) error
}

type CoffeeStationStatus struct {
	StationID StationID `json:"station_id"`
	State     string    `json:"state"`
}

type Calendar interface {
	FindAvailability(context.Context, freebusy.Window) (freebusy.View, error)
	Health(context.Context) error
}

type ProposalStore interface {
	Submit(string, meeting.ProposalInput) meeting.Proposal
	Review(meeting.ProposalID) (meeting.Operation, error)
	Deny(meeting.ProposalID) (meeting.Denial, error)
}

type CalendarEvents interface {
	CreateEvent(context.Context, meeting.EventArguments) (meeting.Event, error)
}

type ApprovalConsumer interface {
	Consume(context.Context, string, approvalauthority.Binding) error
	Health(context.Context) error
}

type Dependencies struct {
	Identity       IdentityVerifier
	Channel        Channel
	Policy         PolicyClient
	CoffeeStation  CoffeeStation
	Calendar       Calendar
	Proposals      ProposalStore
	Approvals      ApprovalConsumer
	CalendarEvents CalendarEvents
}

type coffeeStationStatusInput struct {
	StationID StationID `json:"station_id" jsonschema:"the fixed identifier of the coffee station"`
}

type findAvailabilityInput struct {
	Start freebusy.RFC3339 `json:"start" jsonschema:"RFC3339 start of the requested availability window"`
	End   freebusy.RFC3339 `json:"end" jsonschema:"RFC3339 end of the requested availability window"`
}

type submitMeetingInput struct {
	Start   freebusy.RFC3339 `json:"start" jsonschema:"RFC3339 start of the proposed meeting"`
	End     freebusy.RFC3339 `json:"end" jsonschema:"RFC3339 end of the proposed meeting"`
	Reason  string           `json:"reason" jsonschema:"reason shown to the Owner"`
	Contact string           `json:"contact" jsonschema:"requester contact shown to the Owner"`
}

type proposalReferenceInput struct {
	ProposalID meeting.ProposalID `json:"proposal_id"`
}

type approveMeetingInput struct {
	ProposalID meeting.ProposalID `json:"proposal_id"`
	Approval   string             `json:"approval" jsonschema:"short-lived exact Approval from the Approval Authority"`
}

func NewHandler(deps Dependencies) http.Handler {
	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(request *http.Request) *mcp.Server {
			identity, ok := request.Context().Value(identityContextKey{}).(TrustedIdentity)
			if !ok {
				return newMCPServer(deps, SecurityContext{})
			}
			return newMCPServer(deps, SecurityContext{
				Subject:          identity.Subject,
				Actor:            identity.Actor,
				Channel:          deps.Channel,
				TurnCapabilities: identity.TurnCapabilities,
			})
		},
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true},
	)

	mux := http.NewServeMux()
	mux.Handle("/mcp", authenticate(deps.Identity, mcpHandler))
	mux.HandleFunc("GET /healthz", healthHandler(deps))
	return mux
}

type identityContextKey struct{}

func authenticate(identity IdentityVerifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		const prefix = "Bearer "
		authorization := request.Header.Get("Authorization")
		if identity == nil || !strings.HasPrefix(authorization, prefix) || len(authorization) == len(prefix) {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		trusted, err := identity.Verify(request.Context(), strings.TrimPrefix(authorization, prefix))
		if err != nil {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(response, request.WithContext(context.WithValue(request.Context(), identityContextKey{}, trusted)))
	})
}

func newMCPServer(deps Dependencies, securityContext SecurityContext) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "agent-tool-guardrails",
		Version: "v0.1.0",
	}, nil)
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, request mcp.Request) (mcp.Result, error) {
			if method != "tools/list" {
				return next(ctx, method, request)
			}
			result, err := next(ctx, method, request)
			if err != nil {
				return nil, err
			}
			listed, ok := result.(*mcp.ListToolsResult)
			if !ok {
				return &mcp.ListToolsResult{}, nil
			}
			filtered := make([]*mcp.Tool, 0, len(listed.Tools))
			for _, tool := range listed.Tools {
				decision, decisionErr := deps.Policy.Decide(ctx, PolicyInput{
					SecurityContext: securityContext,
					Operation:       discoverOperation,
					Tool:            ToolName(tool.Name),
				})
				if decisionErr == nil && decision.Allow {
					filtered = append(filtered, tool)
				}
			}
			listed.Tools = filtered
			return listed, nil
		}
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        string(coffeeStationStatusTool),
		Description: "Read the status of the demo coffee station.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input coffeeStationStatusInput) (*mcp.CallToolResult, CoffeeStationStatus, error) {
		decision, err := deps.Policy.Decide(ctx, PolicyInput{
			SecurityContext: securityContext,
			Operation:       executeOperation,
			Tool:            coffeeStationStatusTool,
			Arguments:       input,
		})
		if err != nil {
			return nil, CoffeeStationStatus{}, err
		}
		result := &mcp.CallToolResult{Meta: mcp.Meta{
			"decision_id":     decision.DecisionID,
			"policy_revision": decision.PolicyRevision,
		}}
		if !decision.Allow {
			result.SetError(errors.New("tool call denied by policy"))
			return result, CoffeeStationStatus{}, nil
		}

		status, err := deps.CoffeeStation.Status(ctx, input.StationID)
		if err != nil {
			return nil, CoffeeStationStatus{}, err
		}
		if status.StationID != input.StationID || (status.State != "ready" && status.State != "offline") {
			result.SetError(errors.New("adapter returned invalid coffee station status"))
			return result, CoffeeStationStatus{}, nil
		}
		return result, status, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        string(findAvailabilityTool),
		Description: "Return only available intervals from the isolated demo calendar.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input findAvailabilityInput) (*mcp.CallToolResult, freebusy.View, error) {
		start, startErr := input.Start.Time()
		end, endErr := input.End.Time()
		if startErr != nil || endErr != nil || !end.After(start) {
			result := &mcp.CallToolResult{}
			result.SetError(errors.New("invalid availability window"))
			return result, freebusy.View{}, nil
		}
		decision, err := deps.Policy.Decide(ctx, PolicyInput{
			SecurityContext: securityContext,
			Operation:       executeOperation,
			Tool:            findAvailabilityTool,
			Arguments:       input,
		})
		if err != nil {
			return nil, freebusy.View{}, err
		}
		result := &mcp.CallToolResult{Meta: mcp.Meta{
			"decision_id":     decision.DecisionID,
			"policy_revision": decision.PolicyRevision,
		}}
		if !decision.Allow {
			result.SetError(errors.New("tool call denied by policy"))
			return result, freebusy.View{}, nil
		}
		if deps.Calendar == nil {
			return nil, freebusy.View{}, errors.New("calendar is unavailable")
		}
		view, err := deps.Calendar.FindAvailability(ctx, freebusy.Window{Start: start, End: end})
		if err != nil {
			return nil, freebusy.View{}, err
		}
		previousEnd := start
		for _, interval := range view.AvailableIntervals {
			intervalStart, intervalStartErr := interval.Start.Time()
			intervalEnd, intervalEndErr := interval.End.Time()
			if intervalStartErr != nil || intervalEndErr != nil ||
				intervalStart.Before(start) || intervalEnd.After(end) ||
				!intervalEnd.After(intervalStart) || intervalStart.Before(previousEnd) {
				result.SetError(errors.New("calendar returned an invalid Free/Busy View"))
				return result, freebusy.View{}, nil
			}
			previousEnd = intervalEnd
		}
		return result, view, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        string(submitMeetingTool),
		Description: "Record a Meeting Proposal without creating a calendar event.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input submitMeetingInput) (*mcp.CallToolResult, meeting.Proposal, error) {
		start, startErr := input.Start.Time()
		end, endErr := input.End.Time()
		reason := strings.TrimSpace(input.Reason)
		contact := strings.TrimSpace(input.Contact)
		if startErr != nil || endErr != nil || !end.After(start) || end.Sub(start) > 2*time.Hour ||
			reason == "" || contact == "" || len(reason) > 200 || len(contact) > 320 {
			result := &mcp.CallToolResult{}
			result.SetError(errors.New("invalid Meeting Proposal"))
			return result, meeting.Proposal{}, nil
		}
		decision, err := deps.Policy.Decide(ctx, PolicyInput{
			SecurityContext: securityContext,
			Operation:       executeOperation,
			Tool:            submitMeetingTool,
			Arguments:       input,
		})
		if err != nil {
			return nil, meeting.Proposal{}, err
		}
		result := policyResult(decision)
		if !decision.Allow {
			result.SetError(errors.New("tool call denied by policy"))
			return result, meeting.Proposal{}, nil
		}
		if deps.Proposals == nil {
			return nil, meeting.Proposal{}, errors.New("Meeting Proposal store is unavailable")
		}
		proposal := deps.Proposals.Submit(string(securityContext.Subject), meeting.ProposalInput{
			Start: start, End: end, Reason: reason, Contact: contact,
		})
		return result, proposal, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        string(reviewMeetingTool),
		Description: "Show the Owner the exact normalized calendar operation for a Meeting Proposal.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input proposalReferenceInput) (*mcp.CallToolResult, meeting.Operation, error) {
		decision, err := deps.Policy.Decide(ctx, PolicyInput{
			SecurityContext: securityContext,
			Operation:       executeOperation,
			Tool:            reviewMeetingTool,
			Arguments:       input,
		})
		if err != nil {
			return nil, meeting.Operation{}, err
		}
		result := policyResult(decision)
		if !decision.Allow {
			result.SetError(errors.New("tool call denied by policy"))
			return result, meeting.Operation{}, nil
		}
		if deps.Proposals == nil {
			return nil, meeting.Operation{}, errors.New("Meeting Proposal store is unavailable")
		}
		operation, err := deps.Proposals.Review(input.ProposalID)
		if err != nil {
			result.SetError(err)
			return result, meeting.Operation{}, nil
		}
		return result, operation, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        string(approveMeetingTool),
		Description: "Create one calendar event after consuming the Owner's exact Approval.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input approveMeetingInput) (*mcp.CallToolResult, meeting.Event, error) {
		decision, err := deps.Policy.Decide(ctx, PolicyInput{
			SecurityContext: securityContext,
			Operation:       executeOperation,
			Tool:            approveMeetingTool,
			Arguments:       proposalReferenceInput{ProposalID: input.ProposalID},
		})
		if err != nil {
			return nil, meeting.Event{}, err
		}
		result := policyResult(decision)
		if !decision.Allow {
			result.SetError(errors.New("tool call denied by policy"))
			return result, meeting.Event{}, nil
		}
		if deps.Proposals == nil || deps.Approvals == nil || deps.CalendarEvents == nil {
			return nil, meeting.Event{}, errors.New("approved meeting dependencies are unavailable")
		}
		operation, err := deps.Proposals.Review(input.ProposalID)
		if err != nil {
			result.SetError(err)
			return result, meeting.Event{}, nil
		}
		binding := approvalauthority.Binding{
			Subject:   string(securityContext.Subject),
			Actor:     string(securityContext.Actor),
			Tool:      operation.Tool,
			Arguments: operation.Arguments,
			TraceID:   string(operation.TraceID),
		}
		if err := deps.Approvals.Consume(ctx, input.Approval, binding); err != nil {
			result.SetError(errors.New("exact Approval denied"))
			return result, meeting.Event{}, nil
		}
		event, err := deps.CalendarEvents.CreateEvent(ctx, operation.Arguments)
		if err != nil {
			return nil, meeting.Event{}, err
		}
		if event.EventID == "" {
			result.SetError(errors.New("calendar returned an invalid event"))
			return result, meeting.Event{}, nil
		}
		return result, event, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        string(denyMeetingTool),
		Description: "Record the Owner's explicit denial of a Meeting Proposal without a calendar effect.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input proposalReferenceInput) (*mcp.CallToolResult, meeting.Denial, error) {
		decision, err := deps.Policy.Decide(ctx, PolicyInput{
			SecurityContext: securityContext, Operation: executeOperation, Tool: denyMeetingTool, Arguments: input,
		})
		if err != nil {
			return nil, meeting.Denial{}, err
		}
		result := policyResult(decision)
		if !decision.Allow {
			result.SetError(errors.New("tool call denied by policy"))
			return result, meeting.Denial{}, nil
		}
		if deps.Proposals == nil {
			return nil, meeting.Denial{}, errors.New("Meeting Proposal store is unavailable")
		}
		denial, err := deps.Proposals.Deny(input.ProposalID)
		if err != nil {
			result.SetError(err)
			return result, meeting.Denial{}, nil
		}
		return result, denial, nil
	})

	return server
}

func policyResult(decision PolicyDecision) *mcp.CallToolResult {
	return &mcp.CallToolResult{Meta: mcp.Meta{
		"decision_id":     decision.DecisionID,
		"policy_revision": decision.PolicyRevision,
	}}
}

func healthHandler(deps Dependencies) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if err := deps.Policy.Health(request.Context()); err != nil {
			response.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(response).Encode(map[string]string{
				"status": "unavailable",
				"policy": "unavailable",
			})
			return
		}
		if err := deps.CoffeeStation.Health(request.Context()); err != nil {
			response.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(response).Encode(map[string]string{
				"status":   "unavailable",
				"policy":   "ready",
				"resource": "unavailable",
			})
			return
		}
		if deps.Calendar != nil {
			if err := deps.Calendar.Health(request.Context()); err != nil {
				response.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(response).Encode(map[string]string{
					"status":   "unavailable",
					"policy":   "ready",
					"resource": "unavailable",
				})
				return
			}
		}
		_ = json.NewEncoder(response).Encode(map[string]string{
			"status":   "ready",
			"policy":   "ready",
			"resource": "ready",
		})
	}
}
