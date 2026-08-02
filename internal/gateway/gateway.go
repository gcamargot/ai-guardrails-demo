package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nahtao97/agent-tool-guardrails/internal/approvalauthority"
	"github.com/nahtao97/agent-tool-guardrails/internal/development"
	"github.com/nahtao97/agent-tool-guardrails/internal/freebusy"
	"github.com/nahtao97/agent-tool-guardrails/internal/meeting"
	"github.com/nahtao97/agent-tool-guardrails/internal/outlook"
	"github.com/nahtao97/agent-tool-guardrails/internal/smartlock"
)

type Subject string
type Actor string
type Channel string
type Capability string
type ToolName string
type PolicyOperation string
type StationID string
type LockDeviceID = smartlock.DeviceID

const (
	coffeeStationStatusTool ToolName        = "coffee_station.get_status"
	findAvailabilityTool    ToolName        = "calendar.find_availability"
	submitMeetingTool       ToolName        = "calendar.submit_meeting_proposal"
	reviewMeetingTool       ToolName        = "calendar.review_meeting_proposal"
	approveMeetingTool      ToolName        = "calendar.approve_meeting_proposal"
	denyMeetingTool         ToolName        = "calendar.deny_meeting_proposal"
	unlockSmartLockTool     ToolName        = smartlock.UnlockTool
	searchOutlookTool       ToolName        = "outlook.search_messages"
	readOutlookTool         ToolName        = "outlook.read_message"
	readRepositoryTool      ToolName        = "dev.read_repository"
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
	Reason         string `json:"reason"`
}

type AuditRecord struct {
	TraceID     string          `json:"trace_id,omitempty"`
	DecisionID  string          `json:"decision_id"`
	SubjectKind string          `json:"subject_kind"`
	Actor       Actor           `json:"actor"`
	Channel     Channel         `json:"channel"`
	Operation   PolicyOperation `json:"operation"`
	Tool        ToolName        `json:"tool"`
	Outcome     string          `json:"outcome"`
	Reason      string          `json:"reason"`
}

type AuditSink interface {
	Record(context.Context, AuditRecord) error
	Health(context.Context) error
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
	BeginApproval(meeting.ProposalID) (meeting.Operation, bool, error)
	CompleteApproval(meeting.ProposalID)
	CancelApproval(meeting.ProposalID)
}

type CalendarEvents interface {
	CreateEvent(context.Context, meeting.EventArguments) (meeting.Event, error)
}

type Outlook interface {
	SearchMessages(context.Context, outlook.SearchQuery) ([]outlook.SearchResult, error)
	ReadMessage(context.Context, outlook.MessageID) (outlook.MessageView, error)
	Health(context.Context) error
}

type ApprovalConsumer interface {
	ConsumeExact(context.Context, string, approvalauthority.Binding) (approvalauthority.Consumption, error)
	Health(context.Context) error
}

type SmartLock interface {
	Unlock(context.Context, smartlock.DeviceID) (smartlock.State, error)
	Health(context.Context) error
}

type SmartLockState = smartlock.State
type RepositoryPath = development.RepositoryPath
type RepositoryDocument = development.RepositoryDocument

type DevelopmentRepository interface {
	Read(context.Context, development.RepositoryPath) (development.RepositoryDocument, error)
	Health(context.Context) error
}

type OAuthResource struct {
	Resource             string
	MetadataURL          string
	AuthorizationServers []string
	Scopes               []Capability
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
	SmartLock      SmartLock
	Outlook        Outlook
	Audit          AuditSink
	OAuth          OAuthResource
	Development    DevelopmentRepository
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
	ProposalID meeting.ProposalID    `json:"proposal_id"`
	Approval   meeting.ApprovalToken `json:"approval" jsonschema:"short-lived exact Approval from the Approval Authority"`
}

type unlockSmartLockInput struct {
	DeviceID smartlock.DeviceID    `json:"device_id" jsonschema:"the fixed demo smart-lock identifier"`
	TraceID  smartlock.TraceID     `json:"trace_id" jsonschema:"the trace shown during exact Owner review"`
	Approval meeting.ApprovalToken `json:"approval" jsonschema:"short-lived exact Approval from the Approval Authority"`
}

type searchOutlookInput struct {
	Query outlook.Query `json:"query" jsonschema:"exact mailbox search requested by the Owner"`
	Limit int           `json:"limit" jsonschema:"maximum number of minimized matches"`
}

type readOutlookInput struct {
	MessageID outlook.MessageID `json:"message_id" jsonschema:"exact demo message identifier"`
}

type readRepositoryInput struct {
	Path development.RepositoryPath `json:"path" jsonschema:"fixed allowlisted repository artifact"`
}

type searchOutlookOutput struct {
	Messages []outlook.SearchResult `json:"messages"`
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
	mux.Handle("/mcp", authenticate(deps.Identity, deps.OAuth, mcpHandler))
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", oauthResourceMetadata(deps.OAuth))
	mux.HandleFunc("GET /healthz", healthHandler(deps))
	return mux
}

type identityContextKey struct{}

func authenticate(identity IdentityVerifier, oauth OAuthResource, next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		const prefix = "Bearer "
		authorization := request.Header.Get("Authorization")
		if identity == nil || !strings.HasPrefix(authorization, prefix) || len(authorization) == len(prefix) {
			writeOAuthChallenge(response, oauth)
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		trusted, err := identity.Verify(request.Context(), strings.TrimPrefix(authorization, prefix))
		if err != nil {
			writeOAuthChallenge(response, oauth)
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(response, request.WithContext(context.WithValue(request.Context(), identityContextKey{}, trusted)))
	})
}

func writeOAuthChallenge(response http.ResponseWriter, oauth OAuthResource) {
	if oauth.MetadataURL == "" {
		return
	}
	challenge := fmt.Sprintf(`Bearer resource_metadata=%q`, oauth.MetadataURL)
	if len(oauth.Scopes) > 0 {
		scopes := make([]string, len(oauth.Scopes))
		for index, scope := range oauth.Scopes {
			scopes[index] = string(scope)
		}
		challenge += fmt.Sprintf(`, scope=%q`, strings.Join(scopes, " "))
	}
	response.Header().Set("WWW-Authenticate", challenge)
}

func oauthResourceMetadata(oauth OAuthResource) http.HandlerFunc {
	return func(response http.ResponseWriter, _ *http.Request) {
		if oauth.Resource == "" || len(oauth.AuthorizationServers) == 0 {
			http.Error(response, "not found", http.StatusNotFound)
			return
		}
		scopes := make([]string, len(oauth.Scopes))
		for index, scope := range oauth.Scopes {
			scopes[index] = string(scope)
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{
			"resource":                 oauth.Resource,
			"authorization_servers":    oauth.AuthorizationServers,
			"scopes_supported":         scopes,
			"bearer_methods_supported": []string{"header"},
		})
	}
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
				if ToolName(tool.Name) == unlockSmartLockTool {
					auditErr := recordAudit(
						ctx, deps.Audit, securityContext, discoverOperation, unlockSmartLockTool, decision, "",
						decisionOutcome(decision, decisionErr), decisionReason(decision, decisionErr),
					)
					if auditErr != nil {
						return nil, fmt.Errorf("record smart-lock discovery audit: %w", auditErr)
					}
					if decisionErr != nil {
						continue
					}
				}
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
		Name:        string(readRepositoryTool),
		Description: "Read the fixed allowlisted CONTEXT.md artifact from the demo repository.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input readRepositoryInput) (*mcp.CallToolResult, development.RepositoryDocument, error) {
		if input.Path != development.ContextPath {
			result := &mcp.CallToolResult{}
			result.SetError(errors.New("repository path is not allowlisted"))
			return result, development.RepositoryDocument{}, nil
		}
		result, allowed, err := authorize(ctx, deps.Policy, securityContext, readRepositoryTool, input)
		if err != nil {
			return nil, development.RepositoryDocument{}, err
		}
		if !allowed {
			return result, development.RepositoryDocument{}, nil
		}
		if deps.Development == nil {
			return nil, development.RepositoryDocument{}, errors.New("development repository is unavailable")
		}
		document, err := deps.Development.Read(ctx, input.Path)
		if err != nil {
			return nil, development.RepositoryDocument{}, err
		}
		if err := document.Validate(input.Path); err != nil {
			result.SetError(err)
			return result, development.RepositoryDocument{}, nil
		}
		return result, document, nil
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
		result, allowed, err := authorize(ctx, deps.Policy, securityContext, submitMeetingTool, input)
		if err != nil {
			return nil, meeting.Proposal{}, err
		}
		if !allowed {
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
		result, allowed, err := authorize(ctx, deps.Policy, securityContext, reviewMeetingTool, input)
		if err != nil {
			return nil, meeting.Operation{}, err
		}
		if !allowed {
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
		result, allowed, err := authorize(ctx, deps.Policy, securityContext, approveMeetingTool, proposalReferenceInput{ProposalID: input.ProposalID})
		if err != nil {
			return nil, meeting.Event{}, err
		}
		if !allowed {
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
		if _, err := deps.Approvals.ConsumeExact(ctx, string(input.Approval), exactBinding(securityContext, operation)); err != nil {
			result.SetError(errors.New("exact Approval denied"))
			return result, meeting.Event{}, nil
		}
		approvedOperation, retry, err := deps.Proposals.BeginApproval(input.ProposalID)
		if err != nil {
			result.SetError(err)
			return result, meeting.Event{}, nil
		}
		event, err := deps.CalendarEvents.CreateEvent(ctx, approvedOperation.Arguments)
		if err != nil {
			if !retry {
				deps.Proposals.CancelApproval(input.ProposalID)
			}
			return nil, meeting.Event{}, err
		}
		if !retry {
			deps.Proposals.CompleteApproval(input.ProposalID)
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
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input approveMeetingInput) (*mcp.CallToolResult, meeting.Denial, error) {
		result, allowed, err := authorize(ctx, deps.Policy, securityContext, denyMeetingTool, proposalReferenceInput{ProposalID: input.ProposalID})
		if err != nil {
			return nil, meeting.Denial{}, err
		}
		if !allowed {
			return result, meeting.Denial{}, nil
		}
		if deps.Proposals == nil || deps.Approvals == nil {
			return nil, meeting.Denial{}, errors.New("Meeting Proposal resolution is unavailable")
		}
		operation, err := deps.Proposals.Review(input.ProposalID)
		if err != nil {
			result.SetError(err)
			return result, meeting.Denial{}, nil
		}
		if _, err := deps.Approvals.ConsumeExact(ctx, string(input.Approval), exactBinding(securityContext, operation)); err != nil {
			result.SetError(errors.New("exact Approval denied"))
			return result, meeting.Denial{}, nil
		}
		denial, err := deps.Proposals.Deny(input.ProposalID)
		if err != nil {
			result.SetError(err)
			return result, meeting.Denial{}, nil
		}
		return result, denial, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        string(unlockSmartLockTool),
		Description: "Unlock only the fixed simulated front-door lock after exact Owner Approval.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input unlockSmartLockInput) (*mcp.CallToolResult, SmartLockState, error) {
		arguments := smartlock.Arguments{DeviceID: input.DeviceID}
		decision, err := deps.Policy.Decide(ctx, PolicyInput{
			SecurityContext: securityContext, Operation: executeOperation, Tool: unlockSmartLockTool, Arguments: arguments,
		})
		if err != nil {
			if auditErr := recordAudit(ctx, deps.Audit, securityContext, executeOperation, unlockSmartLockTool, PolicyDecision{DecisionID: "unavailable"}, "", "deny", "policy_unavailable"); auditErr != nil {
				return nil, SmartLockState{}, errors.Join(err, auditErr)
			}
			return nil, SmartLockState{}, err
		}
		result := policyResult(decision)
		if !decision.Allow {
			if err := recordAudit(ctx, deps.Audit, securityContext, executeOperation, unlockSmartLockTool, decision, "", "deny", decision.Reason); err != nil {
				return nil, SmartLockState{}, fmt.Errorf("record denied smart-lock audit: %w", err)
			}
			result.SetError(errors.New("tool call denied by policy"))
			return result, SmartLockState{}, nil
		}
		if deps.Approvals == nil || deps.SmartLock == nil {
			return nil, SmartLockState{}, errors.New("smart-lock dependencies are unavailable")
		}
		consumed, err := deps.Approvals.ConsumeExact(ctx, string(input.Approval), approvalauthority.Binding{
			Subject: string(securityContext.Subject), Actor: string(securityContext.Actor), Tool: string(unlockSmartLockTool),
			Arguments: arguments, TraceID: string(input.TraceID),
		})
		if err != nil {
			traceID := consumed.TraceID
			if traceID == "" {
				traceID = string(input.TraceID)
			}
			if auditErr := recordAudit(ctx, deps.Audit, securityContext, executeOperation, unlockSmartLockTool, decision, traceID, "deny", "exact_approval_denied"); auditErr != nil {
				return nil, SmartLockState{}, errors.Join(err, auditErr)
			}
			result.SetError(errors.New("exact Approval denied"))
			return result, SmartLockState{}, nil
		}
		if err := recordAudit(ctx, deps.Audit, securityContext, executeOperation, unlockSmartLockTool, decision, consumed.TraceID, "allow", decision.Reason); err != nil {
			result.SetError(errors.New("audit record unavailable"))
			return result, SmartLockState{}, nil
		}
		state, err := deps.SmartLock.Unlock(ctx, input.DeviceID)
		if err != nil {
			return nil, SmartLockState{}, err
		}
		if state.DeviceID != input.DeviceID || state.State != smartlock.StateUnlocked {
			result.SetError(errors.New("smart-lock adapter returned invalid state"))
			return result, SmartLockState{}, nil
		}
		return result, state, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        string(searchOutlookTool),
		Description: "Search the isolated demo mailbox and return minimized message metadata.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input searchOutlookInput) (*mcp.CallToolResult, searchOutlookOutput, error) {
		query := outlook.SearchQuery{Query: input.Query, Limit: input.Limit}
		if err := query.Validate(); err != nil {
			result := &mcp.CallToolResult{}
			result.SetError(err)
			return result, searchOutlookOutput{}, nil
		}
		result, allowed, err := authorize(ctx, deps.Policy, securityContext, searchOutlookTool, input)
		if err != nil {
			return nil, searchOutlookOutput{}, err
		}
		if !allowed {
			return result, searchOutlookOutput{}, nil
		}
		if deps.Outlook == nil {
			return nil, searchOutlookOutput{}, errors.New("Outlook is unavailable")
		}
		messages, err := deps.Outlook.SearchMessages(ctx, query)
		if err != nil {
			return nil, searchOutlookOutput{}, err
		}
		if err := outlook.ValidateSearchResults(messages, input.Limit); err != nil {
			result.SetError(err)
			return result, searchOutlookOutput{}, nil
		}
		return result, searchOutlookOutput{Messages: messages}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        string(readOutlookTool),
		Description: "Read one exact demo message as minimized Untrusted Content.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input readOutlookInput) (*mcp.CallToolResult, outlook.MessageView, error) {
		if err := input.MessageID.Validate(); err != nil {
			result := &mcp.CallToolResult{}
			result.SetError(err)
			return result, outlook.MessageView{}, nil
		}
		result, allowed, err := authorize(ctx, deps.Policy, securityContext, readOutlookTool, input)
		if err != nil {
			return nil, outlook.MessageView{}, err
		}
		if !allowed {
			return result, outlook.MessageView{}, nil
		}
		if deps.Outlook == nil {
			return nil, outlook.MessageView{}, errors.New("Outlook is unavailable")
		}
		view, err := deps.Outlook.ReadMessage(ctx, input.MessageID)
		if err != nil {
			return nil, outlook.MessageView{}, err
		}
		if err := view.Validate(input.MessageID); err != nil {
			result.SetError(err)
			return result, outlook.MessageView{}, nil
		}
		return result, view, nil
	})

	return server
}

func policyResult(decision PolicyDecision) *mcp.CallToolResult {
	return &mcp.CallToolResult{Meta: mcp.Meta{
		"decision_id":     decision.DecisionID,
		"policy_revision": decision.PolicyRevision,
	}}
}

func authorize(ctx context.Context, policy PolicyClient, securityContext SecurityContext, tool ToolName, arguments any) (*mcp.CallToolResult, bool, error) {
	decision, err := policy.Decide(ctx, PolicyInput{
		SecurityContext: securityContext, Operation: executeOperation, Tool: tool, Arguments: arguments,
	})
	if err != nil {
		return nil, false, err
	}
	result := policyResult(decision)
	if !decision.Allow {
		result.SetError(errors.New("tool call denied by policy"))
		return result, false, nil
	}
	return result, true, nil
}

func exactBinding(securityContext SecurityContext, operation meeting.Operation) approvalauthority.Binding {
	return approvalauthority.Binding{
		Subject: string(securityContext.Subject), Actor: string(securityContext.Actor), Tool: operation.Tool,
		Arguments: operation.Arguments, TraceID: string(operation.TraceID),
	}
}

func recordAudit(ctx context.Context, sink AuditSink, securityContext SecurityContext, operation PolicyOperation, tool ToolName, decision PolicyDecision, traceID, outcome, reason string) error {
	if sink == nil {
		return errors.New("audit sink is unavailable")
	}
	return sink.Record(ctx, AuditRecord{
		TraceID: traceID, DecisionID: decision.DecisionID, SubjectKind: subjectKind(securityContext.Subject),
		Actor: securityContext.Actor, Channel: securityContext.Channel, Operation: operation, Tool: tool,
		Outcome: outcome, Reason: reason,
	})
}

func subjectKind(subject Subject) string {
	switch {
	case subject == "owner-subject-id":
		return "owner"
	case strings.HasPrefix(string(subject), "external-"):
		return "external"
	default:
		return "unknown"
	}
}

func decisionOutcome(decision PolicyDecision, err error) string {
	if err == nil && decision.Allow {
		return "allow"
	}
	return "deny"
}

func decisionReason(decision PolicyDecision, err error) string {
	if err != nil {
		return "policy_unavailable"
	}
	return decision.Reason
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
		if deps.Outlook != nil {
			if err := deps.Outlook.Health(request.Context()); err != nil {
				response.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(response).Encode(map[string]string{
					"status": "unavailable", "policy": "ready", "resource": "unavailable",
				})
				return
			}
		}
		if deps.SmartLock != nil {
			if err := deps.SmartLock.Health(request.Context()); err != nil {
				response.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(response).Encode(map[string]string{
					"status": "unavailable", "policy": "ready", "resource": "unavailable",
				})
				return
			}
		}
		if deps.Development != nil {
			if err := deps.Development.Health(request.Context()); err != nil {
				response.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(response).Encode(map[string]string{
					"status": "unavailable", "policy": "ready", "resource": "unavailable",
				})
				return
			}
		}
		if deps.Approvals != nil {
			if err := deps.Approvals.Health(request.Context()); err != nil {
				response.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(response).Encode(map[string]string{
					"status": "unavailable", "policy": "ready", "approval": "unavailable",
				})
				return
			}
		}
		if deps.Audit != nil {
			if err := deps.Audit.Health(request.Context()); err != nil {
				response.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(response).Encode(map[string]string{
					"status": "unavailable", "policy": "ready", "audit": "unavailable",
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
