package telegramadapter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nahtao97/agent-tool-guardrails/internal/approvalauthority"
	"github.com/nahtao97/agent-tool-guardrails/internal/meeting"
	"github.com/nahtao97/agent-tool-guardrails/internal/oidcclient"
	"github.com/nahtao97/agent-tool-guardrails/internal/outlook"
	"golang.org/x/oauth2"
)

type GatewayClientConfig struct {
	Endpoint      string
	TokenEndpoint string
	ClientID      string
	ClientSecret  string
	Subject       Subject
	Username      string
	Password      string
	OwnerSubject  Subject
	OwnerUsername string
	OwnerPassword string
	Approvals     ApprovalIssuer
	HTTPClient    *http.Client
}

type ApprovalIssuer interface {
	Issue(context.Context, approvalauthority.Binding) (string, error)
}

type GatewayClient struct {
	config GatewayClientConfig
}

func NewGatewayClient(config GatewayClientConfig) *GatewayClient {
	return &GatewayClient{config: config}
}

func (client *GatewayClient) FindAvailability(
	ctx context.Context,
	identity TrustedTelegramIdentity,
	query AvailabilityQuery,
) ([]AvailableInterval, error) {
	session, err := client.connect(ctx, identity)
	if err != nil {
		return nil, fmt.Errorf("connect Telegram Actor to gateway: %w", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "calendar.find_availability",
		Arguments: map[string]any{
			"start": query.Start.Format("2006-01-02T15:04:05Z07:00"),
			"end":   query.End.Format("2006-01-02T15:04:05Z07:00"),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("call availability Tool: %w", err)
	}
	if result.IsError {
		return nil, result.GetError()
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		return nil, fmt.Errorf("encode Free/Busy View: %w", err)
	}
	var view struct {
		AvailableIntervals []AvailableInterval `json:"available_intervals"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&view); err != nil {
		return nil, fmt.Errorf("decode Free/Busy View: %w", err)
	}
	return view.AvailableIntervals, nil
}

func (client *GatewayClient) SubmitProposal(ctx context.Context, identity TrustedTelegramIdentity, input meeting.ProposalInput) (meeting.Proposal, error) {
	session, err := client.connect(ctx, identity)
	if err != nil {
		return meeting.Proposal{}, err
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "calendar.submit_meeting_proposal",
		Arguments: map[string]any{
			"start": input.Start.UTC().Format(time.RFC3339), "end": input.End.UTC().Format(time.RFC3339),
			"reason": input.Reason, "contact": input.Contact,
		},
	})
	if err != nil || result.IsError {
		return meeting.Proposal{}, toolError("submit Meeting Proposal", result, err)
	}
	var proposal meeting.Proposal
	if err := decodeStructured(result.StructuredContent, &proposal); err != nil {
		return meeting.Proposal{}, err
	}
	return proposal, nil
}

func (client *GatewayClient) ReviewProposal(ctx context.Context, identity TrustedTelegramIdentity, id meeting.ProposalID) (meeting.Operation, error) {
	session, err := client.connectWithScopes(ctx, identity, []string{"calendar.meeting.approve"})
	if err != nil {
		return meeting.Operation{}, err
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "calendar.review_meeting_proposal", Arguments: map[string]any{"proposal_id": id}})
	if err != nil || result.IsError {
		return meeting.Operation{}, toolError("review Meeting Proposal", result, err)
	}
	var operation meeting.Operation
	if err := decodeStructured(result.StructuredContent, &operation); err != nil {
		return meeting.Operation{}, err
	}
	if identity.Subject != client.config.OwnerSubject || client.config.Approvals == nil {
		return meeting.Operation{}, errors.New("only the Owner can review an exact Approval")
	}
	approval, err := client.config.Approvals.Issue(ctx, approvalauthority.Binding{
		Subject: string(identity.Subject), Actor: string(identity.Actor), Tool: operation.Tool,
		Arguments: operation.Arguments, TraceID: string(operation.TraceID),
	})
	if err != nil {
		return meeting.Operation{}, fmt.Errorf("issue reviewed exact Approval: %w", err)
	}
	operation.Approval = meeting.ApprovalToken(approval)
	return operation, nil
}

func (client *GatewayClient) ApproveProposal(ctx context.Context, identity TrustedTelegramIdentity, id meeting.ProposalID, approval meeting.ApprovalToken) (meeting.Event, error) {
	if identity.Subject != client.config.OwnerSubject || approval == "" {
		return meeting.Event{}, errors.New("only the Owner can request an exact Approval")
	}
	session, err := client.connectWithScopes(ctx, identity, []string{"calendar.meeting.approve"})
	if err != nil {
		return meeting.Event{}, err
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "calendar.approve_meeting_proposal", Arguments: map[string]any{"proposal_id": id, "approval": string(approval)},
	})
	if err != nil || result.IsError {
		return meeting.Event{}, toolError("approve Meeting Proposal", result, err)
	}
	var event meeting.Event
	if err := decodeStructured(result.StructuredContent, &event); err != nil {
		return meeting.Event{}, err
	}
	return event, nil
}

func (client *GatewayClient) DenyProposal(ctx context.Context, identity TrustedTelegramIdentity, id meeting.ProposalID, approval meeting.ApprovalToken) (meeting.Denial, error) {
	if identity.Subject != client.config.OwnerSubject || approval == "" {
		return meeting.Denial{}, errors.New("only the Owner can deny a Meeting Proposal")
	}
	session, err := client.connectWithScopes(ctx, identity, []string{"calendar.meeting.approve"})
	if err != nil {
		return meeting.Denial{}, err
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "calendar.deny_meeting_proposal", Arguments: map[string]any{"proposal_id": id, "approval": string(approval)}})
	if err != nil || result.IsError {
		return meeting.Denial{}, toolError("deny Meeting Proposal", result, err)
	}
	var denial meeting.Denial
	if err := decodeStructured(result.StructuredContent, &denial); err != nil {
		return meeting.Denial{}, err
	}
	return denial, nil
}

func (client *GatewayClient) ReviewUnlock(ctx context.Context, identity TrustedTelegramIdentity, deviceID SmartLockDeviceID) (SmartLockOperation, error) {
	if identity.Subject != client.config.OwnerSubject || deviceID != "demo-front-door" || client.config.Approvals == nil {
		return SmartLockOperation{}, errors.New("only the Owner can review the fixed smart-lock operation")
	}
	session, err := client.connectWithScopes(ctx, identity, []string{"smart_lock.write"})
	if err != nil {
		return SmartLockOperation{}, err
	}
	defer session.Close()
	listed, err := session.ListTools(ctx, nil)
	if err != nil {
		return SmartLockOperation{}, fmt.Errorf("discover smart-lock Tool: %w", err)
	}
	found := false
	for _, tool := range listed.Tools {
		found = found || tool.Name == "smart_lock.unlock"
	}
	if !found {
		return SmartLockOperation{}, errors.New("smart-lock Tool is not authorized for this turn")
	}
	traceBytes := make([]byte, 16)
	if _, err := rand.Read(traceBytes); err != nil {
		return SmartLockOperation{}, fmt.Errorf("create smart-lock trace: %w", err)
	}
	operation := SmartLockOperation{
		Tool: "smart_lock.unlock", Arguments: SmartLockArguments{DeviceID: deviceID}, TraceID: "smart-lock-trace-" + hex.EncodeToString(traceBytes),
	}
	approval, err := client.config.Approvals.Issue(ctx, approvalauthority.Binding{
		Subject: string(identity.Subject), Actor: string(identity.Actor), Tool: operation.Tool,
		Arguments: operation.Arguments, TraceID: operation.TraceID,
	})
	if err != nil {
		return SmartLockOperation{}, fmt.Errorf("issue exact smart-lock Approval: %w", err)
	}
	operation.Approval = meeting.ApprovalToken(approval)
	return operation, nil
}

func (client *GatewayClient) Unlock(ctx context.Context, identity TrustedTelegramIdentity, deviceID SmartLockDeviceID, approval meeting.ApprovalToken) (SmartLockState, error) {
	if identity.Subject != client.config.OwnerSubject || deviceID != "demo-front-door" || approval == "" {
		return SmartLockState{}, errors.New("only the Owner can unlock the fixed demo smart lock")
	}
	session, err := client.connectWithScopes(ctx, identity, []string{"smart_lock.write"})
	if err != nil {
		return SmartLockState{}, err
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "smart_lock.unlock", Arguments: map[string]any{"device_id": deviceID, "approval": string(approval)},
	})
	if err != nil || result.IsError {
		return SmartLockState{}, toolError("unlock smart lock", result, err)
	}
	var state SmartLockState
	if err := decodeStructured(result.StructuredContent, &state); err != nil {
		return SmartLockState{}, err
	}
	if state.DeviceID != deviceID || state.State != "unlocked" {
		return SmartLockState{}, errors.New("gateway returned invalid smart-lock state")
	}
	return state, nil
}

func (client *GatewayClient) SearchMessages(ctx context.Context, identity TrustedTelegramIdentity, query OutlookSearchQuery) ([]OutlookSearchResult, error) {
	if identity.Subject != client.config.OwnerSubject {
		return nil, errors.New("only the Owner can grant an Outlook read Turn Capability")
	}
	session, err := client.connectWithScopes(ctx, identity, []string{"outlook.mail.read"})
	if err != nil {
		return nil, err
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "outlook.search_messages", Arguments: map[string]any{"query": query.Query, "limit": query.Limit},
	})
	if err != nil || result.IsError {
		return nil, toolError("search Outlook", result, err)
	}
	var view struct {
		Messages []outlook.SearchResult `json:"messages"`
	}
	if err := decodeStructured(result.StructuredContent, &view); err != nil {
		return nil, err
	}
	return view.Messages, nil
}

func (client *GatewayClient) ReadMessage(ctx context.Context, identity TrustedTelegramIdentity, messageID OutlookMessageID) (OutlookMessageView, error) {
	if identity.Subject != client.config.OwnerSubject {
		return OutlookMessageView{}, errors.New("only the Owner can grant an Outlook read Turn Capability")
	}
	session, err := client.connectWithScopes(ctx, identity, []string{"outlook.mail.read"})
	if err != nil {
		return OutlookMessageView{}, err
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "outlook.read_message", Arguments: map[string]any{"message_id": messageID},
	})
	if err != nil || result.IsError {
		return OutlookMessageView{}, toolError("read Outlook", result, err)
	}
	var view outlook.MessageView
	if err := decodeStructured(result.StructuredContent, &view); err != nil {
		return OutlookMessageView{}, err
	}
	return view, nil
}

func (client *GatewayClient) connect(ctx context.Context, identity TrustedTelegramIdentity) (*mcp.ClientSession, error) {
	return client.connectWithScopes(ctx, identity, nil)
}

func (client *GatewayClient) connectWithScopes(ctx context.Context, identity TrustedTelegramIdentity, scopes []string) (*mcp.ClientSession, error) {
	if identity.Actor != "telegram-agent" || identity.Channel != "telegram" {
		return nil, errors.New("trusted Telegram identity does not match gateway credentials")
	}
	username, password := client.config.Username, client.config.Password
	if identity.Subject == client.config.OwnerSubject {
		username, password = client.config.OwnerUsername, client.config.OwnerPassword
	} else if identity.Subject != client.config.Subject {
		return nil, errors.New("trusted Telegram Subject does not match gateway credentials")
	}
	token, err := (oidcclient.Client{
		Endpoint: client.config.TokenEndpoint, ClientID: client.config.ClientID,
		ClientSecret: client.config.ClientSecret, HTTPClient: client.config.HTTPClient,
	}).PasswordTokenWithScopes(ctx, username, password, scopes)
	if err != nil {
		return nil, err
	}
	baseTransport := http.DefaultTransport
	if client.config.HTTPClient != nil && client.config.HTTPClient.Transport != nil {
		baseTransport = client.config.HTTPClient.Transport
	}
	authorizedClient := &http.Client{Transport: &oauth2.Transport{
		Source: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}), Base: baseTransport,
	}}
	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "telegram-adapter", Version: "v0.4.0"}, nil)
	return mcpClient.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: client.config.Endpoint, DisableStandaloneSSE: true, HTTPClient: authorizedClient,
	}, nil)
}

func decodeStructured(value any, destination any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	return decoder.Decode(destination)
}

func toolError(action string, result *mcp.CallToolResult, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	if result != nil && result.IsError {
		return fmt.Errorf("%s: %w", action, result.GetError())
	}
	return errors.New(action + " failed")
}
