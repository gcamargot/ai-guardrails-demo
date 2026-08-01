package telegramadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/freebusy"
	"github.com/nahtao97/agent-tool-guardrails/internal/meeting"
	"github.com/nahtao97/agent-tool-guardrails/internal/outlook"
)

type TelegramUserID int64
type Subject string
type Actor string
type Channel string

type TrustedTelegramIdentity struct {
	Subject Subject
	Actor   Actor
	Channel Channel
}

type AvailabilityQuery = freebusy.Window
type AvailableInterval = freebusy.AvailableInterval
type OutlookMessageID = outlook.MessageID
type OutlookQuery = outlook.Query
type OutlookSearchQuery = outlook.SearchQuery
type OutlookSearchResult = outlook.SearchResult
type OutlookMessageView = outlook.MessageView

type AvailabilityGateway interface {
	FindAvailability(context.Context, TrustedTelegramIdentity, AvailabilityQuery) ([]AvailableInterval, error)
}

type MeetingGateway interface {
	SubmitProposal(context.Context, TrustedTelegramIdentity, meeting.ProposalInput) (meeting.Proposal, error)
	ReviewProposal(context.Context, TrustedTelegramIdentity, meeting.ProposalID) (meeting.Operation, error)
	ApproveProposal(context.Context, TrustedTelegramIdentity, meeting.ProposalID, meeting.ApprovalToken) (meeting.Event, error)
	DenyProposal(context.Context, TrustedTelegramIdentity, meeting.ProposalID, meeting.ApprovalToken) (meeting.Denial, error)
}

type OutlookGateway interface {
	SearchMessages(context.Context, TrustedTelegramIdentity, OutlookSearchQuery) ([]OutlookSearchResult, error)
	ReadMessage(context.Context, TrustedTelegramIdentity, OutlookMessageID) (OutlookMessageView, error)
}

type Config struct {
	WebhookSecret     string
	VerifiedUsers     map[TelegramUserID]Subject
	OwnerSubject      Subject
	ClassifierURL     string
	HTTPClient        *http.Client
	Availability      AvailabilityGateway
	Meetings          MeetingGateway
	Outlook           OutlookGateway
	AvailabilityLimit int
	ProposalLimit     int
	RateLimitWindow   time.Duration
}

func NewHandler(config Config) http.Handler {
	client := config.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	limits := newRateLimits(config)
	commands := commandRouter{config: config, limits: limits}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"status":"ready"}`))
	})
	mux.HandleFunc("POST /telegram/webhook", func(response http.ResponseWriter, request *http.Request) {
		if config.WebhookSecret == "" || request.Header.Get("X-Telegram-Bot-Api-Secret-Token") != config.WebhookSecret {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		var update struct {
			Message struct {
				From struct {
					ID TelegramUserID `json:"id"`
				} `json:"from"`
				Text string `json:"text"`
			} `json:"message"`
		}
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&update); err != nil || update.Message.Text == "" {
			http.Error(response, "invalid Telegram update", http.StatusBadRequest)
			return
		}
		subject, verified := config.VerifiedUsers[update.Message.From.ID]
		if !verified {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}

		identity := TrustedTelegramIdentity{Subject: subject, Actor: "telegram-agent", Channel: "telegram"}
		if commands.Route(response, request, subject, identity, update.Message.Text) {
			return
		}

		if subject != config.OwnerSubject && !limits.allow(subject, "availability") {
			http.Error(response, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		query, err := classify(request.Context(), client, config.ClassifierURL, update.Message.Text)
		if err != nil {
			http.Error(response, "classification failed", http.StatusBadGateway)
			return
		}
		intervals, err := config.Availability.FindAvailability(request.Context(), identity, query)
		if err != nil {
			http.Error(response, "availability request failed", http.StatusBadGateway)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(struct {
			AvailableIntervals []AvailableInterval `json:"available_intervals"`
		}{AvailableIntervals: intervals})
	})
	return mux
}

type commandRouter struct {
	config Config
	limits *rateLimits
}

func (router commandRouter) Route(response http.ResponseWriter, request *http.Request, subject Subject, identity TrustedTelegramIdentity, command string) bool {
	switch {
	case strings.HasPrefix(command, "/outlook-search "):
		router.handleOutlookSearch(response, request, subject, identity, command)
		return true
	case strings.HasPrefix(command, "/outlook-read "):
		router.handleOutlookRead(response, request, subject, identity, command)
		return true
	case strings.HasPrefix(command, "/review "), strings.HasPrefix(command, "/approve "), strings.HasPrefix(command, "/deny "):
		router.handleMeetingResolution(response, request, subject, identity, command)
		return true
	case strings.HasPrefix(command, "/propose "):
		router.handleMeetingProposal(response, request, subject, identity, command)
		return true
	default:
		return false
	}
}

func (router commandRouter) handleOutlookSearch(response http.ResponseWriter, request *http.Request, subject Subject, identity TrustedTelegramIdentity, command string) {
	if subject != router.config.OwnerSubject || router.config.Outlook == nil {
		http.Error(response, "forbidden", http.StatusForbidden)
		return
	}
	query := OutlookSearchQuery{Query: OutlookQuery(strings.TrimSpace(strings.TrimPrefix(command, "/outlook-search "))), Limit: 5}
	if err := query.Validate(); err != nil {
		http.Error(response, "invalid Outlook search", http.StatusBadRequest)
		return
	}
	messages, err := router.config.Outlook.SearchMessages(request.Context(), identity, query)
	if err != nil {
		http.Error(response, "Outlook search failed", http.StatusBadGateway)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(struct {
		Messages []OutlookSearchResult `json:"messages"`
	}{Messages: messages})
}

func (router commandRouter) handleOutlookRead(response http.ResponseWriter, request *http.Request, subject Subject, identity TrustedTelegramIdentity, command string) {
	if subject != router.config.OwnerSubject || router.config.Outlook == nil {
		http.Error(response, "forbidden", http.StatusForbidden)
		return
	}
	messageID := OutlookMessageID(strings.TrimSpace(strings.TrimPrefix(command, "/outlook-read ")))
	if err := messageID.Validate(); err != nil {
		http.Error(response, "invalid Outlook message", http.StatusBadRequest)
		return
	}
	message, err := router.config.Outlook.ReadMessage(request.Context(), identity, messageID)
	if err != nil {
		http.Error(response, "Outlook read failed", http.StatusBadGateway)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(message)
}

func (router commandRouter) handleMeetingResolution(response http.ResponseWriter, request *http.Request, subject Subject, identity TrustedTelegramIdentity, text string) {
	if subject != router.config.OwnerSubject || router.config.Meetings == nil {
		http.Error(response, "forbidden", http.StatusForbidden)
		return
	}
	parts := strings.Fields(text)
	command := parts[0]
	if (command == "/review" && len(parts) != 2) || (command != "/review" && len(parts) != 3) {
		http.Error(response, "review the exact Meeting Proposal before resolving it", http.StatusBadRequest)
		return
	}
	proposalID := meeting.ProposalID(parts[1])
	if proposalID == "" {
		http.Error(response, "invalid Meeting Proposal reference", http.StatusBadRequest)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	if command == "/review" {
		operation, err := router.config.Meetings.ReviewProposal(request.Context(), identity, proposalID)
		if err != nil {
			http.Error(response, "Meeting Proposal review failed", http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(response).Encode(operation)
		return
	}
	if command == "/deny" {
		denial, err := router.config.Meetings.DenyProposal(request.Context(), identity, proposalID, meeting.ApprovalToken(parts[2]))
		if err != nil {
			http.Error(response, "Meeting Proposal denial failed", http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(response).Encode(denial)
		return
	}
	event, err := router.config.Meetings.ApproveProposal(request.Context(), identity, proposalID, meeting.ApprovalToken(parts[2]))
	if err != nil {
		http.Error(response, "Meeting Proposal approval failed", http.StatusBadGateway)
		return
	}
	_ = json.NewEncoder(response).Encode(event)
}

func (router commandRouter) handleMeetingProposal(response http.ResponseWriter, request *http.Request, subject Subject, identity TrustedTelegramIdentity, command string) {
	if subject != router.config.OwnerSubject && !router.limits.allow(subject, "proposal") {
		http.Error(response, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	proposalInput, err := parseProposal(strings.TrimPrefix(command, "/propose "))
	if err != nil || router.config.Meetings == nil || subject == router.config.OwnerSubject {
		http.Error(response, "invalid Meeting Proposal", http.StatusBadRequest)
		return
	}
	proposal, err := router.config.Meetings.SubmitProposal(request.Context(), identity, proposalInput)
	if err != nil {
		http.Error(response, "Meeting Proposal failed", http.StatusBadGateway)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(response).Encode(struct {
		MeetingProposal meeting.Proposal `json:"meeting_proposal"`
	}{MeetingProposal: proposal})
}

type rateLimitKey struct {
	Subject Subject
	Action  string
}

type rateLimitEntry struct {
	Started time.Time
	Count   int
}

type rateLimits struct {
	mu     sync.Mutex
	limits map[string]int
	window time.Duration
	items  map[rateLimitKey]rateLimitEntry
}

func newRateLimits(config Config) *rateLimits {
	availabilityLimit := config.AvailabilityLimit
	if availabilityLimit <= 0 {
		availabilityLimit = 10
	}
	proposalLimit := config.ProposalLimit
	if proposalLimit <= 0 {
		proposalLimit = 3
	}
	window := config.RateLimitWindow
	if window <= 0 {
		window = time.Hour
	}
	return &rateLimits{
		limits: map[string]int{"availability": availabilityLimit, "proposal": proposalLimit},
		window: window,
		items:  make(map[rateLimitKey]rateLimitEntry),
	}
}

func (limits *rateLimits) allow(subject Subject, action string) bool {
	limits.mu.Lock()
	defer limits.mu.Unlock()
	key := rateLimitKey{Subject: subject, Action: action}
	now := time.Now()
	entry := limits.items[key]
	if entry.Started.IsZero() || now.Sub(entry.Started) >= limits.window {
		limits.items[key] = rateLimitEntry{Started: now, Count: 1}
		return true
	}
	if entry.Count >= limits.limits[action] {
		return false
	}
	entry.Count++
	limits.items[key] = entry
	return true
}

func parseProposal(text string) (meeting.ProposalInput, error) {
	parts := strings.SplitN(text, " ", 4)
	if len(parts) != 4 || strings.TrimSpace(parts[2]) == "" || strings.TrimSpace(parts[3]) == "" {
		return meeting.ProposalInput{}, errors.New("proposal requires start, end, contact and reason")
	}
	start, startErr := time.Parse(time.RFC3339, parts[0])
	end, endErr := time.Parse(time.RFC3339, parts[1])
	if startErr != nil || endErr != nil || !end.After(start) {
		return meeting.ProposalInput{}, errors.New("invalid proposal interval")
	}
	return meeting.ProposalInput{Start: start, End: end, Contact: parts[2], Reason: strings.TrimSpace(parts[3])}, nil
}

func classify(ctx context.Context, client *http.Client, endpoint, text string) (AvailabilityQuery, error) {
	body, err := json.Marshal(map[string]string{"message": text})
	if err != nil {
		return AvailabilityQuery{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return AvailabilityQuery{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return AvailabilityQuery{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return AvailabilityQuery{}, errors.New("classifier returned a non-success response")
	}
	var interpretation struct {
		Start string `json:"start"`
		End   string `json:"end"`
	}
	if err := json.NewDecoder(response.Body).Decode(&interpretation); err != nil {
		return AvailabilityQuery{}, err
	}
	start, err := time.Parse(time.RFC3339, interpretation.Start)
	if err != nil {
		return AvailabilityQuery{}, err
	}
	end, err := time.Parse(time.RFC3339, interpretation.End)
	if err != nil {
		return AvailabilityQuery{}, err
	}
	return freebusy.Window{Start: start, End: end}, nil
}
