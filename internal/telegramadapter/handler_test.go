package telegramadapter_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/meeting"
	"github.com/nahtao97/agent-tool-guardrails/internal/telegramadapter"
)

func TestExternalSubjectSubmitsMeetingProposalWithoutCalendarEffect(t *testing.T) {
	t.Parallel()

	meetings := &capturingMeetingGateway{}
	handler := telegramadapter.NewHandler(telegramadapter.Config{
		WebhookSecret: "verified-webhook-secret",
		VerifiedUsers: map[telegramadapter.TelegramUserID]telegramadapter.Subject{
			4242: "external-alice-subject-id",
		},
		OwnerSubject: "owner-subject-id",
		Meetings:     meetings,
	})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/telegram/webhook", strings.NewReader(`{
		"message":{"from":{"id":4242},"text":"/propose 2026-08-03T13:00:00Z 2026-08-03T13:30:00Z alice@example.invalid Platform sync"}
	}`))
	if err != nil {
		t.Fatalf("create proposal webhook: %v", err)
	}
	request.Header.Set("X-Telegram-Bot-Api-Secret-Token", "verified-webhook-secret")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("submit Meeting Proposal: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusAccepted)
	}
	var body struct {
		MeetingProposal meeting.Proposal `json:"meeting_proposal"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode Meeting Proposal: %v", err)
	}
	if body.MeetingProposal.ProposalID != "proposal-1" || body.MeetingProposal.RequesterSubject != "external-alice-subject-id" {
		t.Fatalf("Meeting Proposal = %#v", body.MeetingProposal)
	}
	if meetings.identity.Subject != "external-alice-subject-id" || meetings.input.Reason != "Platform sync" || meetings.effects != 0 {
		t.Fatalf("submission identity=%#v input=%#v effects=%d", meetings.identity, meetings.input, meetings.effects)
	}
}

func TestExternalSubjectIsRateLimitedSeparatelyForAvailabilityAndProposals(t *testing.T) {
	t.Parallel()

	classifier := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"start":"2026-08-03T09:00:00Z","end":"2026-08-03T10:00:00Z"}`))
	}))
	t.Cleanup(classifier.Close)
	handler := telegramadapter.NewHandler(telegramadapter.Config{
		WebhookSecret:     "verified-webhook-secret",
		VerifiedUsers:     map[telegramadapter.TelegramUserID]telegramadapter.Subject{4242: "external-alice-subject-id"},
		OwnerSubject:      "owner-subject-id",
		ClassifierURL:     classifier.URL,
		HTTPClient:        classifier.Client(),
		Availability:      &capturingAvailabilityGateway{},
		Meetings:          &capturingMeetingGateway{},
		AvailabilityLimit: 1,
		ProposalLimit:     1,
		RateLimitWindow:   time.Hour,
	})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	availability := `{"message":{"from":{"id":4242},"text":"availability"}}`
	proposal := `{"message":{"from":{"id":4242},"text":"/propose 2026-08-03T13:00:00Z 2026-08-03T13:30:00Z alice@example.invalid Platform sync"}}`
	if status := postTelegram(t, server.URL, availability); status != http.StatusOK {
		t.Fatalf("first availability status = %d", status)
	}
	if status := postTelegram(t, server.URL, availability); status != http.StatusTooManyRequests {
		t.Fatalf("second availability status = %d, want 429", status)
	}
	if status := postTelegram(t, server.URL, proposal); status != http.StatusAccepted {
		t.Fatalf("first proposal status = %d", status)
	}
	if status := postTelegram(t, server.URL, proposal); status != http.StatusTooManyRequests {
		t.Fatalf("second proposal status = %d, want 429", status)
	}
}

func TestOwnerReviewsExactOperationBeforeExplicitApproval(t *testing.T) {
	t.Parallel()
	meetings := &capturingMeetingGateway{}
	handler := telegramadapter.NewHandler(telegramadapter.Config{
		WebhookSecret: "verified-webhook-secret",
		VerifiedUsers: map[telegramadapter.TelegramUserID]telegramadapter.Subject{9001: "owner-subject-id"},
		OwnerSubject:  "owner-subject-id",
		Meetings:      meetings,
	})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	if status := postTelegram(t, server.URL, `{"message":{"from":{"id":9001},"text":"/approve proposal-1"}}`); status != http.StatusBadRequest {
		t.Fatalf("unreviewed approve status = %d, want 400", status)
	}
	if status := postTelegram(t, server.URL, `{"message":{"from":{"id":9001},"text":"/review proposal-1"}}`); status != http.StatusOK {
		t.Fatalf("review status = %d", status)
	}
	if meetings.reviewed != "proposal-1" || meetings.effects != 0 {
		t.Fatalf("reviewed=%q effects=%d", meetings.reviewed, meetings.effects)
	}
	if status := postTelegram(t, server.URL, `{"message":{"from":{"id":9001},"text":"/approve proposal-1 reviewed-token"}}`); status != http.StatusOK {
		t.Fatalf("approve status = %d", status)
	}
	if meetings.approved != "proposal-1" || meetings.effects != 1 {
		t.Fatalf("approved=%q effects=%d", meetings.approved, meetings.effects)
	}
	if status := postTelegram(t, server.URL, `{"message":{"from":{"id":9001},"text":"/deny proposal-2 reviewed-token"}}`); status != http.StatusOK {
		t.Fatalf("deny status = %d", status)
	}
	if meetings.denied != "proposal-2" {
		t.Fatalf("denied=%q", meetings.denied)
	}
}

func postTelegram(t *testing.T, serverURL, body string) int {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, serverURL+"/telegram/webhook", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create Telegram webhook: %v", err)
	}
	request.Header.Set("X-Telegram-Bot-Api-Secret-Token", "verified-webhook-secret")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("post Telegram webhook: %v", err)
	}
	defer response.Body.Close()
	return response.StatusCode
}

func TestVerifiedTelegramIdentityCannotBeOverriddenByModelInterpretation(t *testing.T) {
	t.Parallel()

	classifier := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{
			"start":"2026-08-03T09:00:00Z",
			"end":"2026-08-03T12:00:00Z",
			"subject":"owner-subject-id",
			"actor":"coding-agent",
			"capabilities":["calendar.events.read"]
		}`))
	}))
	t.Cleanup(classifier.Close)

	gateway := &capturingAvailabilityGateway{}
	handler := telegramadapter.NewHandler(telegramadapter.Config{
		WebhookSecret: "verified-webhook-secret",
		VerifiedUsers: map[telegramadapter.TelegramUserID]telegramadapter.Subject{
			4242: "external-alice-subject-id",
		},
		ClassifierURL: classifier.URL,
		HTTPClient:    classifier.Client(),
		Availability:  gateway,
	})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/telegram/webhook", strings.NewReader(`{
		"message":{"from":{"id":4242},"text":"¿Cuándo estás libre el lunes por la mañana?"}
	}`))
	if err != nil {
		t.Fatalf("create Telegram webhook request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Telegram-Bot-Api-Secret-Token", "verified-webhook-secret")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("send Telegram webhook request: %v", err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })

	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	var body struct {
		AvailableIntervals []telegramadapter.AvailableInterval `json:"available_intervals"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode Telegram response: %v", err)
	}
	if len(body.AvailableIntervals) != 1 || body.AvailableIntervals[0].Start != "2026-08-03T10:00:00Z" {
		t.Fatalf("available intervals = %#v", body.AvailableIntervals)
	}

	want := telegramadapter.TrustedTelegramIdentity{
		Subject: "external-alice-subject-id",
		Actor:   "telegram-agent",
		Channel: "telegram",
	}
	if gateway.identity != want {
		t.Fatalf("trusted identity = %#v, want %#v", gateway.identity, want)
	}
	if gateway.query.Start != time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC) ||
		gateway.query.End != time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC) {
		t.Fatalf("availability query = %#v", gateway.query)
	}
}

type capturingAvailabilityGateway struct {
	identity telegramadapter.TrustedTelegramIdentity
	query    telegramadapter.AvailabilityQuery
}

type capturingMeetingGateway struct {
	identity telegramadapter.TrustedTelegramIdentity
	input    meeting.ProposalInput
	effects  int
	reviewed meeting.ProposalID
	approved meeting.ProposalID
	denied   meeting.ProposalID
}

func (gateway *capturingMeetingGateway) SubmitProposal(
	_ context.Context,
	identity telegramadapter.TrustedTelegramIdentity,
	input meeting.ProposalInput,
) (meeting.Proposal, error) {
	gateway.identity = identity
	gateway.input = input
	return meeting.Proposal{
		ProposalID:       "proposal-1",
		TraceID:          "trace-1",
		Start:            input.Start.Format(time.RFC3339),
		End:              input.End.Format(time.RFC3339),
		RequesterSubject: string(identity.Subject),
		Reason:           input.Reason,
		Contact:          input.Contact,
	}, nil
}

func (gateway *capturingMeetingGateway) ReviewProposal(_ context.Context, _ telegramadapter.TrustedTelegramIdentity, id meeting.ProposalID) (meeting.Operation, error) {
	gateway.reviewed = id
	return meeting.Operation{Tool: "calendar.create_event", TraceID: "trace-1", Arguments: meeting.EventArguments{ProposalID: id}}, nil
}

func (gateway *capturingMeetingGateway) ApproveProposal(_ context.Context, _ telegramadapter.TrustedTelegramIdentity, id meeting.ProposalID, _ meeting.ApprovalToken) (meeting.Event, error) {
	gateway.approved = id
	gateway.effects++
	return meeting.Event{EventID: "event-1", Created: true, EventCount: 1}, nil
}

func (gateway *capturingMeetingGateway) DenyProposal(_ context.Context, _ telegramadapter.TrustedTelegramIdentity, id meeting.ProposalID, _ meeting.ApprovalToken) (meeting.Denial, error) {
	gateway.denied = id
	return meeting.Denial{ProposalID: id, Status: "denied"}, nil
}

func (gateway *capturingAvailabilityGateway) FindAvailability(
	_ context.Context,
	identity telegramadapter.TrustedTelegramIdentity,
	query telegramadapter.AvailabilityQuery,
) ([]telegramadapter.AvailableInterval, error) {
	gateway.identity = identity
	gateway.query = query
	return []telegramadapter.AvailableInterval{{
		Start: "2026-08-03T10:00:00Z",
		End:   "2026-08-03T10:30:00Z",
	}}, nil
}
