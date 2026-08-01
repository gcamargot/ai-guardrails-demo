package telegramadapter_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/telegramadapter"
)

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
